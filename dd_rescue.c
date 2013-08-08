/** dd_rescue.c
 * 
 * dd_rescue copies your data from one file to another.  Files might as well be
 * block devices, such as hd partitions.  Unlike dd, it does not necessarily
 * abort on errors but continues to copy the disk, possibly leaving holes
 * behind.  Also, it does NOT truncate the output file, so you can copy more
 * and more pieces of your data, as time goes by.  This tool is thus suitable
 * for rescueing data of crashed disk, and that's the reason it has been
 * written by me.
 *
 * Copyright (C) Kurt Garloff <kurt@garloff.de>, 11/1997 -- 02/2013
 *
 * Improvements from LAB Valentin, see
 * http://www.kalysto.org/utilities/dd_rhelp/index.en.html
 * 
 * License: GNU GPL v2 or v3
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the Free
 *  Software Foundation; either version 2 of the License, or (at your option)
 *  version 3.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 *  more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110-1301,  USA.
 */

/**
 * TODO:
 * - Provide options to copy ACLs/xattrs as well
 * - Use termcap to fetch cursor up/down and color codes
 * - Display more infos on errors by collecting info from syslog
 * - Option to send TRIM on zeroed file blocks
 * - Options to compress with libz, liblzo, libbz2, lzma, ... 
 */

#ifndef VERSION
# define VERSION "(unknown)"
#endif
#ifndef __COMPILER__
# define __COMPILER__ "(unknown compiler)"
#endif

#define ID "$Id$"

#ifndef BUF_SOFTBLOCKSIZE
# define BUF_SOFTBLOCKSIZE 65536
#endif

#ifndef BUF_HARDBLOCKSIZE
# define BUF_HARDBLOCKSIZE pagesize
#endif

#ifndef DIO_SOFTBLOCKSIZE
# define DIO_SOFTBLOCKSIZE 1048576
#endif

#ifndef DIO_HARDBLOCKSIZE
# define DIO_HARDBLOCKSIZE 512
#endif


#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <utime.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <libgen.h>

#include "frandom.h"
#include "list.h"
#include "fmt_no.h"
#include "find_nonzero.h"

#ifndef LACK_GETOPT_LONG
#include <getopt.h>
#endif
// hack around buggy splice definition(!)
#define splice oldsplice
#include <fcntl.h>
#undef splice

#ifdef HAVE_LIBFALLOCATE
#include <fallocate.h>
#endif

#ifdef HAVE_LIBDL
#include <dlfcn.h>
void* libfalloc = (void*)0;
#endif

/* splice */
#ifdef __linux__
# define __KERNEL__
# include <asm/unistd.h>
# ifdef __NR_splice
#  define HAVE_SPLICE 1
#  ifndef SPLICE_F_MOVE	/* from fcntl.h on x86-64 linux */
#   define SPLICE_F_MOVE 1
#   define SPLICE_F_MORE 4
#  endif
#  if 1
static inline long splice(int fdin, loff_t *off_in, int fdout, 
			      loff_t *off_out, size_t len, unsigned int flags)
{
	return syscall(__NR_splice, fdin, off_in, fdout, off_out, len, flags);
}
#  else
_syscall6(long, splice, int, fdin, loff_t*, off_in, int, fdout, loff_t*, off_out, size_t, len, unsigned int, flags);
#  endif
# endif
#endif

/* fwd decls */
int cleanup();

/* Global vars and options */
unsigned int softbs, hardbs, syncfreq;
int maxerr, nrerr, dotrunc;
char trunclast, reverse, abwrerr, sparse, nosparse;
char verbose, quiet, interact, force, in_report, nocol;
unsigned char *buf, *buf2, *origbuf, *origbuf2;
const char *lname, *iname, *oname, *bbname = NULL;
off_t ipos, opos, xfer, lxfer, sxfer, fxfer, maxxfer, axfer, init_opos, ilen, olen, estxfer;

int ides, odes;
int o_dir_in, o_dir_out;
char identical, preserve, falloc, dosplice;
char i_chr, o_chr;
char i_repeat, i_rep_init;
size_t i_rep_zero;
int  prng_seed;
char noextend, avoidwrite, avoidnull;
char prng_libc, prng_frnd;
char bsim715, bsim715_4, bsim715_2, bsim715_2ndpass;
char extend;
char* prng_sfile;

void *prng_state, *prng_state2;


FILE *logfd;
struct timeval starttime, lasttime, currenttime;
struct timezone tz;
clock_t startclock;
/* Rate limit for status updates */
float printint = 0.1;

unsigned int pagesize = 4096;

/* multiple output files */
typedef struct _ofile {
	const char* name;
	int fd;
	char cdev;
} ofile_t;
LISTDECL(ofile_t);
LISTTYPE(ofile_t) *ofiles;

typedef char* charp;
LISTDECL(charp);
LISTTYPE(charp) *freenames;

const char *scrollup = 0;

#ifndef UP
# define UP "\x1b[A"
# define DOWN "\n"
# define RIGHT "\x1b[C"
#endif

const char* up = UP;
const char* fourup = UP UP UP UP;
const char* threeup = UP UP UP;
//const char* down = DOWN;
const char* right = RIGHT;
const char* nineright = RIGHT RIGHT RIGHT RIGHT RIGHT RIGHT RIGHT RIGHT RIGHT;
char *graph;

#ifdef NO_COLORS
# define RED ""
# define AMBER ""
# define YELLOW ""
# define GREEN ""
# define BOLD ""
# define INV ""
# define NORM ""
#else
#ifndef RED
# define RED "\x1b[0;31m"
# define AMBER "\x1b[0;33m"
# define YELLOW "\x1b[1;33m"
# define GREEN "\x1b[0;32m"
# define BOLD "\x1b[0;1m"
# define INV "\x1b[0;7m"
# define NORM "\x1b[0;0m"
#endif
#endif


#define DDR_INFO  "dd_rescue: (info): "
#define DDR_WARN  "dd_rescue: (warning): "
#define DDR_FATAL "dd_rescue: (fatal): "
#define DDR_INFO_C  BOLD DDR_INFO NORM
#define DDR_WARN_C  AMBER DDR_WARN NORM
#define DDR_FATAL_C RED DDR_FATAL NORM

enum ddrlog_t { NOHDR=0, INFO, WARN, FATAL };
const char* ddrlogpre[] = {"", DDR_INFO, DDR_WARN, DDR_FATAL };
const char* ddrlogpre_c[] = {"", DDR_INFO_C, DDR_WARN_C, DDR_FATAL_C };


#ifdef MISS_STRSIGNAL
static char sbuf[16];
static char* strsignal(int sig)
{
	sprintf(sbuf, "sig %i", sig);
	return sbuf;
}
#endif
#ifdef MISS_PREAD
static ssize_t pread(int fd, void *buf, size_t sz, off_t off)
{
	if (lseek(fd, off, SEEK_SET))
		return -1;
	return read(fd, buf, sz);
}

static ssize_t pwrite(int fd, void *buf, size_t sz, off_t off)
{
	if (lseek(fd, off, SEEK_SET))
		return -1;
	return write(fd, buf, sz);
}
#endif

inline float difftimetv(const struct timeval* const t2, 
			const struct timeval* const t1)
{
	return  (float) (t2->tv_sec  - t1->tv_sec ) +
		(float) (t2->tv_usec - t1->tv_usec) * 1e-6;
}

/** Write to file and simultaneously log to logfdile, if existing */
int fplog(FILE* const file, enum ddrlog_t logpre, const char * const fmt, ...)
{
	int ret = 0;
	va_list vl; 
	va_start(vl, fmt);
	if (file) {
		if (logpre) {
			if ((file == stdout || file == stderr) && !nocol)
				fprintf(file, "%s", ddrlogpre_c[logpre]);
			else
				fprintf(file, "%s", ddrlogpre[logpre]);
		}
		ret = vfprintf(file, fmt, vl);
	}
	va_end(vl);
	if (logfd) {
		if (logpre)
			fprintf(logfd, "%s", ddrlogpre[logpre]);
		va_start(vl, fmt);
		ret = vfprintf(logfd, fmt, vl);
		va_end(vl);
	}
	scrollup = 0;
	return ret;
}

static int check_identical(const char* const in, const char* const on)
{
	int err = 0;
	struct stat istat, ostat;
	errno = 0;
	if (strcmp(in, on) == 0) 
		return 1;
	err -= stat(in, &istat);
	if (err)
	       	return 0;
	err -= stat(on, &ostat);
	errno = 0;
	if (!err &&
	    istat.st_ino == ostat.st_ino &&
	    istat.st_dev == ostat.st_dev)
		return 1;
	return 0;
}

static int openfile(const char* const fname, const int flags)
{
	int fdes;
	if (!strcmp(fname, "-")) {
		if (flags & O_WRONLY || flags & O_RDWR)
			fdes = 1;  /* stdout */
		else 
			fdes = 0;  /* stdin */
	} else
		fdes = open(fname, flags, 0640);
	if (fdes == -1) {
		fplog(stderr, FATAL, "open \"%s\" failed: %s\n",
			fname, strerror(errno));
		cleanup(); exit(17);
	}
	return fdes;
}

/** Checks whether file is seekable */
static void check_seekable(const int fd, char *ischr, const char* msg)
{
	errno = 0;
	if (!*ischr && lseek(fd, (off_t)0, SEEK_SET) != 0) {
		if (msg) {
			fplog(stderr, WARN, "file %s is not seekable!\n", msg);
			fplog(stderr, WARN, "%s\n", strerror(errno));
		}
		*ischr = 1;
	}
	errno = 0;
}

/** Calc position in graph */
inline int gpos(off_t off)
{
	static const int glen = 40; //strlen(graph) - 2;
	return 1+(glen*off/ilen);
}

/** Prepare graph */
static void preparegraph()
{
	if (!ilen || ipos > ilen)
		return;
	graph = strdup(":.........................................:");
	if (reverse) {
		graph[gpos(ipos)+1] = '<';
		graph[gpos(ipos-estxfer)-1] = '>';

	} else {
		graph[gpos(ipos)-1] = '>';
		graph[gpos(ipos+estxfer)+1] = '<';
	}
}

void updgraph(int err)
{
	int off;
	if (!ilen || ipos > ilen)
		return;
	off = gpos(ipos);
	if (graph[off] == 'x')
		return;
	if (err)
		graph[off] = 'x';
	else {
		if (bsim715_2ndpass)
			graph[off] = '.';
		else
			graph[off] = '-';
	}
}

/** Tries to determine size of input file */
void input_length()
{
	struct stat stbuf;
	estxfer = maxxfer;
	if (reverse) {
		if (ipos)
			ilen = ipos;
		else
			ilen = maxxfer;
	} else
		ilen = ipos + maxxfer;
	if (estxfer)
		preparegraph();
	if (i_chr)
		return;
	if (fstat(ides, &stbuf))
		return;
	if (S_ISLNK(stbuf.st_mode))
		return;
	if (S_ISCHR(stbuf.st_mode)) {
		i_chr = 1;
		return;
	}
	if (S_ISBLK(stbuf.st_mode)) {
		/* Do magic to figure size of block dev */
		off_t p = lseek(ides, 0, SEEK_CUR);
		if (p == -1)
			return;
		ilen = lseek(ides, 0, SEEK_END) + 1;
		lseek(ides, p, SEEK_SET);
	} else {
		off_t diff;
		ilen = stbuf.st_size;
		if (!ilen)
			return;
		diff = ilen - stbuf.st_blocks*512;
		if (diff >= 4096 && (float)diff/ilen > 0.05 && !quiet)
		       fplog(stderr, INFO, "%s is sparse (%i%%) %s\n", iname, (int)(100.0*diff/ilen), (sparse? "": ", consider -a"));
	}
	if (!ilen)
		return;
	if (!reverse)
		estxfer = ilen - ipos;
	else
		estxfer = ipos;
	if (maxxfer && estxfer > maxxfer)
		estxfer = maxxfer;
	if (estxfer < 0)
		estxfer = 0;
	if (!quiet)
		fplog(stderr, INFO, "expect to copy %LikB from %s\n",
			estxfer/1024, iname);
	if (!graph)
		preparegraph();
}

int output_length()
{
	struct stat stbuf;
	if (o_chr)
		return -1;
	if (fstat(odes, &stbuf))
		return -1;
	if (S_ISLNK(stbuf.st_mode))
		return -1;
	if (S_ISCHR(stbuf.st_mode)) {
		o_chr = 1;
		return -1;
	}
	if (S_ISBLK(stbuf.st_mode)) {
		/* Do magic to figure size of block dev */
		off_t p = lseek(odes, 0, SEEK_CUR);
		if (p == -1)
			return -1;
		olen = lseek(odes, 0, SEEK_END) + 1;
		lseek(odes, p, SEEK_SET);
	} else {
		off_t diff;
		olen = stbuf.st_size;
		if (!olen)
			return -1;
		diff = olen - stbuf.st_blocks*512;
		if (diff >= 4096 && (float)diff/ilen > 0.05 && !quiet)
		       fplog(stderr, INFO, "%s is sparse (%i%%) %s\n", oname, (int)(100.0*diff/olen), (sparse? "": ", consider -a"));
	}
	if (!olen)
		return -1;
	if (!reverse) {
		off_t newmax = olen - opos;
		if (newmax < 0) {
			fplog(stderr, FATAL, "output position is beyond end of file but -M specified!\n");
			cleanup();
			exit(19);
		}			
		if (!maxxfer || maxxfer > newmax) {
			maxxfer = newmax;
			if (!quiet)
				fplog(stderr, INFO, "limit max xfer to %LikB\n",
					maxxfer/1024);
		}
	} else if (opos > olen) {
		fplog(stderr, WARN, "change output position %LikB to endpos %Likb due to -M\n",
			opos/1024, olen/1024);
		opos = olen;
	}
	return 0;
}


static void sparse_output_warn()
{
	struct stat stbuf;
	off_t eff_opos;
	if (o_chr)
		return;
	if (fstat(odes, &stbuf))
		return;
	if (S_ISCHR(stbuf.st_mode)) {
		o_chr = 1;
		return;
	}
	if (S_ISBLK(stbuf.st_mode)) {
		if (sparse || !nosparse)
			fplog(stderr, WARN, "%s is a block device; -a not recommended; -A recommended\n", oname);
		return;
	}
	eff_opos = (opos == (off_t)-INT_MAX? ipos: opos);
	if (sparse && (eff_opos < stbuf.st_size))
		fplog(stderr, WARN, "write into %s (@%li/%li): sparse not recommended\n", 
				oname, eff_opos, stbuf.st_size);
}

#if defined(HAVE_FALLOCATE) || defined(HAVE_LIBFALLOCATE)

#ifdef HAVE_LIBDL
static void* load_libfallocate()
{
	if (!libfalloc)
		libfalloc = dlopen("libfallocate.so.0", RTLD_NOW);
	if (!libfalloc)
		return 0;
	else
		return dlsym(libfalloc, "linux_fallocate64");
}
#endif

static void do_fallocate(int fd, const char* onm)
{
	struct stat stbuf;
	off_t to_falloc, alloced;
	int rc = 0;
	if (!estxfer)
		return;
	if (fstat(fd, &stbuf))
		return;
	if (!S_ISREG(stbuf.st_mode))
		return;
	alloced = stbuf.st_blocks*512 - opos;
	to_falloc = estxfer - (alloced < 0 ? 0 : alloced);
	if (to_falloc <= 0)
		return;
#ifdef HAVE_LIBDL
	typedef int (*_l_f_t) (int fd, int mode, __off64_t start, __off64_t len);
	//int (*_linux_fallocate64)(int fd, int mode, __off64_t start, __off64_t len);
	_l_f_t _linux_fallocate64 = (_l_f_t)load_libfallocate();
	if (_linux_fallocate64)
		rc = _linux_fallocate64(fd, FALLOC_FL_KEEP_SIZE,
				opos, to_falloc);
#ifdef HAVE_FALLOCATE
	else
		rc = fallocate64(fd, 1, opos, to_falloc);
#endif
#elif defined(HAVE_LIBFALLOCATE)
	rc = linux_fallocate64(fd, FALLOC_FL_KEEP_SIZE, 
			      opos, to_falloc);
#else /* HAVE_FALLOCATE */
	rc = fallocate64(fd, 1, opos, to_falloc);
#endif
	if (rc)
	       fplog(stderr, WARN, "fallocate %s (%Li, %Li) failed: %s\n",
			       onm, opos, to_falloc, strerror(errno));
}
#endif

float floatrate4  = 0.0;
float floatrate32 = 0.0;
void doprint(FILE* const file, const unsigned int bs, const clock_t cl, 
	     const float t1, const float t2, const int sync)
{
	float avgrate = (float)xfer/t1;
	float currate = (float)(xfer-lxfer)/t2;
	const char *bold = BOLD, *norm = NORM;
	if (!floatrate4) {
		floatrate4  = currate;
		floatrate32 = currate;
	} else {
		floatrate4  = (floatrate4 * 3 + currate)/ 4;
		floatrate32 = (floatrate32*31 + currate)/32;
	}
	if (nocol || (file != stderr && file != stdout)) {
		bold = ""; norm = "";
	}
	fprintf(file, DDR_INFO "ipos:%sk, opos:%sk, xferd:%sk\n",
		fmt_int(10, 1, 1024, ipos, bold, norm, 1),
		fmt_int(10, 1, 1024, opos, bold, norm, 1),
		fmt_int(10, 1, 1024, xfer, bold, norm, 1));
	fprintf(file, "             %s  %s  errs:%7i, errxfer:%sk, succxfer:%sk\n",
		(reverse? "-": " "), (bs==hardbs? "*": " "), nrerr, 
		fmt_int(10, 1, 1024, fxfer, bold, norm, 1),
		fmt_int(10, 1, 1024, sxfer, bold, norm, 1));
	if (sync || (file != stdin && file != stdout) )
		fprintf(file, "             +curr.rate:%skB/s, avg.rate:%skB/s, avg.load:%s%%\n",
			fmt_int(9, 0, 1024, floatrate4, bold, norm, 1),
			fmt_int(9, 0, 1024, avgrate, bold, norm, 1),
			fmt_int(3, 1, 10, (cl-startclock)/(t1*(CLOCKS_PER_SEC/1000)), bold, norm, 1));
	else
		fprintf(file, "             -curr.rate:%skB/s, avg.rate:%skB/s, avg.load:%s%%\n",
			nineright, 
			fmt_int(9, 0, 1024, avgrate, bold, norm, 1),
			fmt_int(3, 1, 10, (cl-startclock)/(t1*(CLOCKS_PER_SEC/1000)), bold, norm, 1));
	if (estxfer && avgrate > 0) {
		int sec;
		if (in_report)
			sec = 0.5 + t1;
		else
			sec = 0.5 + 2*(estxfer-xfer)/(avgrate+floatrate32);
		int hour = sec / 3600;
		int min = (sec % 3600) / 60;
		sec = sec % 60;
		updgraph(0);
		fprintf(file, "             %s %3i%%  %s: %2i:%02i:%02i \n",
			graph, (int)(100*xfer/estxfer), (in_report? "TOT": "ETA"), 
			hour, min, sec);
		scrollup = fourup;
	} else
		scrollup = threeup;
}

void printstatus(FILE* const file1, FILE* const file2,
		 const int bs, const int sync)
{
	float t1, t2; 
	clock_t cl;
	static int einvalwarn = 0;

	if (sync) {
		int err = fsync(odes);
		if (err && (errno != EINVAL || !einvalwarn) &&!o_chr) {
			fplog(stderr, WARN, "sync %s (%.1fk): %s!  \n",
			      oname, (double)ipos/1024.0, strerror(errno));
			++einvalwarn;
		}
		errno = 0;
	}

	gettimeofday(&currenttime, NULL);
	t1 = difftimetv(&currenttime, &starttime);
	t2 = difftimetv(&currenttime, &lasttime);
	cl = clock();

	/* Idea: Could save last not printed status and print on err */
	if (t2 < printint && !sync && !in_report) {
		if (estxfer)
			updgraph(0);
		return;
	}

	if (scrollup) {
		if (file1 == stderr || file1 == stdout)
			fprintf(file1, "%s", scrollup);
		if (file2 == stderr || file2 == stdout)
			fprintf(file2, "%s", scrollup);
	}

	if (file1) 
		doprint(file1, bs, cl, t1, t2, sync);
	if (file2)
		doprint(file2, bs, cl, t1, t2, sync);
	if (1 || sync) {
		memcpy(&lasttime, &currenttime, sizeof(lasttime));
		lxfer = xfer;
	}
}

static void savebb(unsigned long block)
{
	FILE *bbfile;
	fplog(stderr, WARN, "Bad block reading %s: %lu \n", 
			iname, block);
	if (bbname == NULL)
		return;
	bbfile = fopen(bbname, "a");
	fprintf(bbfile, "%lu\n", block);
	fclose(bbfile);
}

void printreport()
{
	/* report */
	FILE *report = (!quiet || nrerr)? stderr: 0;
	in_report = 1;
	if (report) {
		fplog(report, INFO, "Summary for %s -> %s", iname, oname);
		LISTTYPE(ofile_t) *of;
		LISTFOREACH(ofiles, of)
			fplog(report, NOHDR, "; %s", LISTDATA(of).name);
		if (logfd > 0)
			fprintf(logfd, ":\n");
		fprintf(report, "\n");
		printstatus(report, logfd, 0, 1);
		if (avoidwrite) 
			fplog(report, INFO, "Avoided %LikB of writes (performed %LikB)\n", axfer/1024, (sxfer-axfer)/1024);
	}
}

void exit_report(int rc)
{
	gettimeofday(&currenttime, NULL);
	printreport();
	cleanup();
	fplog(stderr, FATAL, "Not completed fully successfully! \n");
	exit(rc);
}


int copyperm(int ifd, int ofd)
{
	int err; 
	mode_t fmode;
	struct stat stbuf;
	err = fstat(ifd, &stbuf);
	if (err)
		return err;
	fmode = stbuf.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX);
	err = fchown(ofd, stbuf.st_uid, stbuf.st_gid);
	if (err)
		fmode &= ~(S_ISUID | S_ISGID);
	err += fchmod(ofd, fmode);
	return err;
}

/** File time copy */
int copytimes(const char* inm, const char* onm)
{
	int err;
	struct stat stbuf;
	struct utimbuf utbuf;
	err = stat(inm, &stbuf);
	if (err)
		return err;
	utbuf.actime  = stbuf.st_atime;
	utbuf.modtime = stbuf.st_mtime;
	err = utime(onm, &utbuf);
	return err;
}

static int mayexpandfile(const char* onm)
{
	struct stat st;
	off_t maxopos = opos;
	if (init_opos > opos)
		maxopos = init_opos;
	stat(onm, &st);
	if (!S_ISREG(st.st_mode))
		return 0;
	if (st.st_size < maxopos || trunclast)
		return truncate(onm, maxopos);
	else 
		return 0;		
}

int sync_close(int fd, const char* nm, char chr)
{
	int rc, err = 0;
	if (fd != -1) {
		/* Make sure, the output file is expanded to the last (first) position
	 	 * FIXME: 0 byte writes do NOT expand file -- mayexpandfile() will
		 * take care of that. */
		if (!avoidwrite) 
			rc = pwrite(fd, buf, 0, opos);
		rc = fsync(fd);
		if (rc && !chr) {
			fplog(stderr, WARN, "fsync %s (%.1fk): %s!\n",
			      nm, (double)opos/1024, strerror(errno));
			++err;
			errno = 0;
		}
		rc = close(fd); 
		if (rc) {
			fplog(stderr, WARN, "close %s (%.1fk): %s!\n",
			      nm, (double)opos/1024, strerror(errno));
			++err;
		}
		if (sparse) {
			rc = mayexpandfile(nm);
			if (rc)
				fplog(stderr, WARN, "seek %s (%.1fk): %s!\n",
				      nm, (double)opos/1024, strerror(errno));
		} else if (trunclast && !reverse) {
			rc = truncate(nm, opos);
			if (rc)
				fplog(stderr, WARN, "could not truncate %s to %.1fk: %s!\n",
					nm, (double)opos/1024, strerror(errno));
		}

	}
	return err;
}			 

#define ZFREE(ptr)	\
	do {		\
	  if (ptr)	\
	    free(ptr);	\
	  ptr = 0;	\
	} while(0)

int cleanup()
{
	int rc, errs = 0;
	errs += sync_close(odes, oname, o_chr);
	if (ides != -1) {
		rc = close(ides);
		if (rc) {
			fplog(stderr, WARN, "close %s (%.1fk): %s!\n",
			      iname, (double)ipos/1024, strerror(errno));
			++errs;
		}
	}
	if (logfd)
		fclose(logfd);
	LISTTYPE(ofile_t) *of;
	LISTFOREACH(ofiles, of) {
		ofile_t *oft = &(LISTDATA(of));
		rc = sync_close(oft->fd, oft->name, oft->cdev);
	}
	ZFREE(origbuf2);
	ZFREE(origbuf);
	ZFREE(graph);
	if (preserve)
		copytimes(iname, oname);
	LISTFOREACH(ofiles, of)
		if (preserve)
			copytimes(iname, LISTDATA(of).name);
	if (prng_state2) {
		frandom_release(prng_state2);
		prng_state2 = 0;
	}
	if (prng_state) {
		frandom_release(prng_state);
		prng_state = 0;
	}
	LISTTREEDEL(ofiles, ofile_t);
	LISTTYPE(charp) *onl;
	LISTFOREACH(freenames, onl) {
		free(LISTDATA(onl));
		LISTDATA(onl) = 0;
	}
	LISTTREEDEL(freenames, charp);
#if HAVE_LIBDL
	if (libfalloc)
		dlclose(libfalloc);
#endif
	return errs;
}

ssize_t fill_rand(void *bf, size_t ln)
{
	unsigned int i;
	int* buf = (int*)bf;
	for (i = 0; i < ln/sizeof(int); ++i)
		buf[i] = rand();
	return ln;
}

/** is the block zero ? */
static ssize_t blockiszero(const unsigned char* blk, const size_t ln)
{
	if (i_repeat && i_rep_zero)
		return i_rep_zero;
	i_rep_zero = find_nonzero_opt(blk, ln);
	return i_rep_zero;
}

static inline ssize_t mypread(int fd, void* bf, size_t sz, off_t off)
{
	if (i_repeat) {
		if (i_rep_init)
			return sz;
		else
			i_rep_init = 1;
	}
	if (prng_libc)
		return fill_rand(bf, sz);
	if (prng_frnd) {
		if (!bsim715_2ndpass)
			return frandom_bytes(prng_state, (unsigned char*) bf, sz);
		else
			return frandom_bytes_inv(prng_state, (unsigned char*) bf, sz);
	}
	if (i_chr) 
		return read(fd, bf, sz);
	else
		return pread(fd, bf, sz, off);
}

static inline ssize_t mypwrite(int fd, void* bf, size_t sz, off_t off)
{
	if (o_chr) {
		if (!avoidnull)
			return write(fd, bf, sz);
		else {
			axfer += sz;
			return sz;
		}
	} else {
		if (avoidwrite) {
			ssize_t ln = pread(fd, buf2, sz, off);
			if (ln < (ssize_t)sz)
				return pwrite(fd, bf, sz, off);
			if (memcmp(bf, buf2, ln))
				return pwrite(fd, bf, sz, off);
			else {
				axfer += ln;
				return ln;
			}
		} else
			return pwrite(fd, bf, sz, off);
	}
}


ssize_t readblock(const int toread)
{
	ssize_t err, rd = 0;
	//errno = 0; /* should not be necessary */
	do {
		rd += (err = mypread(ides, buf+rd, toread-rd, ipos+rd-reverse*toread));
		if (err == -1) 
			rd++;
	} while ((err == -1 && (errno == EINTR || errno == EAGAIN))
		  || (rd < toread && err > 0 && errno == 0));
	//if (rd < toread) memset (buf+rd, 0, toread-rd);
	return (/*err == -1? err:*/ rd);
}

ssize_t writeblock(const int towrite)
{
	ssize_t err, wr = 0;
	//errno = 0; /* should not be necessary */
	do {
		wr += (err = mypwrite(odes, buf+wr, towrite-wr, opos+wr-reverse*towrite));
		if (err == -1) 
			wr++;
	} while ((err == -1 && (errno == EINTR || errno == EAGAIN))
		  || (wr < towrite && err > 0 && errno == 0));
	if (wr < towrite && err != 0) {
		/* Write error: handle ? .. */
		fplog(stderr, (abwrerr? FATAL: WARN),
				"write %s (%.1fk): %s\n",
	      			oname, (double)opos/1024, strerror(errno));
		if (abwrerr) 
			exit_report(21);
		nrerr++;
	}
	int oldeno = errno;
	char oldochr = o_chr;
	LISTTYPE(ofile_t) *of;
	LISTFOREACH(ofiles, of) {
		ssize_t e2, w2 = 0;
		ofile_t *oft = &(LISTDATA(of));
		o_chr = oft->cdev;
		do {
			w2 += (e2 = mypwrite(oft->fd, buf+w2, towrite-w2, opos+w2-reverse*towrite));
			if (e2 == -1) 
				w2++;
		} while ((e2 == -1 && (errno == EINTR || errno == EAGAIN))
			  || (w2 < towrite && e2 > 0 && errno == 0));
		if (w2 < towrite && e2 != 0) 
			fplog(stderr, WARN, "2ndary write %s (%.1fk): %s\n",
			      oft->name, (double)opos/1024, strerror(errno));
	}
	o_chr = oldochr;
	errno = oldeno;	
	return (/*err == -1? err:*/ wr);
}

int blockxfer(const off_t max, const int bs)
{
	int block = bs;
	/* Don't xfer more bytes than our limit */
	if (max && max-xfer < bs)
		block = max-xfer;
	if (reverse) {
		/* Can't go beyond the beginning of the file */
		if (block > ipos)
			block = ipos;
		if (block > opos)
			block = opos;
	}
	return block;
}

void exitfatalerr(const int eno)
{
	if (eno == ESPIPE || eno == EPERM || eno == ENXIO || eno == ENODEV) {
		fplog(stderr, FATAL, "%s (%.1fk): %s! \n", 
		      iname, (double)ipos/1024, strerror(eno));
		fplog(stderr, NOHDR, "dd_rescue: Last error fatal! Exiting ... \n");
		exit_report(20);
	}
}

/* Update positions after successful copy, rd = progress, wr = really written */
static void advancepos(const ssize_t rd, const ssize_t wr)
{
	sxfer += wr; xfer += rd;
	if (reverse) { 
		ipos -= rd; opos -= rd; 
	} else { 
		ipos += rd; opos += rd; 
	}
}

static int is_writeerr_fatal(int err)
{
	return (err == ENOSPC || err == EROFS
#ifdef EDQUOT
               || err == EDQUOT
#endif
               || (err == EFBIG && !reverse));
}

int weno;

/* Do write,  update positions ... 
 * Returns number of successfully written bytes. */
ssize_t dowrite(const ssize_t rd)
{
	int err = 0;
	int fatal = 0;
	ssize_t wr = 0;
	weno = 0;
	errno = 0;
	if (!sparse || blockiszero(buf, rd) < rd) {
		err = ((wr = writeblock(rd)) < rd ? 1: 0);
		weno = errno;
	}
	if (err && is_writeerr_fatal(weno))
		++fatal;
	if (err) {
		fplog(stderr, WARN, "assumption rd(%i) == wr(%i) failed! \n", rd, wr);
		fplog(stderr, (fatal? FATAL: WARN),
			"write %s (%.1fk): %s!\n", 
			oname, (double)(opos+wr)/1024, strerror(weno));
		errno = 0;
		/* FIXME: This breaks for reverse direction */
		if (!reverse)
			advancepos(wr, wr);
		else
			return 0;
	} else
		advancepos(rd, wr);
	return wr;
}

/* Do write with retry if rd > hardbs, update positions ... 
 * Returns 0 on success, -1 on fatal error, 1 on normal error. */
int dowrite_retry(const ssize_t rd)
{
	int errs = 0;
	ssize_t wr = dowrite(rd);
	if (wr == rd || weno == 0)
		return 0;
	if ((rd <= (ssize_t)hardbs) || (weno != ENOSPC && weno != EFBIG)) {
		/* No retry, move on */
		advancepos(rd-wr, 0);
		return is_writeerr_fatal(weno)? -1: 1;
	} else {
		ssize_t rwr = wr;
		unsigned char* oldbuf = buf; 
		int adv = 1;
		buf += wr;
		fplog(stderr, INFO, "retrying writes with smaller blocks \n");
		if (reverse) {
			buf = oldbuf+rd-hardbs;
			adv = -1;
		}
		while (rwr < rd) {
			ssize_t towr = ((ssize_t)hardbs > rd-rwr)? rd-rwr: hardbs;
			ssize_t wr2 = dowrite(towr);
			if (is_writeerr_fatal(weno)) {
				buf = oldbuf;
				return -1;
			}
			if (wr2 < towr) {
				advancepos(towr-wr2, 0);
				++errs;
			}
			rwr += towr; buf += towr*adv;
		}
		buf = oldbuf;
	}
	return errs;
}

static int partialwrite(const ssize_t rd)
{
	/* But first: write available data and advance (optimization) */
	if (rd > 0 && !reverse) 
		return dowrite_retry(rd);
	return 0;	
}

int copyfile_hardbs(const off_t max)
{
	ssize_t toread;
	int errs = 0; errno = 0;
#if 0	
	fprintf(stderr, "%s%s%s%s copyfile (ipos=%.1fk, xfer=%.1fk, max=%.1fk, bs=%i)                         ##\n%s%s%s%s",
		up, up, up, up,
		(double)ipos/1024, (double)xfer/1024, (double)max/1024, hardbs,
		down, down, down, down);
#endif
	while ((toread = blockxfer(max, hardbs)) > 0) { 
		int eno;
		ssize_t rd = readblock(toread);
		eno = errno;

		/* EOF */
		if (rd == 0 && !eno) {
			if (!quiet)
				fplog(stderr, INFO, "read %s (%.1fk): EOF\n", 
				      iname, (double)ipos/1024);
			return errs;
		}
		/* READ ERROR */
		if (rd < toread/* && errno*/) {
			if (eno) {
				++errs;
				/* Read error occurred: Print warning */
				printstatus(stderr, logfd, hardbs, 1);
			}
			/* Some errnos are fatal */
			exitfatalerr(eno);
			/* Non fatal error */
			/* This is the case, where we were not called from copyfile_softbs and thus have to assume harmless EOF */
			if (/*softbs <= hardbs &&*/ eno == 0) {
				int ret;
				/* But first: write available data and advance (optimization) */
				if ((ret = partialwrite(rd)) < 0)
					return ret;
				else
					errs += ret;
				/* partialwrite calls dowrite_retry which updates
				 * statistics and positions. */
				continue;
			}					
			/* Real error on small blocks: Don't retry */
			nrerr++; 
			fplog(stderr, WARN, "read %s (%.1fk): %s!\n", 
			      iname, (double)ipos/1024, strerror(eno));
		
			errno = 0;
			if (nosparse || 
			    (rd > 0 && (!sparse || blockiszero(buf, rd) < rd))) {
				ssize_t wr = 0;
				memset(buf+rd, 0, toread-rd);
				errs += ((wr = writeblock(toread)) < toread ? 1: 0);
				eno = errno;
				if (wr <= 0 && (eno == ENOSPC 
					   || (eno == EFBIG && !reverse))) 
					return errs;
				if (toread != wr) {
					fplog(stderr, WARN, "assumption toread(%i) == wr(%i) failed! \n", toread, wr);	
					/*
					fplog(stderr, WARN, "%s (%.1fk): %s!\n", 
					      oname, (double)opos/1024, strerror(eno));
					fprintf(stderr, "%s%s%s%s", down, down, down, down);
				 	*/
				}
			}
			savebb(ipos/hardbs);
			updgraph(1);
			fxfer += toread; xfer += toread;
			if (reverse) { 
				ipos -= toread; opos -= toread; 
			} else { 
				ipos += toread; opos += toread; 
			}
			/* exit if too many errs */
			if (maxerr && nrerr >= maxerr) {
				fplog(stderr, FATAL, "maxerr reached!\n");
				exit_report(32);
			}
		} else {
	      		int err = dowrite_retry(rd);
			if (err < 0)
				return -err;
			else
				errs += err;
		}

		if (syncfreq && !(xfer % (syncfreq*softbs)))
			printstatus((quiet? 0: stderr), 0, hardbs, 1);
		else if (!quiet && !(xfer % (8*softbs)))
			printstatus(stderr, 0, hardbs, 0);
	} /* remain */
	return errs;
}

int copyfile_softbs(const off_t max)
{
	ssize_t toread;
	int errs = 0, rc; int eno;
	errno = 0;
#if 0	
	fprintf(stderr, "%s%s%s%s copyfile (ipos=%.1fk, xfer=%.1fk, max=%.1fk, bs=%i)                         ##\n%s%s%s%s",
		up, up, up, up,
		(double)ipos/1024, (double)xfer/1024, (double)max/1024, softbs,
		down, down, down, down);
#endif
	/* expand file to AT LEAST the right length 
	 * FIXME: 0 byte writes do NOT expand file */
	if (!o_chr && !avoidwrite) {
		rc = pwrite(odes, buf, 0, opos);
		if (rc)
			fplog(stderr, WARN, "extending file %s to %.1fk failed\n",
			      oname, (double)opos/1024);
	}
	while ((toread = blockxfer(max, softbs)) > 0) {
		int err;
		ssize_t rd = readblock(toread);
		eno = errno;

		/* EOF */
		if (rd == 0 && !eno) {
			if (!quiet)
				fplog(stderr, INFO, "read %s (%.1fk): EOF\n", 
				      iname, (double)ipos/1024);
			return errs;
		}
		/* READ ERROR or short read */
		if (rd < toread/* && errno*/) {
			int ret;
			off_t new_max, old_xfer;
			if (eno) {
				++errs;
				/* Read error occurred: Print warning */
				printstatus(stderr, logfd, softbs, 1);
			}
			/* Some errnos are fatal */
			exitfatalerr(eno);
			/* Non fatal error */
			new_max = xfer + toread;
			/* Error with large blocks: Try small ones ... */
			if (verbose) {
				/*
				fprintf(stderr, DDR_INFO "problems at ipos %.1fk: %s \n                 fall back to smaller blocksize \n%s%s%s%s",
				        (double)ipos/1024, strerror(eno), down, down, down, down);
				 */
				fprintf(stderr, DDR_INFO "problems at ipos %.1fk: %s \n                 fall back to smaller blocksize \n",
				        (double)ipos/1024, strerror(eno));
				scrollup = 0;
				printstatus(stderr, logfd, hardbs, 1);
			}
			/* But first: write available data and advance (optimization) */
			if ((ret = partialwrite(rd)) < 0)
				return ret;
			else
				errs += ret;
			old_xfer = xfer;
			errs += (err = copyfile_hardbs(new_max));
			/* EOF */
			if (!err && old_xfer == xfer)
				return errs;
			/*
			if (reverse && rd) {
				ipos -= rd; opos -= rd;
				xfer += rd; sxfer += wr;
			}
			*/	
			/* Stay with small blocks, until we could read two whole 
			   large ones without errors */
			new_max = xfer;
			while (err && (!max || (max-xfer > 0)) && ((!reverse) || (ipos > 0 && opos > 0))) {
				new_max += 2*softbs; old_xfer = xfer;
				if (max && new_max > max) 
					new_max = max;
				errs += (err = copyfile_hardbs(new_max));
			}
			errno = 0;
			/* EOF ? */      
			if (!err && xfer == old_xfer)
				return errs;
			if (verbose) {
				fprintf(stderr, DDR_INFO "ipos %.1fk promote to large bs again! \n",
					(double)ipos/1024);
				scrollup = 0;
			}
		} else {
	      		err = dowrite_retry(rd);
			if (err < 0)
				return -err;
			else
				errs += err;
		} /* errno */

		if (syncfreq && !(xfer % (syncfreq*softbs)))
			printstatus((quiet? 0: stderr), 0, softbs, 1);
		else if (!quiet && !(xfer % (16*softbs)))
			printstatus(stderr, 0, softbs, 0);
	} /* remain */
	return errs;
}

#ifdef HAVE_SPLICE
int copyfile_splice(const off_t max)
{
	ssize_t toread;
	int fd_pipe[2];
	LISTTYPE(ofile_t) *oft;
	if (pipe(fd_pipe) < 0)
		return copyfile_softbs(max);
	while ((toread	= blockxfer(max, softbs)) > 0) {
		off_t old_ipos = ipos, old_opos = opos;
		ssize_t rd = splice(ides, &ipos, fd_pipe[1], NULL, toread,
					SPLICE_F_MOVE | SPLICE_F_MORE);
		if (rd < 0) {
			if (!quiet)
				fplog(stderr, INFO, "%s (%.1fk): fall back to userspace copy\n",
				      iname, (double)ipos/1024);
			close(fd_pipe[0]); close(fd_pipe[1]);
			return copyfile_softbs(max);
		}
		if (rd == 0) {
			if (!quiet)
				fplog(stderr, INFO, "read %s (%.1fk): EOF (splice)\n",
				      iname, (double)ipos/1024);
			break;
		}
		while (rd) {
			ssize_t wr = splice(fd_pipe[0], NULL, odes, &opos, rd,
					SPLICE_F_MOVE | SPLICE_F_MORE);
			if (wr < 0) {
				fplog(stderr, FATAL, "write %s (%.1fk): %s (splice)\n",
					oname, (double)opos/1024.0, strerror(errno));

				close(fd_pipe[0]); close(fd_pipe[1]);
				exit_report(23);
			}
			rd -= wr; xfer += wr; sxfer += wr;
		}
		off_t new_ipos = ipos, new_opos = opos;
		LISTFOREACH(ofiles, oft) {
			ipos = old_ipos; opos = old_opos;
			rd = splice(ides, &ipos, fd_pipe[1], NULL, toread,
					SPLICE_F_MOVE | SPLICE_F_MORE);
			/* Simplify error handling, it worked before ... */
			if (rd <= 0) {
				fplog(stderr, WARN, "Confused: splice() read failed unexpectedly: %s\n",
					strerror(errno));
				/* We should abort here .... */
				ipos = new_ipos; opos = new_opos;
				continue;
			}
			while (rd) {
				ssize_t wr = splice(fd_pipe[0], NULL, LISTDATA(oft).fd, &opos, rd,
						SPLICE_F_MOVE | SPLICE_F_MORE);
				if (wr < 0) {	
					fplog(stderr, WARN, "Confused: splice() write failed unexpectedly: %s\n",
						strerror(errno));
					/* We should abort here .... */
					ipos = new_ipos; opos = new_opos;
					continue;
				}
			rd -= wr;
			}
		}
		if (ipos != new_ipos || opos != new_opos) {
			fplog(stderr, WARN, "Confused: splice progress inconsistent: %zi %zi %zi %zi\n",
				ipos, new_ipos, opos, new_opos);
			ipos = new_ipos; opos = new_opos;
		}	
		advancepos(0, 0);
		if (syncfreq && !(xfer % (syncfreq*softbs)))
			printstatus((quiet? 0: stderr), 0, softbs, 1);
		else if (!quiet && !(xfer % (16*softbs)))
			printstatus(stderr, 0, softbs, 0);
	}
	close(fd_pipe[0]); close(fd_pipe[1]);
	return 0;
}
#endif

int tripleoverwrite(const off_t max)
{
	int ret = 0;
	off_t orig_opos = opos;
	void* prng_state2 = frandom_stdup(prng_state);
	clock_t orig_startclock = startclock;
	struct timeval orig_starttime;
	LISTTYPE(ofile_t) *of;
	memcpy(&orig_starttime, &starttime, sizeof(starttime));
	fprintf(stderr, "%s%s%s%s" DDR_INFO "Triple overwrite (BSI M7.15): first pass ... (frandom)      \n\n\n\n\n", up, up, up, up);
	ret += copyfile_softbs(max);
	fprintf(stderr, "syncing ... \n%s", up);
	ret += fsync(odes);
	LISTFOREACH(ofiles, of)
		fsync(LISTDATA(of).fd);
	/* TODO: better error handling */
	frandom_release(prng_state);
	prng_state = prng_state2; prng_state2 = 0;
	bsim715_2ndpass = 1;
	if (!bsim715_2) {
		opos = orig_opos; xfer = 0; ipos = 0;
		startclock = clock(); gettimeofday(&starttime, NULL);
		fprintf(stderr, DDR_INFO "Triple overwrite (BSI M7.15): second pass ... (frandom_inv)\n\n\n\n\n");
		ret += copyfile_softbs(max);
		fprintf(stderr, "syncing ... \n%s", up);
		ret += fsync(odes);
		LISTFOREACH(ofiles, of)
			fsync(LISTDATA(of).fd);
		/* TODO: better error handling */
		bsim715_2ndpass = 0;
		if (bsim715_4) {
			frandom_bytes(prng_state, buf, 16);
			fprintf(stderr, DDR_INFO "Triple overwrite (BSI M7.15): third pass ... (frandom) \n\n\n\n\n");
			opos = orig_opos; xfer = 0; ipos = 0;
			startclock = clock(); gettimeofday(&starttime, NULL);
			ret += copyfile_softbs(max);
			fprintf(stderr, "syncing ... \n%s", up);
			ret += fsync(odes);
			LISTFOREACH(ofiles, of)
				fsync(LISTDATA(of).fd);
			bsim715_2ndpass = 1;
			iname = "FRND+invFRND+FRND2+ZERO";
		} else
			iname = "FRND+invFRND+ZERO";
	} else
		iname = "FRND+ZERO";
	fprintf(stderr, DDR_INFO "Triple overwrite (BSI M7.15): last pass ... (zeros) \n\n\n\n\n");
	frandom_release(prng_state); prng_state = 0;
	memset(buf, 0, softbs); 
	i_repeat = 1; i_rep_init = 1;
	opos = orig_opos; xfer = 0; ipos = 0;
	startclock = clock(); gettimeofday(&starttime, NULL);
	ret += copyfile_softbs(max);
	startclock = orig_startclock;
	memcpy(&starttime, &orig_starttime, sizeof(starttime));
	xfer = sxfer;
	if (ret)
		fplog(stderr, WARN, "There were %i errors! %s may not be safely overwritten!\n", ret, oname);
	//fprintf(stderr, "syncing ... \n%s", up);
	return ret;
}

static off_t readint(const char* const ptr)
{
	char *es; double res;

	res = strtod(ptr, &es);
	switch (*es) {
		case 'b': res *= 512; break;
		case 'k': res *= 1024; break;
		case 'M': res *= 1024*1024; break;
		case 'G': res *= 1024*1024*1024; break;
		case ' ':
		case '\0': break;
		default:
			fplog(stderr, WARN, "suffix %c ignored!\n", *es);
	}
	return (off_t)res;
}

char readbool(const char* arg)
{
	if (isdigit(*arg))
		return !!atoi(arg);
	if (!strcasecmp(arg, "yes")
		|| !strcasecmp(arg, "y")
		|| !strcasecmp(arg, "always")
		|| !strcasecmp(arg, "true"))
		return 1;
	return 0;
}

void init_random()
{
	if (prng_sfile) {
		int ln, fd = -1;
		unsigned char sbf[256];
		if (!strcmp(prng_sfile, "-")) {
			fd = 0;
			if (verbose)
				fplog(stderr, INFO, "reading random seed from <stdin> ...\n");
		} else
			fd = open(prng_sfile, O_RDONLY);
		if (fd == -1) {
			fplog(stderr, FATAL, "Could not open \"%s\" for random seed!\n", prng_sfile);
			/* ERROR */
			cleanup(); exit(28);
		}
		if (prng_libc) {
			unsigned int* sval = (unsigned int*)sbf;
			ln = read(fd, sbf, 4);
			if (ln != 4) {
				fplog(stderr, FATAL, "failed to read 4 bytes from \"%s\"!\n", prng_sfile);
				cleanup(); exit(29);
			}
			srand(*sval); rand();
		} else {
			ln = read(fd, sbf, 256);
			if (ln != 256) {
				fplog(stderr, FATAL, "failed to read 256 bytes from \"%s\"!\n", prng_sfile);
				cleanup(); exit(29);
			}
			prng_state = frandom_init(sbf);
		}
	} else {
		if (!prng_seed)
			prng_seed = frandom_getseedval();
		if (prng_libc) {
			srand(prng_seed); rand();
		} else
			prng_state = frandom_init_lrand(prng_seed);
	}
}


void printversion()
{
	fprintf(stderr, "\ndd_rescue Version %s, kurt@garloff.de, GNU GPL v2/v3\n", VERSION);
	fprintf(stderr, " (%s)\n", ID);
	fprintf(stderr, " (compiled %s %s by %s)\n", __DATE__, __TIME__, __COMPILER__);
	fprintf(stderr, " (features: ");
#ifdef O_DIRECT
	fprintf(stderr, "O_DIRECT ");
#endif
#ifdef HAVE_LIBDL
	fprintf(stderr, "dl/libfallocate ");
#elif defined(HAVE_LIBFALLOCATE)
	fprintf(stderr, "libfallocate ");
#endif	
#if defined(HAVE_FALLOCATE)
	fprintf(stderr, "fallocate ");
#endif
#ifdef HAVE_SPLICE
	fprintf(stderr, "splice ");
#endif
	fprintf(stderr, ")\n");
	fprintf(stderr, "dd_rescue is free software. It's protected by the terms of GNU GPL v2 or v3\n");
	fprintf(stderr, " (at your option).\n");
}


#ifndef LACK_GETOPT_LONG
struct option longopts[] = { 	{"help", 0, NULL, 'h'}, {"verbose", 0, NULL, 'v'},
				{"quiet", 0, NULL, 'q'}, {"version", 0, NULL, 'V'},
				{"color", 1, NULL, 'c'},
				{"ipos", 1, NULL, 's'}, {"opos", 1, NULL, 'S'},
				{"softbs", 1, NULL, 'b'}, {"hardbs", 1, NULL, 'B'},
				{"maxerr", 1, NULL, 'e'}, {"maxxfer", 1, NULL, 'm'},
				{"noextend", 0, NULL, 'M'}, {"extend", 0, NULL, 'x'},
				{"append", 0, NULL, 'x'},
				{"syncfreq", 1, NULL, 'y'}, {"logfile", 1, NULL, 'l'},
				{"bbfile", 1, NULL, 'o'}, {"reverse", 0, NULL, 'r'},
				{"repeat", 0, NULL, 'R'}, {"truncate", 0, NULL, 't'},
				{"trunclast", 0, NULL, 'T'},
				{"odir_in", 0, NULL, 'd'}, {"odir_out", 0, NULL, 'D'},
				{"splice", 0, NULL, 'k'}, {"fallocate", 0, NULL, 'P'},
				{"abort_we", 0, NULL, 'w'}, {"avoidwrite", 0, NULL, 'W'},
				{"sparse", 0, NULL, 'a'}, {"alwayswrite", 0, NULL, 'A'},
				{"interactive", 0, NULL, 'i'}, {"force", 0, NULL, 'f'},
				{"preserve", 0, NULL, 'p'}, {"outfile", 1, NULL, 'Y'},
				{"random", 1, NULL, 'z'}, {"frandom", 1, NULL, 'Z'},
 				{"shred3", 1, NULL, '3'}, {"shred4", 1, NULL, '4'},
 				{"shred2", 1, NULL, '2'},
				/* GNU ddrescue compat */
				{"block-size", 1, NULL, 'B'}, {"input-position", 1, NULL, 's'},
				{"output-position", 1, NULL, 'S'}, {"max-size", 1, NULL, 'm'},
				/* dd like args */
				{"bs", 1, NULL, 'b'},	/* seek and skip refer to obs/ibs, thus no direct corresp. */
				{"of", 1, NULL, 'Y'},	/* short form of outfile */
				/* END */	
				{NULL, 0, NULL, 0},
};
#endif


void printhelp()
{
	printversion();
	fprintf(stderr, "dd_rescue copies data from one file (or block device) to another.\n");
	fprintf(stderr, "USAGE: dd_rescue [options] infile outfile\n");
	fprintf(stderr, "Options: -s ipos    start position in  input file (default=0),\n");
	fprintf(stderr, "         -S opos    start position in output file (def=ipos),\n");
	fprintf(stderr, "         -b softbs  block size for copy operation (def=%i, %i for -d),\n", BUF_SOFTBLOCKSIZE, DIO_SOFTBLOCKSIZE);
	fprintf(stderr, "         -B hardbs  fallback block size in case of errs (def=%i, %i for -d),\n", BUF_HARDBLOCKSIZE, DIO_HARDBLOCKSIZE);
	fprintf(stderr, "         -e maxerr  exit after maxerr errors (def=0=infinite),\n");
	fprintf(stderr, "         -m maxxfer maximum amount of data to be transfered (def=0=inf),\n");
	fprintf(stderr,	"         -M         avoid extending outfile,\n");
	fprintf(stderr,	"         -x         count opos from the end of outfile (eXtend),\n");
	fprintf(stderr, "         -y syncsz  frequency of fsync calls in bytes (def=512*softbs),\n");
	fprintf(stderr, "         -l logfile name of a file to log errors and summary to (def=\"\"),\n");
	fprintf(stderr, "         -o bbfile  name of a file to log bad blocks numbers (def=\"\"),\n");
	fprintf(stderr, "         -r         reverse direction copy (def=forward),\n");
	fprintf(stderr, "         -R         repeatedly write same block (def if infile is /dev/zero),\n");
	fprintf(stderr, "         -t         truncate output file (def=no),\n");
	fprintf(stderr, "         -T         truncate output file at last pos (def=no),\n");
#ifdef O_DIRECT
	fprintf(stderr, "         -d/D       use O_DIRECT for input/output (def=no),\n");
#endif
#ifdef HAVE_SPLICE
	fprintf(stderr, "         -k         use efficient in-kernel zerocopy splice,\n");
#endif       	
#if defined(HAVE_FALLOCATE) || defined(HAVE_LIBFALLOCATE)
	fprintf(stderr, "         -P         use fallocate to preallocate target space,\n");
#endif
	fprintf(stderr, "         -w         abort on Write errors (def=no),\n");
	fprintf(stderr, "         -W         read target block and avoid Writes if identical (def=no),\n");
	fprintf(stderr, "         -a         spArse file writing (def=no),\n");
	fprintf(stderr, "         -A         Always write blocks, zeroed if err (def=no),\n");
	fprintf(stderr, "         -i         interactive: ask before overwriting data (def=no),\n");
	fprintf(stderr, "         -f         force: skip some sanity checks (def=no),\n");
	fprintf(stderr, "         -p         preserve: preserve ownership / perms (def=no),\n");
	fprintf(stderr, "         -Y oname   Secondary output file (multiple possible),\n");
	fprintf(stderr, "         -q         quiet operation,\n");
	fprintf(stderr, "         -v         verbose operation,\n");
	fprintf(stderr, "         -c 0/1     switch off/on colors (def=auto),\n");
	fprintf(stderr, "         -V         display version and exit,\n");
	fprintf(stderr, "         -h         display this help and exit.\n");
	fprintf(stderr, "Instead of infile, -z/Z SEED or -z/Z SEEDFILE may be specified, taking the PRNG\n");
	fprintf(stderr, " from libc or frandom (RC4 based) as input. SEED = 0 means a time based seed;\n");
	fprintf(stderr, " Using /dev/urandom as SEEDFILE gives good pseudo random numbers.\n");
	fprintf(stderr, "Likewise, -3 SEED/SEEDFILE will overwrite ofile 3 times (r,ir,0, BSI M7.15).\n");
	fprintf(stderr, " With -4 SEED/SEEDFILE you get an additional random pass (r,ir,r2,0).\n");
	fprintf(stderr, " With -2 SEED/SEEDFILE you only get one random pass (r,0).\n\n");
	fprintf(stderr, "Sizes may be given in units b(=512), k(=1024), M(=1024^2) or G(1024^3) bytes\n");
	fprintf(stderr, "This program is useful to rescue data in case of I/O errors, because\n");
	fprintf(stderr, " it does not necessarily abort or truncate the output.\n");
}

#define YESNO(flag) (flag? "yes": "no ")

void printinfo(FILE* const file)
{
	fplog(file, INFO, "about to transfer %.1f kBytes from %s to %s\n",
	      (double)maxxfer/1024, iname, oname);
	fplog(file, INFO, "blocksizes: soft %i, hard %i\n", softbs, hardbs);
	fplog(file, INFO, "starting positions: in %.1fk, out %.1fk\n",
	      (double)ipos/1024, (double)opos/1024);
	fplog(file, INFO, "Logfile: %s, Maxerr: %li\n",
	      (lname? lname: "(none)"), maxerr);
	fplog(file, INFO, "Reverse: %s, Trunc: %s, interactive: %s\n",
	      YESNO(reverse), (dotrunc? "yes": (trunclast? "last": "no")), YESNO(interact));
	fplog(file, INFO, "abort on Write errs: %s, spArse write: %s\n",
	      YESNO(abwrerr), (sparse? "yes": (nosparse? "never": "if err")));
	fplog(file, INFO, "preserve: %s, splice: %s, avoidWrite: %s\n",
	      YESNO(preserve), YESNO(dosplice), YESNO(avoidwrite));
	fplog(file, INFO, "fallocate: %s, Repeat: %s, O_DIRECT: %s/%s\n",
	      YESNO(falloc), YESNO(i_repeat), YESNO(o_dir_in), YESNO(o_dir_out));
	/*
	fplog(file, INFO, "verbose: %s, quiet: %s\n", 
	      YESNO(verbose), YESNO(quiet));
	*/
}

void breakhandler(int sig)
{
	fplog(stderr, FATAL, "Caught signal %i \"%s\". Exiting!\n",
	      sig, strsignal(sig));
	printreport();
	cleanup();
	signal(sig, SIG_DFL);
	raise(sig);
}

unsigned char* zalloc_aligned_buf(unsigned int bs, unsigned char**obuf)
{
	unsigned char *ptr;
#if defined (__DragonFly__) || defined(__NetBSD__)
	ptr = (unsigned char*)valloc(bs);
#else
	void *mp;
	if (posix_memalign(&mp, pagesize, bs))
		ptr = 0;
	else
		ptr = (unsigned char*)mp;
#endif /* NetBSD */
	if (obuf) 
		*obuf = ptr;
	if (!ptr) {
		fplog(stderr, WARN, "allocation of aligned buffer failed -- use malloc\n");
		ptr = (unsigned char*)malloc(bs + pagesize);
		if (!ptr) {
			fplog(stderr, FATAL, "allocation of buffer failed!\n");
			cleanup(); exit(18);
		}
		if (obuf)
			*obuf = ptr;
		ptr += pagesize-1;
		ptr -= (unsigned long)ptr % pagesize;
	}
	memset(ptr, 0, bs);
	return ptr;
}

/** Heuristic: strings starting with - or a digit are numbers, ev.thing else a filename. A pure "-" is a filename. */
int is_filename(char* arg)
{
	if (!arg)
		return 0;
	if (!strcmp(arg, "-"))
		return 1;
	if (isdigit(arg[0]) || arg[0] == '-')
		return 0;
	return 1;
}

const char* retstrdupcat3(const char* dir, char dirsep, const char* inm)
{
	char* ibase = basename(strdupa(inm));
	const int dlen = strlen(dir) + (dirsep>0? 1: dirsep);
	char* ret = (char*)malloc(dlen + strlen(inm) + 1);
	strcpy(ret, dir);
	if (dirsep > 0) {
		ret[dlen-1] = dirsep;
		ret[dlen] = 0;
	}
	strcpy(ret+dlen, ibase);
	LISTAPPEND(freenames, ret, charp);
	return ret;
}
		

/** Fix output filename if it's a directory */
const char* dirappfile(const char* onm)
{
	size_t oln = strlen(onm);
	if (!strcmp(onm, ".")) {
		char* ret = strdup(basename(strdupa(iname)));
		LISTAPPEND(freenames, ret, charp);
		return ret;
	}
	if (oln > 0) {
		char lastchr = onm[oln-1];
		if (lastchr == '/') 
			return retstrdupcat3(onm, 0, iname);
		else if ((lastchr == '.') &&
			  (oln > 1 && onm[oln-2] == '/'))
			return retstrdupcat3(onm, -1, iname);
		else if ((lastchr == '.') &&
			   (oln > 2 && onm[oln-2] == '.' && onm[oln-3] == '/'))
			return retstrdupcat3(onm, '/', iname);
		else { /* Not clear by name, so test */
			struct stat stbuf;
			int err = stat(onm, &stbuf);
			if (!err && S_ISDIR(stbuf.st_mode))
				return retstrdupcat3(onm, '/', iname);
		}
	}
	return onm;
}

char test_nocolor_term()
{
	char* term = getenv("TERM");
	if (!term) 
		return 1;
	if (!strcasecmp(term, "dumb") || !strcasecmp(term, "unknown")
		|| !strcasecmp(term, "net") || !strcasecmp(term, "vanilla"))
		return 1;
	if (!strcasecmp(term+strlen(term)-2, "-m") 
		|| !strcasecmp(term+strlen(term)-5, "-mono"))
		return 1;
	return 0;
}

int main(int argc, char* argv[])
{
	int c;
	off_t syncsz = -1;

  	/* defaults */
	softbs = 0; hardbs = 0; /* marker for defaults */
	maxerr = 0; ipos = (off_t)-INT_MAX; opos = (off_t)-INT_MAX; maxxfer = 0; 
	reverse = 0; dotrunc = 0; trunclast = 0; abwrerr = 0; sparse = 0; nosparse = 0;
	verbose = 0; quiet = 0; interact = 0; force = 0; preserve = 0;
	lname = 0; iname = 0; oname = 0; o_dir_in = 0; o_dir_out = 0;
	dosplice = 0; falloc = 0;

	/* Initialization */
	sxfer = 0; fxfer = 0; lxfer = 0; xfer = 0; axfer = 0;
	ides = -1; odes = -1; logfd = 0; nrerr = 0; buf = 0; buf2 = 0;
	i_chr = 0; o_chr = 0;

	i_repeat = 0; i_rep_init = 0; i_rep_zero = 0;
	noextend = 0; avoidwrite = 0; avoidnull = 0;
	bsim715 = 0; bsim715_4 = 0; bsim715_2 = 0; bsim715_2ndpass = 0;
	extend = 0;
	prng_libc = 0; prng_frnd = 0;
	prng_seed = 0; prng_sfile = 0;
	prng_state = 0; prng_state2 = 0;

	ofiles = NULL;

	nocol = test_nocolor_term();
#ifdef NEED_SIMD_RUNTIME_DETECTION
	detect_simd();
#endif

#ifdef _SC_PAGESIZE
	pagesize = sysconf(_SC_PAGESIZE);
#endif
#ifdef LACK_GETOPT_LONG
	while ((c = getopt(argc, argv, ":rtTfihqvVwWaAdDkMRpPc:b:B:m:e:s:S:l:o:y:z:Z:2:3:4:xY:")) != -1) 
#else
	while ((c = getopt_long(argc, argv, ":rtTfihqvVwWaAdDkMRpPc:b:B:m:e:s:S:l:o:y:z:Z:2:3:4:xY:", longopts, NULL)) != -1) 
#endif
	{
		switch (c) {
			case 'r': reverse = 1; break;
			case 'R': i_repeat = 1; break;
			case 't': dotrunc = O_TRUNC; break;
			case 'T': trunclast = 1; break;
			case 'i': interact = 1; force = 0; break;
			case 'f': interact = 0; force = 1; break;
#ifdef O_DIRECT
			case 'd': o_dir_in  = O_DIRECT; break;
			case 'D': o_dir_out = O_DIRECT; break;
#endif
#ifdef HAVE_SPLICE
			case 'k': dosplice = 1; break;
#endif				  
			case 'p': preserve = 1; break;
			case 'P': falloc = 1; break;
			case 'a': sparse = 1; nosparse = 0; break;
			case 'A': nosparse = 1; sparse = 0; break;
			case 'w': abwrerr = 1; break;
			case 'W': avoidwrite = 1; break;
			case 'h': printhelp(); exit(0); break;
			case 'V': printversion(); exit(0); break;
			case 'v': quiet = 0; verbose = 1; break;
			case 'q': verbose = 0; quiet = 1; break;
			case 'c': nocol = !readbool(optarg); break;
			case 'b': softbs = (int)readint(optarg); break;
			case 'B': hardbs = (int)readint(optarg); break;
			case 'm': maxxfer = readint(optarg); break;
			case 'M': noextend = 1; break;
			case 'e': maxerr = (int)readint(optarg); break;
			case 'y': syncsz = readint(optarg); break;
			case 's': ipos = readint(optarg); break;
			case 'S': opos = readint(optarg); break;
			case 'l': lname = optarg; break;
			case 'o': bbname = optarg; break;
			case 'x': extend = 1; break;
			case 'Y': do { ofile_t of; of.name = optarg; of.fd = -1; of.cdev = 0; LISTAPPEND(ofiles, of, ofile_t); } while (0); break;
			case 'z': prng_libc = 1; if (is_filename(optarg)) prng_sfile = optarg; else prng_seed = readint(optarg); break;
			case 'Z': prng_frnd = 1; if (is_filename(optarg)) prng_sfile = optarg; else prng_seed = readint(optarg); break;
			case '2': prng_frnd = 1; if (is_filename(optarg)) prng_sfile = optarg; else prng_seed = readint(optarg); bsim715 = 1; bsim715_2 = 1; break;
			case '3': prng_frnd = 1; if (is_filename(optarg)) prng_sfile = optarg; else prng_seed = readint(optarg); bsim715 = 1; break;
			case '4': prng_frnd = 1; if (is_filename(optarg)) prng_sfile = optarg; else prng_seed = readint(optarg); bsim715 = 1; bsim715_4 = 1; break;
			case ':': fplog(stderr, FATAL, "option %c requires an argument!\n", optopt); 
				printhelp();
				exit(11); break;
			case '?': fplog(stderr, FATAL, "unknown option %c!\n", optopt, argv[0]);
				printhelp();
				exit(11); break;
			default: fplog(stderr, FATAL, "your getopt() is buggy!\n");
				exit(255);
		}
	}
  
	init_opos = opos;
	
	if (prng_libc)
		iname = "PRNG_libc";
	else if (prng_frnd)
		iname = "PRNG_frnd";
	else if (optind < argc)
		iname = argv[optind++];

	if (optind < argc) 
		oname = argv[optind++];
	if (optind < argc) {
		fplog(stderr, FATAL, "spurious options: %s ...\n", argv[optind]);
		printhelp();
		exit(12);
	}
	if (!iname || !oname) {
		fplog(stderr, FATAL, "both input and output files have to be specified!\n");
		printhelp();
		exit(12);
	}

	if (lname) {
		c = openfile(lname, O_WRONLY | O_CREAT /*| O_EXCL*/);
		logfd = fdopen(c, "a");
	}

	/* Defaults for blocksizes */
	if (softbs == 0) {
		if (o_dir_in)
			softbs = DIO_SOFTBLOCKSIZE;
		else
			softbs = BUF_SOFTBLOCKSIZE;
	}
	if (hardbs == 0) {
		if (o_dir_in)
			hardbs = DIO_HARDBLOCKSIZE;
		else
			hardbs = BUF_HARDBLOCKSIZE;
	}
	if (!quiet)
		fplog(stderr, INFO, "Using softbs=%lu, hardbs=%lu\n", softbs, hardbs);

	/* sanity checks */
#ifdef O_DIRECT
	if ((o_dir_in || o_dir_out) && hardbs < 512) {
		hardbs = 512;
		fplog(stderr, WARN, "O_DIRECT requires hardbs of at least %i!\n",
		      hardbs);
	}

	if (o_dir_in || o_dir_out)
		fplog(stderr, WARN, "We don't handle misalignment of last block w/ O_DIRECT!\n");
				
#endif

	if (softbs < hardbs) {
		fplog(stderr, WARN, "setting hardbs from %i to softbs %i!\n",
		      hardbs, softbs);
		hardbs = softbs;
	}

	/* Set sync frequency */
	/*
	if (syncsz == -1)
		syncfreq = 512;
	else */ if (syncsz <= 0)
		syncfreq = 0;
	else
		syncfreq = (syncsz + softbs - 1) / softbs;

	/* Have those been set by cmdline params? */
	if (ipos == (off_t)-INT_MAX) 
		ipos = 0;

	if (dosplice && avoidwrite) {
		fplog(stderr, WARN, "disable write avoidance (-W) for splice copy\n");
		avoidwrite = 0;
	}
	buf = zalloc_aligned_buf(softbs, &origbuf);

	/* Optimization: Don't reread from /dev/zero over and over ... */
	if (!dosplice && !strcmp(iname, "/dev/zero")) {
		if (!i_repeat && verbose)
			fplog(stderr, INFO, "turning on repeat (-R) for /dev/zero\n");
		i_repeat = 1;
		if (reverse && !ipos && maxxfer)
			ipos = maxxfer > opos? opos: maxxfer;
	}

	/* Properly append input basename if output name is dir */
	oname = dirappfile(oname);

	identical = check_identical(iname, oname);

	if (identical && dotrunc && !force) {
		fplog(stderr, FATAL, "infile and outfile are identical and trunc turned on!\n");
		cleanup(); exit(14);
	}
	/* Open input and output files */
	if (prng_libc || prng_frnd) {
		init_random();
		i_chr = 1; /* ides = 0; */
		dosplice = 0; sparse = 0;
	} else {
		ides = openfile(iname, O_RDONLY | o_dir_in);
		if (ides < 0) {
			fplog(stderr, FATAL, "could not open %s: %s\n", iname, strerror(errno));
			cleanup(); exit(22);
		}
	}
	/* Overwrite? */
	/* Special case '-': stdout */
	if (strcmp(oname, "-"))
		odes = open(oname, O_WRONLY | o_dir_out, 0640);
	else {
		odes = 1;
		o_chr = 1;
	}

	if (odes > 1) 
		close(odes);

	if (odes > 1 && interact) {
		int a;
		do {
			fprintf(stderr, "dd_rescue: (question): %s existing %s [y/n] ?", 
				(dotrunc? "Overwrite": "Write into"), oname);
			a = toupper(fgetc(stdin)); //fprintf(stderr, "\n");
		} while (a != 'Y' && a != 'N');
		if (a == 'N') {
			fplog(stderr, FATAL, "exit on user request!\n");
			cleanup(); exit(23);
		}
	}
	if (o_chr && avoidwrite) {
		if (!strcmp(oname, "/dev/null")) {
			fplog(stderr, INFO, "Avoid writes to /dev/null ...\n");
			avoidnull = 1;
		} else {
			fplog(stderr, WARN, "Disabling -Write avoidance b/c ofile is not seekable\n");
			avoidwrite = 0;
		}
	}
		
	if (odes != 1) {
		if (avoidwrite) {
			buf2 = zalloc_aligned_buf(softbs, &origbuf2);
			odes = openfile(oname, O_RDWR | O_CREAT | o_dir_out /*| O_EXCL*/ | dotrunc);
		} else
			odes = openfile(oname, O_WRONLY | O_CREAT | o_dir_out /*| O_EXCL*/ | dotrunc);
	}

	if (odes < 0) {
		fplog(stderr, FATAL, "%s: %s\n", oname, strerror(errno));
		cleanup(); exit(24);
	}

	if (preserve)
		copyperm(ides, odes);
			
	check_seekable(ides, &i_chr, "input");
	check_seekable(odes, &o_chr, "output");

	sparse_output_warn();
	if (o_chr) {
		if (!nosparse)
			fplog(stderr, WARN, "Not using sparse writes for non-seekable output\n");
		nosparse = 1; sparse = 0; dosplice = 0;
		if (avoidwrite) {
			if (!strcmp(oname, "/dev/null")) {
				fplog(stderr, INFO, "Avoid writes to /dev/null ...\n");
				avoidnull = 1;
			} else {
				fplog(stderr, WARN, "Disabling -Write avoidance b/c ofile is not seekable\n");
				ZFREE(origbuf2);
				avoidwrite = 0;
			}
		}
	}

	/* special case: reverse with ipos == 0 means ipos = end_of_file */
	if (reverse && ipos == 0) {
		ipos = lseek(ides, ipos, SEEK_END);
		if (ipos == -1) {
			fplog(stderr, FATAL, "could not seek to end of file %s!\n", iname);
			perror("dd_rescue"); cleanup(); exit(19);
		}
		if (verbose) 
			fprintf(stderr, DDR_INFO "ipos set to the end: %.1fk\n", 
			        (double)ipos/1024);
		/* if opos not set, assume same position */
		if (opos == (off_t)-INT_MAX) 
			opos = ipos;
		/* if explicitly set to zero, assume end of _existing_ file */
		if (opos == 0) {
			opos = lseek(odes, opos, SEEK_END);
			if (opos == (off_t)-1) {
				fplog(stderr, FATAL, "could not seek to end of file %s!\n", oname);
				perror("dd_rescue"); cleanup(); exit(19);
			}
			/* if existing empty, assume same position */
			if (opos == 0) 
				opos = ipos;
			if (verbose) 
				fprintf(stderr, DDR_INFO "opos set to: %.1fk\n",
					(double)opos/1024);
    		}
	}

	/* if opos not set, assume same position */
	if (opos == (off_t)-INT_MAX)
		opos = ipos;

	if (identical) {
		fplog(stderr, WARN, "infile and outfile are identical!\n");
		if (opos > ipos && !reverse && !force) {
			fplog(stderr, WARN, "turned on reverse, as ipos < opos!\n");
			reverse = 1;
    		}
		if (opos < ipos && reverse && !force) {
			fplog(stderr, WARN, "turned off reverse, as opos < ipos!\n");
			reverse = 0;
		}
  	}

	if (o_chr && opos != 0) {
		if (force)
			fplog(stderr, WARN, "ignore non-seekable output with opos != 0 due to --force\n");
		else {
			fplog(stderr, FATAL, "outfile not seekable, but opos !=0 requested!\n");
			cleanup(); exit(19);
		}
	}
	if (i_chr && ipos != 0) {
		fplog(stderr, FATAL, "infile not seekable, but ipos !=0 requested!\n");
		cleanup(); exit(19);
	}
		
	if (dosplice) {
		if (!quiet)
			fplog(stderr, INFO, "splice copy, ignoring -a, -r, -y, -R, -W\n");
		reverse = 0;
	}

	if (noextend || extend) {
		if (output_length() == -1) {
			fplog(stderr, FATAL, "asked to (not) extend output file but can't determine size\n");
			cleanup(); exit(19);
		}
		if (extend)
			opos += olen;
	}
	input_length();

	if (ipos < 0 || opos < 0) {
		fplog(stderr, FATAL, "negative position requested (%.1fk)\n", (double)ipos/1024);
		cleanup(); exit(25);
	}


#if defined(HAVE_FALLOCATE) || defined(HAVE_LIBFALLOCATE)
	if (falloc && !o_chr)
		do_fallocate(odes, oname);
#endif

	if (verbose) {
		printinfo(stderr);
		if (logfd)
			printinfo(logfd);
	}

	if (bsim715 && avoidwrite) {
		fplog(stderr, WARN, "won't avoid writes for -3\n");
		avoidwrite = 0;
		ZFREE(buf2);
	}
	if (bsim715 && o_chr) {
		fplog(stderr, WARN, "triple overwrite with non-seekable output!\n");
	}
	if (reverse && trunclast)
		if (ftruncate(odes, opos))
			fplog(stderr, WARN, "Could not truncate %s to %.1fk: %s!\n",
				oname, (double)opos/1024, strerror(errno));

	LISTTYPE(ofile_t) *of;
	LISTFOREACH(ofiles, of) {
		int id;
		ofile_t *oft = &(LISTDATA(of));
		oft->name = dirappfile(oft->name);
		id = check_identical(iname, oft->name);
		if (id)
			fplog(stderr, WARN, "Input file and secondary output file %s are identical!\n", oft->name);
		oft->fd = openfile(oft->name, (avoidwrite? O_RDWR: O_WRONLY) | O_CREAT | o_dir_out | dotrunc);
		check_seekable(oft->fd, &(oft->cdev), NULL);
		if (preserve)
			copyperm(ides, oft->fd);
#if defined(HAVE_FALLOCATE) || defined(HAVE_LIBFALLOCATE)
		if (falloc && !oft->cdev)
			do_fallocate(oft->fd, oft->name);
#endif
		if (reverse && trunclast)
			if (ftruncate(oft->fd, opos))
				fplog(stderr, WARN, "Could not truncate %s to %.1fk: %s!\n",
					oft->name, (double)opos/1024, strerror(errno));
	}

	/* Install signal handler */
	signal(SIGHUP , breakhandler);
	signal(SIGINT , breakhandler);
	signal(SIGTERM, breakhandler);
	signal(SIGQUIT, breakhandler);

	/* Save time and start to work */
	startclock = clock();
	gettimeofday(&starttime, NULL);
	memcpy(&lasttime, &starttime, sizeof(lasttime));

	if (!quiet) {
		scrollup = 0;
		printstatus(stderr, 0, softbs, 0);
	}

	if (bsim715) {
		c = tripleoverwrite(maxxfer);
	} else {
#ifdef HAVE_SPLICE
		if (dosplice)
			c = copyfile_splice(maxxfer);
		else 
#endif
		{
			if (softbs > hardbs)
				c = copyfile_softbs(maxxfer);
			else
				c = copyfile_hardbs(maxxfer);
		}
	}

	gettimeofday(&currenttime, NULL);
	printreport();
	c += cleanup();
	if (c && verbose)
		fplog(stderr, WARN, "There were %i errors! \n", c);
	return c;
}

