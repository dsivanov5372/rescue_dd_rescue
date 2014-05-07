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
 * - Use termcap to fetch cursor up/down and color codes
 * - Display more infos on errors by collecting info from syslog
 * - Option to send TRIM on zeroed file blocks
 * - Options to compress with libz, liblzo, libbz2, lzma, ... 
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef VERSION
# define VERSION "(unknown)"
#endif
#ifndef __COMPILER__
# define __COMPILER__ "(unknown compiler)"
#endif

#define ID "$Id$"

#ifndef BUF_SOFTBLOCKSIZE
# define BUF_SOFTBLOCKSIZE 131072
#endif

#ifndef BUF_HARDBLOCKSIZE
# define BUF_HARDBLOCKSIZE fstate->pagesize
#endif

#ifndef DIO_SOFTBLOCKSIZE
# define DIO_SOFTBLOCKSIZE 1048576
#endif

#ifndef DIO_HARDBLOCKSIZE
# define DIO_HARDBLOCKSIZE 512
#endif


#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64

#ifdef TEST_SYSCALL
#define splice _splice
#define fallocate64 _fallocate64
#define pread64 _pread64
#define pwrite64 _pwrite64
#endif
// hack around buggy splice definition(!)
#if defined(__GLIBC__) && __GLIBC__ == 2 && __GLIBC_MINOR__ < 10
# define SPLICE_IS_BUGGY 1
# define splice _splice
#endif

#include <unistd.h>
#include <fcntl.h>

#ifdef SPLICE_IS_BUGGY
#undef splice
#endif
#ifdef TEST_SYSCALL
#undef splice
#undef fallocate64
#undef pread64
#undef pwrite64
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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
#include <assert.h>

#include "frandom.h"
#include "list.h"
#include "fmt_no.h"
#include "find_nonzero.h"

#include "fstrim.h"

#include "ddr_plugin.h"
#include "ddr_ctrl.h"

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif

#ifdef NO_LIBFALLOCATE
# undef HAVE_LIBFALLOCATE
# undef HAVE_FALLOCATE_H
#endif

#ifdef HAVE_FALLOCATE_H
# include <fallocate.h>
#else
# ifdef HAVE_FALLOCATE64
#  include <linux/falloc.h>
# endif
#endif

#if defined(HAVE_DLFCN_H) && !defined(NO_LIBDL)
#include <dlfcn.h>
void* libfalloc = (void*)0;
#define USE_LIBDL 1
#endif

/* splice */
#if defined(__linux__) && (!defined(HAVE_SPLICE) || defined(SPLICE_IS_BUGGY) || defined(TEST_SYSCALL))
#include "splice.h"
#endif
/* fallocate64 */
#if defined(__linux__) && (!defined(HAVE_FALLOCATE64) || defined(TEST_SYSCALL))
# include "fallocate64.h"
#endif

/* xattrs */
#ifdef HAVE_ATTR_XATTR_H
# include <attr/xattr.h>
#else
/* TODO: Could provide the prototypes for the syscalls ourselves ... */
# warning No support for copying extended attributes / ACLs
#endif

/* Handle lack of stat64 */
#ifdef HAVE_STAT64
# define STAT64 stat64
# define FSTAT64 fstat64
#else
# define STAT64 stat
# define FSTAT64 fstat
# warning We lack stat64, may not handle >2GB files correctly
#endif

#ifndef HAVE_LSEEK64
# define lseek64 lseek
# warning We lack lseek64, may not handle >2GB files correctly
#endif

/* This is not critical -- most platforms have an internal 64bit offset with plain open() */
#ifndef HAVE_OPEN64
# define open64 open
#endif

#if !defined(HAVE_PREAD64) || defined(TEST_SYSCALL)
#include "pread64.h"
#endif


/* fwd decls */
int cleanup();

/* Options */
static opt_t _opts;
opt_t *opts = &_opts;

/* Data protection */
static dpopt_t _dpopts;
dpopt_t *dpopts = &_dpopts;

static dpstate_t _dpstate;
dpstate_t *dpstate = &_dpstate;

/* State */
static fstate_t _fstate;
fstate_t *fstate = &_fstate;

/* Progress */
static progress_t _progress;
progress_t *progress = &_progress;

/* Repeat zero optimization */
static repeat_t _repeat;
repeat_t *repeat = &_repeat;


/* Rate limit for status updates */
float printint = 0.1;
char in_report;

FILE *logfd;

struct timeval starttime, lasttime, currenttime;
struct timezone tz;
clock_t startclock;

sig_atomic_t interrupted = 0;
int int_by = 0;

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

const char* ddrlogpre[] = {"", DDR_INFO, DDR_WARN, DDR_FATAL };
const char* ddrlogpre_c[] = {"", DDR_INFO_C, DDR_WARN_C, DDR_FATAL_C };


#ifdef MISS_STRSIGNAL
static char sfstate->buf[16];
static char* strsignal(int sig)
{
	sprintf(sfstate->buf, "sig %i", sig);
	return sfstate->buf;
}
#endif

inline char* fmt_kiB(loff_t no)
{
	return fmt_int(0, 1, 1024, no, (opts->nocol? "": BOLD), (opts->nocol? "": NORM), 1);
}

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
			if ((file == stdout || file == stderr) && !opts->nocol)
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

/** Plugin infrastructure */
unsigned int max_slack_pre = 0;
int max_neg_slack_pre = 0;
unsigned int max_slack_post = 0;
int max_neg_slack_post = 0;
int last_lnchg = -1;
unsigned int max_align = 0;
char not_sparse = 0;
char plugin_help = 0;
char have_block_cb = 0;

char plugins_loaded = 0;
char plugins_opened = 0;
LISTDECL(ddr_plugin_t);
LISTTYPE(ddr_plugin_t) *ddr_plugins;

void call_plugins_open()
{
	unsigned int slk_pre = 0, slk_post = 0;
	/* Do iterate over list */
	LISTTYPE(ddr_plugin_t) *plug;
	LISTFOREACH(ddr_plugins, plug) {
		if (LISTDATA(plug).open_callback) {
			int spre  = LISTDATA(plug).slack_pre ;
			int spost = LISTDATA(plug).slack_post;
			slk_pre  += spre  >= 0? spre : -spre *((opts->softbs+15)/16);
			slk_post += spost >= 0? spost: -spost*((opts->softbs+15)/16);
			/*
			fplog(stderr, INFO, "Pre %i Post %i TPre %i TPost %i\n",
				spre, spost, slk_pre, slk_post);
			 */
			int err = LISTDATA(plug).open_callback(fstate->ides, opts->iname, fstate->ipos,
						fstate->odes, opts->oname, fstate->opos,
						opts->softbs, opts->hardbs, progress->estxfer, 
						(plugins_opened < last_lnchg ? 1: 0),
						max_slack_pre-slk_pre, max_slack_post-slk_post,
					       	&fstate->buf, &LISTDATA(plug).state);
			if (err < 0) {
				fplog(stderr, WARN, "Error initializing plugin %s: %s!\n",
					LISTDATA(plug).name, strerror(err));
				exit(13);
			} else if (err>0) {
				fstate->ipos += err;
				fplog(stderr, WARN, "Plugin %s skipping %i bytes might break other plugins!\n",
					LISTDATA(plug).name, err);
			}
		}
		++plugins_opened;
	}
	assert(slk_pre  == max_slack_pre );
	assert(slk_post == max_slack_post);
}

void call_plugins_close()
{
	if (!plugins_opened)
		return;
	LISTTYPE(ddr_plugin_t) *plug;
	LISTFOREACH(ddr_plugins, plug) {
		if (LISTDATA(plug).close_callback) {
			int err = LISTDATA(plug).close_callback(fstate->opos, &LISTDATA(plug).state);
			if (err)
				fplog(stderr, WARN, "Error closing plugin %s: %s!\n",
					LISTDATA(plug).name, strerror(err));
		}
		--plugins_opened;
	}
}

unsigned char* call_plugins_block(unsigned char *bf, int *towr, int eof, loff_t *ooff)
{
	if (!plugins_opened)
		return bf;
	LISTTYPE(ddr_plugin_t) *plug;
	LISTFOREACH(ddr_plugins, plug)
		if (LISTDATA(plug).block_callback)
			bf = LISTDATA(plug).block_callback(bf, towr, eof, ooff, &LISTDATA(plug).state);
	return bf;
}

#ifdef USE_LIBDL
typedef void* VOIDP;
LISTDECL(VOIDP);
LISTTYPE(VOIDP) *ddr_plug_handles;

ddr_plugin_t* insert_plugin(void* hdl, const char* nm, char* param)
{
	LISTAPPEND(ddr_plug_handles, hdl, VOIDP);
	ddr_plugin_t *plug = (ddr_plugin_t*)dlsym(hdl, "ddr_plug");
	if (!plug) {
		fplog(stderr, WARN, "plugin %s loaded, but ddr_plug not found!\n", nm);
		return NULL;
	}
	if (!plug->name)
		plug->name = nm;
	plug->fplog = fplog;

	if (plug->slack_pre > 0)
		max_slack_pre += plug->slack_pre;
	else if (plug->slack_pre < 0)
		max_neg_slack_pre += plug->slack_pre;
	if (plug->slack_post > 0)
		max_slack_post += plug->slack_post;
	else if (plug->slack_post < 0)
		max_neg_slack_post += plug->slack_post;

	if (plug->needs_align > max_align)
		max_align = plug->needs_align;
	if (!plug->handles_sparse)
		not_sparse = 1;
	if (param && !plug->init_callback) {
		fplog(stderr, FATAL, "Plugin %s has no init callback to consume passed param %s\n",
			nm, param);
		exit(13);
	}
	if (plug->init_callback)
		if (plug->init_callback(&plug->state, param, plugins_loaded))
			exit(13);
	plugins_loaded++;
	LISTAPPEND(ddr_plugins, *plug, ddr_plugin_t);
	if (param && !memcmp(param, "help", 4))
		plugin_help++;
	if (plug->block_callback)
		have_block_cb++;
	return plug;
}


void load_plugins(char* plugs)
{
	char* next;
	char path[256];
	int plugno = 0;
	int errs = 0;
	while (plugs) {
		next = strchr(plugs, ',');
		if (next)
			*next++ = 0;
		char* param = strchr(plugs, '=');
		if (param)
			*param++ = 0;
		snprintf(path, 255, "libddr_%s.so", plugs);
		//errno = ENOENT;
		void* hdl = dlopen(path, RTLD_NOW);
		/* Allow full name (with absolute path if wanted) */
		if (!hdl) 
			hdl = dlopen(plugs, RTLD_NOW);
		if (!hdl) {
			fplog(stderr, FATAL, "Could not load plugin %s\n", plugs);
			++errs;
		} else {
			ddr_plugin_t *plug = insert_plugin(hdl, plugs, param);
			if (!plug) {
				++errs;
				continue;
			}
			if (plug->changes_output_len)
				last_lnchg = plugno;
			++plugno;
		}
		plugs = next;
	}
	if (errs)
		exit(13);
}

void unload_plugins()
{
	LISTTYPE(VOIDP) *plug_hdl;
	/* FIXME: Freeing in opts->reverse order would be better ... */
	LISTFOREACH(ddr_plug_handles, plug_hdl)
		dlclose(LISTDATA(plug_hdl));
	LISTTREEDEL(ddr_plug_handles, VOIDP);
	LISTTREEDEL(ddr_plugins, ddr_plugin_t);
}
#endif

#if defined(HAVE_POSIX_FADVISE) && !defined(HAVE_POSIX_FADVISE64)
#define posix_fadvise64 posix_fadvise
#endif
#ifdef HAVE_POSIX_FADVISE
static inline void fadvise(char after)
{
	if (!opts->reverse) {
		if (after) 
			posix_fadvise64(fstate->ides, opts->init_ipos, progress->xfer, POSIX_FADV_NOREUSE);
		else 
			posix_fadvise64(fstate->ides, opts->init_ipos, progress->estxfer, POSIX_FADV_SEQUENTIAL);
	}
}
#else
static inline void fadvise(char after)
{}
#endif


static int check_identical(const char* const in, const char* const on)
{
	int err = 0;
	struct STAT64 istat, ostat;
	errno = 0;
	if (strcmp(in, on) == 0) 
		return 1;
	err -= STAT64(in, &istat);
	if (err)
	       	return 0;
	err -= STAT64(on, &ostat);
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
		fdes = open64(fname, flags, 0640);
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
	if (!*ischr && lseek64(fd, (loff_t)0, SEEK_SET) != 0) {
		if (msg) {
			fplog(stderr, WARN, "file %s is not seekable!\n", msg);
			fplog(stderr, WARN, "%s\n", strerror(errno));
		}
		*ischr = 1;
	}
	errno = 0;
}

/** Calc position in graph */
inline int gpos(loff_t off)
{
	static const int glen = 40; //strlen(graph) - 2;
	return 1+(glen*off/fstate->ilen);
}

/** Prepare graph */
static void preparegraph()
{
	if (!fstate->ilen || opts->init_ipos > fstate->ilen)
		return;
	graph = strdup(":.........................................:");
	if (opts->reverse) {
		graph[gpos(opts->init_ipos)+1] = '<';
		graph[gpos(opts->init_ipos-progress->estxfer)-1] = '>';

	} else {
		graph[gpos(opts->init_ipos)-1] = '>';
		graph[gpos(opts->init_ipos+progress->estxfer)+1] = '<';
	}
}

void updgraph(int err)
{
	int off;
	if (!fstate->ilen || fstate->ipos > fstate->ilen)
		return;
	off = gpos(fstate->ipos);
	if (graph[off] == 'x')
		return;
	if (err)
		graph[off] = 'x';
	else {
		if (dpopts->bsim715_2ndpass)
			graph[off] = '.';
		else
			graph[off] = '-';
	}
}

/** Tries to determine size of input file */
void input_length()
{
	struct STAT64 stbuf;
	progress->estxfer = opts->maxxfer;
	if (opts->reverse) {
		if (opts->init_ipos)
			fstate->ilen = opts->init_ipos;
		else
			fstate->ilen = opts->maxxfer;
	} else
		fstate->ilen = opts->init_ipos + opts->maxxfer;
	if (progress->estxfer)
		preparegraph();
	if (fstate->i_chr)
		return;
	if (FSTAT64(fstate->ides, &stbuf))
		return;
	if (S_ISLNK(stbuf.st_mode))
		return;
	if (S_ISCHR(stbuf.st_mode)) {
		fstate->i_chr = 1;
		return;
	}
	if (S_ISBLK(stbuf.st_mode)) {
		/* Do magic to figure size of block dev */
		loff_t p = lseek64(fstate->ides, 0, SEEK_CUR);
		if (p == -1)
			return;
		fstate->ilen = lseek64(fstate->ides, 0, SEEK_END) /* + 1 */;
		lseek64(fstate->ides, p, SEEK_SET);
	} else {
		loff_t diff;
		fstate->ilen = stbuf.st_size;
		if (!fstate->ilen)
			return;
		diff = fstate->ilen - stbuf.st_blocks*512;
		if (diff >= 4096 && (float)diff/fstate->ilen > 0.05 && !opts->quiet)
		       fplog(stderr, INFO, "%s is sparse (%i%%) %s\n", opts->iname, (int)(100.0*diff/fstate->ilen), (opts->sparse? "": ", consider -a"));
	}
	if (!fstate->ilen)
		return;
	if (!opts->reverse)
		progress->estxfer = fstate->ilen - opts->init_ipos;
	else
		progress->estxfer = opts->init_ipos;
	if (opts->maxxfer && progress->estxfer > opts->maxxfer)
		progress->estxfer = opts->maxxfer;
	if (progress->estxfer < 0)
		progress->estxfer = 0;
	if (!opts->quiet)
		fplog(stderr, INFO, "expect to copy %skiB from %s\n",
			fmt_kiB(progress->estxfer), opts->iname);
	if (!graph)
		preparegraph();
}

int output_length()
{
	struct STAT64 stbuf;
	if (fstate->o_chr)
		return -1;
	if (FSTAT64(fstate->odes, &stbuf))
		return -1;
	if (S_ISLNK(stbuf.st_mode)) {
		// TODO: Use readlink and follow?
		fstate->o_lnk = 1;
		return -1;
	}
	if (S_ISCHR(stbuf.st_mode)) {
		fstate->o_chr = 1;
		return -1;
	}
	if (S_ISBLK(stbuf.st_mode)) {
		/* Do magic to figure size of block dev */
		loff_t p = lseek64(fstate->odes, 0, SEEK_CUR);
		fstate->o_blk = 1;
		if (p == -1)
			return -1;
		fstate->olen = lseek64(fstate->odes, 0, SEEK_END) + 1;
		lseek64(fstate->odes, p, SEEK_SET);
	} else {
		loff_t diff;
		fstate->olen = stbuf.st_size;
		if (!fstate->olen)
			return -1;
		diff = fstate->olen - stbuf.st_blocks*512;
		if (diff >= 4096 && (float)diff/fstate->ilen > 0.05 && !opts->quiet)
		       fplog(stderr, INFO, "%s is sparse (%i%%) %s\n", opts->oname, (int)(100.0*diff/fstate->olen), (opts->sparse? "": ", consider -a"));
	}
	if (!fstate->olen)
		return -1;
	if (!opts->reverse) {
		loff_t newmax = fstate->olen - opts->init_opos;
		if (newmax < 0) {
			fplog(stderr, FATAL, "output position is beyond end of file but -M specified!\n");
			cleanup();
			exit(19);
		}			
		if (!opts->maxxfer || opts->maxxfer > newmax) {
			opts->maxxfer = newmax;
			if (!opts->quiet)
				fplog(stderr, INFO, "limit max xfer to %skiB\n",
					fmt_kiB(opts->maxxfer));
		}
	} else if (opts->init_opos > fstate->olen) {
		fplog(stderr, WARN, "change output position %skiB to endpos %skiB due to -M\n",
			fmt_kiB(opts->init_opos), fmt_kiB(fstate->olen));
		opts->init_opos = fstate->olen;
	}
	return 0;
}


static void sparse_output_warn()
{
	struct STAT64 stbuf;
	loff_t eff_opos;
	if (fstate->o_chr)
		return;
	if (FSTAT64(fstate->odes, &stbuf))
		return;
	if (S_ISCHR(stbuf.st_mode)) {
		fstate->o_chr = 1;
		return;
	}
	if (S_ISBLK(stbuf.st_mode)) {
		if (opts->sparse || !opts->nosparse)
			fplog(stderr, WARN, "%s is a block device; -a not recommended; -A recommended\n", opts->oname);
		return;
	}
	eff_opos = (opts->init_opos == (loff_t)-INT_MAX? opts->init_ipos: opts->init_opos);
	if (opts->sparse && (eff_opos < stbuf.st_size))
		fplog(stderr, WARN, "write into %s (@%sk/%sk): sparse not recommended\n", 
				opts->oname, fmt_kiB(eff_opos), fmt_kiB(stbuf.st_size));
}

#if defined(HAVE_FALLOCATE64) || defined(HAVE_LIBFALLOCATE)

#ifdef USE_LIBDL
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
	struct STAT64 stbuf;
	loff_t to_falloc, alloced;
	int rc = 0;
	if (!progress->estxfer)
		return;
	if (FSTAT64(fd, &stbuf))
		return;
	if (!S_ISREG(stbuf.st_mode))
		return;
	alloced = stbuf.st_blocks*512 - opts->init_opos;
	to_falloc = progress->estxfer - (alloced < 0 ? 0 : alloced);
	if (to_falloc <= 0)
		return;
#ifdef USE_LIBDL
	typedef int (*_l_f_t) (int fd, int mode, __off64_t start, __off64_t len);
	//int (*_linux_fallocate64)(int fd, int mode, __off64_t start, __off64_t len);
	_l_f_t _linux_fallocate64 = (_l_f_t)load_libfallocate();
	if (_linux_fallocate64)
		rc = _linux_fallocate64(fd, FALLOC_FL_KEEP_SIZE,
				opts->init_opos, to_falloc);
#ifdef HAVE_FALLOCATE64
	else
		rc = fallocate64(fd, 1, opts->init_opos, to_falloc);
#endif
#elif defined(HAVE_LIBFALLOCATE)
	rc = linux_fallocate64(fd, FALLOC_FL_KEEP_SIZE, 
			      opts->init_opos, to_falloc);
#else /* HAVE_FALLOCATE64 */
	rc = opts->fallocate64(fd, 1, opts->init_opos, to_falloc);
#endif
	if (rc)
	       fplog(stderr, WARN, "fallocate %s (%sk, %sk) failed: %s\n",
			       onm, fmt_kiB(opts->init_opos), fmt_kiB(to_falloc), strerror(errno));
}
#endif

float floatrate4  = 0.0;
float floatrate32 = 0.0;
void doprint(FILE* const file, const unsigned int bs, const clock_t cl, 
	     const float t1, const float t2, const int sync)
{
	float avgrate = (float)progress->xfer/t1;
	float currate = (float)(progress->xfer-progress->lxfer)/t2;
	const char *bold = BOLD, *norm = NORM;
	if (!floatrate4) {
		floatrate4  = currate;
		floatrate32 = currate;
	} else {
		floatrate4  = (floatrate4 * 3 + currate)/ 4;
		floatrate32 = (floatrate32*31 + currate)/32;
	}
	if (opts->nocol || (file != stderr && file != stdout)) {
		bold = ""; norm = "";
	}
	fprintf(file, DDR_INFO "ipos:%sk, opos:%sk, xferd:%sk\n",
		fmt_int(10, 1, 1024, fstate->ipos, bold, norm, 1),
		fmt_int(10, 1, 1024, fstate->opos, bold, norm, 1),
		fmt_int(10, 1, 1024, progress->xfer, bold, norm, 1));
	fprintf(file, "             %s  %s  errs:%7i, errxfer:%sk, succxfer:%sk\n",
		(opts->reverse? "-": " "), (bs==opts->hardbs? "*": " "), fstate->nrerr, 
		fmt_int(10, 1, 1024, progress->fxfer, bold, norm, 1),
		fmt_int(10, 1, 1024, progress->sxfer, bold, norm, 1));
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
	if (progress->estxfer && avgrate > 0) {
		int sec;
		if (in_report)
			sec = 0.5 + t1;
		else
			sec = 0.5 + 2*(progress->estxfer-progress->xfer)/(avgrate+floatrate32);
		int hour = sec / 3600;
		int min = (sec % 3600) / 60;
		sec = sec % 60;
		updgraph(0);
		fprintf(file, "             %s %3i%%  %s: %2i:%02i:%02i \n",
			graph, (int)(100*progress->xfer/progress->estxfer), (in_report? "TOT": "ETA"), 
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
		int err = fsync(fstate->odes);
		if (err && (errno != EINVAL || !einvalwarn) &&!fstate->o_chr) {
			fplog(stderr, WARN, "sync %s (%sskiB): %s!  \n",
			      opts->oname, fmt_kiB(fstate->ipos), strerror(errno));
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
		if (progress->estxfer)
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
		progress->lxfer = progress->xfer;
	}
}

static void savebb(loff_t block)
{
	FILE *bbfile;
	fplog(stderr, WARN, "Bad block reading %s: %s \n", 
			opts->iname, fmt_int(0, 0, 1, block, (opts->nocol? "": BOLD), (opts->nocol? "": NORM), 1));
	if (opts->bbname == NULL)
		return;
	bbfile = fopen(opts->bbname, "a");
	fprintf(bbfile, "%s\n", fmt_int(0, 0, 1, block, "", "", 0));
	fclose(bbfile);
}

void printreport()
{
	/* report */
	FILE *report = (!opts->quiet || fstate->nrerr)? stderr: 0;
	in_report = 1;
	if (report) {
		fplog(report, INFO, "Summary for %s -> %s", opts->iname, opts->oname);
		LISTTYPE(ofile_t) *of;
		LISTFOREACH(ofiles, of)
			fplog(report, NOHDR, "; %s", LISTDATA(of).name);
		if (logfd > 0)
			fprintf(logfd, ":\n");
		fprintf(report, "\n");
		printstatus(report, logfd, 0, 1);
		if (opts->avoidwrite) 
			fplog(report, INFO, "Avoided %skiB of writes (performed %skiB)\n", 
				fmt_kiB(progress->axfer), fmt_kiB(progress->sxfer-progress->axfer));
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


/** Copy xattrs */
int copyxattr(const char* inm, const char* onm)
#ifdef HAVE_ATTR_XATTR_H
{
	char *attrs = NULL;
	ssize_t aln = listxattr(inm, NULL, 0);
	int copied = 0;
	if (aln <= 0)
		return 0;
	attrs = (char*)malloc(aln);
	if (!attrs) {
		fplog(stderr, WARN, "Can't allocate buffer of len %z for attr names\n", aln);
		return -1;
	}
	aln = listxattr(inm, attrs, aln);
	if (aln <= 0) {
		fplog(stderr, WARN, "Could not read attr list: %s\n", strerror(errno));
		free(attrs);
		return -1;
	}
	int offs;
	unsigned char* extrabuf = fstate->buf;
	int ebufall = 0;
	for (offs = 0; offs < aln; offs += 1+strlen(attrs+offs)) {
		ssize_t itln = getxattr(inm, attrs+offs, NULL, 0);
		if (ebufall && itln > ebufall) {
			extrabuf = (unsigned char*)realloc(extrabuf, itln);
			ebufall = itln;
		} else if (itln > (ssize_t)opts->softbs) {
			extrabuf = (unsigned char*)malloc(itln);
			ebufall = itln;
		}
		itln = getxattr(inm, attrs+offs, extrabuf, itln);
		if (itln <= 0) {
			fplog(stderr, WARN, "Could not read attr %s: %s\n", attrs+offs, strerror(errno));
			continue;
		}
		if (setxattr(onm, attrs+offs, extrabuf, itln, 0))
			fplog(stderr, WARN, "Could not write attr %s: %s\n", attrs+offs, strerror(errno));
		if (opts->verbose)
			fplog(stderr, INFO, "Copied attr %s (%i bytes)\n", attrs+offs, itln);
		++copied;
	}
	if (ebufall)
		free(extrabuf);
	free(attrs);
	return copied;
}
#else
{
	return 0;
}
#endif

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
	struct STAT64 st;
	loff_t maxopos = fstate->opos;
	if (opts->init_opos > fstate->opos)
		maxopos = opts->init_opos;
	STAT64(onm, &st);
	if (!S_ISREG(st.st_mode))
		return 0;
	if (st.st_size < maxopos || opts->trunclast)
		return truncate(onm, maxopos);
	else 
		return 0;		
}


void remove_and_trim(const char* onm)
{
	int err = unlink(onm);
	if (err)
		fplog(stderr, WARN, "remove(%s) failed: %s\n",
			onm, strerror(errno));
#ifdef FITRIM
	loff_t trimmed = fstrim(onm, opts->quiet);
	if (trimmed < 0) 
		fplog(stderr, WARN, "fstrim %s failed: %s%s\n", 
			onm, strerror(-trimmed), (-trimmed == EPERM? " (have root?)": ""));
	else
		fplog(stderr, INFO, "Trimmed %skiB \n", 
				fmt_int(0, 0, 1024, trimmed, (opts->nocol? "": BOLD), (opts->nocol? "": NORM), 1));
#endif
}

int sync_close(int fd, const char* nm, char chr)
{
	int rc, err = 0;
	if (fd != -1) {
		/* Make sure, the output file is expanded to the last (first) position
	 	 * FIXME: 0 byte writes do NOT expand file -- mayexpandfile() will
		 * take care of that. */
		if (!opts->avoidwrite) 
			rc = pwrite(fd, fstate->buf, 0, fstate->opos);
		rc = fsync(fd);
		if (rc && !chr) {
			fplog(stderr, WARN, "fsync %s (%skiB): %s!\n",
			      nm, fmt_kiB(fstate->opos), strerror(errno));
			++err;
			errno = 0;
		}
		rc = close(fd); 
		if (rc) {
			fplog(stderr, WARN, "close %s (%skiB): %s!\n",
			      nm, fmt_kiB(fstate->opos), strerror(errno));
			++err;
		}
		if (opts->sparse) {
			rc = mayexpandfile(nm);
			if (rc)
				fplog(stderr, WARN, "seek %s (%skiB): %s!\n",
				      nm, fmt_kiB(fstate->opos), strerror(errno));
		} else if (opts->trunclast && !opts->reverse) {
			rc = truncate(nm, fstate->opos);
			if (rc)
				fplog(stderr, WARN, "could not truncate %s to %skiB: %s!\n",
					nm, fmt_kiB(fstate->opos), strerror(errno));
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


ssize_t writeblock(int towrite);
static void advancepos(const ssize_t rd, const ssize_t wr, const ssize_t rwr);

int cleanup()
{
	int rc, errs = 0;
	if (!opts->dosplice && !dpopts->bsim715) {
		/* EOF notifiction */
		int fbytes = writeblock(0);
		if (fbytes >= 0)
			advancepos(0, fbytes, fbytes);
		else
			errs++;
		/* And finalize */
		call_plugins_close();
	}
	errs += sync_close(fstate->odes, opts->oname, fstate->o_chr);
	if (fstate->ides != -1) {
		rc = close(fstate->ides);
		if (rc) {
			fplog(stderr, WARN, "close %s (%skiB): %s!\n",
			      opts->iname, fmt_kiB(fstate->ipos), strerror(errno));
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
	ZFREE(fstate->origbuf2);
	ZFREE(graph);
	if (opts->preserve) {
		copyxattr(opts->iname, opts->oname);
		copytimes(opts->iname, opts->oname);
	}
	if (opts->rmvtrim)
		remove_and_trim(opts->oname);
	LISTFOREACH(ofiles, of) {
		if (opts->preserve) {
			copyxattr(opts->iname, LISTDATA(of).name);
			copytimes(opts->iname, LISTDATA(of).name);
		}
		if (opts->rmvtrim)
			remove_and_trim(LISTDATA(of).name);
	}
	ZFREE(fstate->origbuf);
	if (dpstate->prng_state2) {
		frandom_release(dpstate->prng_state2);
		dpstate->prng_state2 = 0;
	}
	if (dpstate->prng_state) {
		frandom_release(dpstate->prng_state);
		dpstate->prng_state = 0;
	}
	LISTTREEDEL(ofiles, ofile_t);
	LISTTYPE(charp) *onl;
	LISTFOREACH(freenames, onl) {
		free(LISTDATA(onl));
		LISTDATA(onl) = 0;
	}
	LISTTREEDEL(freenames, charp);
#if USE_LIBDL
	if (libfalloc)
		dlclose(libfalloc);
	if (plugins_loaded)
		unload_plugins();
#endif
	return errs;
}

ssize_t fill_rand(void *bf, size_t ln)
{
	unsigned int i;
	int* rbuf = (int*)bf;
	for (i = 0; i < ln/sizeof(int); ++i)
		rbuf[i] = rand();
	return ln;
}

/** is the block zero ? */
static ssize_t blockiszero(const unsigned char* blk, const size_t ln)
{
	if (opts->i_repeat && repeat->i_rep_zero)
		return repeat->i_rep_zero;
	if (!ln || *blk) 
		repeat->i_rep_zero = 0;
	else
		repeat->i_rep_zero = FIND_NONZERO_OPT(blk, ln);
	return repeat->i_rep_zero;
}

static inline ssize_t mypread(int fd, void* bf, size_t sz, loff_t off)
{
	if (opts->i_repeat) {
		if (repeat->i_rep_init)
			return sz;
		else
			repeat->i_rep_init = 1;
	}
	if (dpopts->prng_libc)
		return fill_rand(bf, sz);
	if (dpopts->prng_frnd) {
		if (!dpopts->bsim715_2ndpass)
			return frandom_bytes(dpstate->prng_state, (unsigned char*) bf, sz);
		else
			return frandom_bytes_inv(dpstate->prng_state, (unsigned char*) bf, sz);
	}
	if (fstate->i_chr) 
		return read(fd, bf, sz);
	else
		return pread64(fd, bf, sz, off);
}

static inline ssize_t mypwrite(int fd, void* bf, size_t sz, loff_t off)
{
	if (fstate->o_chr) {
		if (!opts->avoidnull)
			return write(fd, bf, sz);
		else {
			progress->axfer += sz;
			return sz;
		}
	} else {
		if (opts->avoidwrite) {
			ssize_t ln = pread64(fd, fstate->buf2, sz, off);
			if (ln < (ssize_t)sz)
				return pwrite64(fd, bf, sz, off);
			if (memcmp(bf, fstate->buf2, ln))
				return pwrite64(fd, bf, sz, off);
			else {
				progress->axfer += ln;
				return ln;
			}
		} else
			return pwrite64(fd, bf, sz, off);
	}
}


ssize_t readblock(const int toread)
{
	ssize_t err, rd = 0;
	//errno = 0; /* should not be necessary */
	do {
		rd += (err = mypread(fstate->ides, fstate->buf+rd, toread-rd, fstate->ipos+rd-opts->reverse*toread));
		if (err == -1) 
			rd++;
	} while ((err == -1 && (errno == EINTR || errno == EAGAIN))
		  || (rd < toread && err > 0 && errno == 0));
	//if (rd < toread) memset (fstate->buf+rd, 0, toread-rd);
	return (/*err == -1? err:*/ rd);
}

ssize_t writeblock(int towrite)
{
	ssize_t err, wr = 0;
	int lasterr = 0;
	int eof = towrite? 0: 1;
	unsigned char* wbuf = call_plugins_block(fstate->buf, &towrite, eof, &fstate->opos);
	if (!wbuf || !towrite)
		return towrite;
	//errno = 0; /* should not be necessary */
	do {
		wr += (err = mypwrite(fstate->odes, wbuf+wr, towrite-wr, fstate->opos+wr-opts->reverse*towrite));
		if (err == -1) 
			wr++;
	} while ((err == -1 && (errno == EINTR || errno == EAGAIN))
		  || (wr < towrite && err > 0 && errno == 0));
	if (wr < towrite && err != 0) {
		/* Write error: handle ? .. */
		lasterr = errno;
		fplog(stderr, (opts->abwrerr? FATAL: WARN),
				"write %s (%skiB): %s\n",
	      			opts->oname, fmt_kiB(fstate->opos), strerror(errno));
		if (opts->abwrerr) 
			exit_report(21);
		fstate->nrerr++;
	}
	int oldeno = errno;
	char oldochr = fstate->o_chr;
	LISTTYPE(ofile_t) *of;
	LISTFOREACH(ofiles, of) {
		ssize_t e2, w2 = 0;
		ofile_t *oft = &(LISTDATA(of));
		fstate->o_chr = oft->cdev;
		do {
			w2 += (e2 = mypwrite(oft->fd, wbuf+w2, towrite-w2, fstate->opos+w2-opts->reverse*towrite));
			if (e2 == -1) 
				w2++;
		} while ((e2 == -1 && (errno == EINTR || errno == EAGAIN))
			  || (w2 < towrite && e2 > 0 && errno == 0));
		if (w2 < towrite && e2 != 0) 
			fplog(stderr, WARN, "2ndary write %s (%skiB): %s\n",
			      oft->name, fmt_kiB(fstate->opos), strerror(errno));
	}
	fstate->o_chr = oldochr;
	errno = oldeno;	
	return (lasterr? -lasterr: wr);
}

int blockxfer(const loff_t max, const int bs)
{
	int block = bs;
	/* Don't progress->xfer more bytes than our limit */
	if (max && max-progress->xfer < bs)
		block = max-progress->xfer;
	if (opts->reverse) {
		/* Can't go beyond the beginning of the file */
		if (block > fstate->ipos)
			block = fstate->ipos;
		if (block > fstate->opos)
			block = fstate->opos;
	}
	/* If we write the first block and it's a full block, do alignment ... */
	if (block == bs && !progress->xfer && ((fstate->opos % bs && !fstate->o_chr) || (fstate->ipos % bs && !fstate->i_chr))) {
		/* Write alignment is more important except if fstate->o_chr == 1 */
		int off = fstate->o_chr? fstate->ipos % bs: fstate->opos % bs;
		int aligned = opts->reverse? off: bs-off;
		if (!max_align || !(aligned % max_align))
			block = aligned;
	}
	return block;
}

void exitfatalerr(const int eno)
{
	if (eno == ESPIPE || eno == EPERM || eno == ENXIO || eno == ENODEV) {
		fplog(stderr, FATAL, "%s (%skiB): %s! \n", 
		      opts->iname, fmt_kiB(fstate->ipos), strerror(eno));
		fplog(stderr, NOHDR, "dd_rescue: Last error fatal! Exiting ... \n");
		exit_report(20);
	}
}

/* Update positions after successful copy, rd = progress, wr = really written */
static void advancepos(const ssize_t rd, const ssize_t wr, const ssize_t rwr)
{
	progress->sxfer += rwr; progress->xfer += rd;
	if (opts->reverse) { 
		fstate->ipos -= rd; fstate->opos -= wr; 
	} else { 
		fstate->ipos += rd; fstate->opos += wr; 
	}
}

static int is_writeerr_fatal(int err)
{
	return (err == ENOSPC || err == EROFS
#ifdef EDQUOT
               || err == EDQUOT
#endif
               || (err == EFBIG && !opts->reverse));
}

int weno;

/* Do write, update positions ... 
 * Returns number of successfully written bytes. */
ssize_t dowrite(const ssize_t rd)
{
	int err = 0;
	int fatal = 0;
	ssize_t wr = 0;
	weno = 0;
	errno = 0;
	err = ((wr = writeblock(rd)) < 0 ? -wr: 0);
	weno = errno;

	if (err && is_writeerr_fatal(weno))
		++fatal;
	if (err) {
		fplog(stderr, WARN, "assumption rd(%i) == wr(%i) failed! \n", rd, wr);
		fplog(stderr, (fatal? FATAL: WARN),
			"write %s (%skiB): %s!\n", 
			opts->oname, fmt_kiB(fstate->opos+wr), strerror(weno));
		errno = 0;
		/* FIXME: This breaks for opts->reverse direction */
		if (!opts->reverse)
			advancepos(wr, wr, wr);
		else
			return 0;
	} else
		advancepos(rd, wr, wr);
	return wr;
}

/* Write rd-sized block at fstate->buf; if opts->sparse is set, check if at least half of the
 * block is empty and if so, move over the opts->sparse pieces ... */
ssize_t dowrite_sparse(const ssize_t rd)
{
	/* Simple case: opts->sparse not set => just write */
	if (!opts->sparse)
		return dowrite(rd);
	ssize_t zln = blockiszero(fstate->buf, rd);
	/* Also simple: Whole block is empty, so just move on */
	if (zln >= rd) {
		advancepos(rd, rd, 0);
		weno = 0;
		return 0;
	}
	/* Block is smaller than 2*opts->hardbs and not completely zero, so don't bother optimizing ... */
	if (rd < 2*(ssize_t)opts->hardbs)
		return dowrite(rd);
	/* Check both halves -- aligned to opts->hardbs boundaries */
	int mid = rd/2;
	mid -= mid%opts->hardbs;
	zln -= zln%opts->hardbs;
	/* First half is empty */
	if (zln >= mid) {
		unsigned char* oldbuf = fstate->buf;
		advancepos(zln, zln, 0);
		fstate->buf += zln;
		ssize_t wr = dowrite(rd-zln);
		fstate->buf = oldbuf;
		return wr;
	}
	/* Check second half */
	ssize_t zln2 = blockiszero(fstate->buf+mid, rd-mid);
	if (zln2 < rd-mid)
		return dowrite(rd);
	else {
		ssize_t wr = dowrite(mid);
		//advancepos(mid, wr);
		if (wr != mid) 
			return wr;
		advancepos(rd-mid, wr, 0);
		return wr;
	}
}

/* Do write with retry if rd > opts->hardbs, update positions ... 
 * Returns 0 on success, -1 on fatal error, 1 on normal error. */
int dowrite_retry(const ssize_t rd)
{
	int errs = 0;
	ssize_t wr = dowrite_sparse(rd);
	if (wr == rd || weno == 0)
		return 0;
	if ((rd <= (ssize_t)opts->hardbs) || (weno != ENOSPC && weno != EFBIG)) {
		/* No retry, move on */
		advancepos(rd-wr, rd-wr, 0);
		return is_writeerr_fatal(weno)? -1: 1;
	} else {
		ssize_t rwr = wr;
		unsigned char* oldbuf = fstate->buf; 
		int adv = 1;
		fstate->buf += wr;
		fplog(stderr, INFO, "retrying writes with smaller blocks \n");
		if (opts->reverse) {
			fstate->buf = oldbuf+rd-opts->hardbs;
			adv = -1;
		}
		while (rwr < rd) {
			ssize_t towr = ((ssize_t)opts->hardbs > rd-rwr)? rd-rwr: opts->hardbs;
			ssize_t wr2 = dowrite(towr);
			if (is_writeerr_fatal(weno)) {
				fstate->buf = oldbuf;
				return -1;
			}
			if (wr2 < towr) {
				advancepos(towr-wr2, towr-wr2, 0);
				++errs;
			}
			rwr += towr; fstate->buf += towr*adv;
		}
		fstate->buf = oldbuf;
	}
	return errs;
}

static int partialwrite(const ssize_t rd)
{
	/* But first: write available data and advance (optimization) */
	if (rd > 0 && !opts->reverse) 
		return dowrite_retry(rd);
	return 0;	
}

int copyfile_hardbs(const loff_t max)
{
	ssize_t toread;
	int errs = 0; errno = 0;
#if 0	
	fprintf(stderr, "%s%s%s%s copyfile (fstate->ipos=%.1fk, progress->xfer=%.1fk, max=%.1fk, bs=%i)                         ##\n%s%s%s%s",
		up, up, up, up,
		(double)fstate->ipos/1024, (double)progress->xfer/1024, (double)max/1024, opts->hardbs,
		down, down, down, down);
#endif
	while ((toread = blockxfer(max, opts->hardbs)) > 0 && !interrupted) { 
		int eno;
		ssize_t rd = readblock(toread);
		eno = errno;

		/* EOF */
		if (rd == 0 && !eno) {
			if (!opts->quiet)
				fplog(stderr, INFO, "read %s (%skiB): EOF\n", 
				      opts->iname, fmt_kiB(fstate->ipos));
			return errs;
		}
		/* READ ERROR */
		if (rd < toread/* && errno*/) {
			if (eno) {
				++errs;
				/* Read error occurred: Print warning */
				printstatus(stderr, logfd, opts->hardbs, 1);
			}
			/* Some errnos are fatal */
			exitfatalerr(eno);
			/* Non fatal error */
			/* This is the case, where we were not called from copyfile_softbs and thus have to assume harmless EOF */
			if (/*opts->softbs <= opts->hardbs &&*/ eno == 0) {
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
			fstate->nrerr++; 
			fplog(stderr, WARN, "read %s (%skiB): %s!\n", 
			      opts->iname, fmt_kiB(fstate->ipos), strerror(eno));
		
			errno = 0;
			if (opts->nosparse || 
			    (rd > 0 && (!opts->sparse || blockiszero(fstate->buf, rd) < rd))) {
				ssize_t wr = 0;
				memset(fstate->buf+rd, 0, toread-rd);
				errs += ((wr = writeblock(toread)) < 0? -wr: 0);
				eno = errno;
				if (wr <= 0 && (eno == ENOSPC 
					   || (eno == EFBIG && !opts->reverse))) 
					return errs;
				if (toread != wr) {
					fplog(stderr, WARN, "assumption toread(%i) == wr(%i) failed! \n", toread, wr);	
					/*
					fplog(stderr, WARN, "%s (%skiB): %s!\n", 
					      opts->oname, fmt_kiB(fstate->opos), strerror(eno));
					fprintf(stderr, "%s%s%s%s", down, down, down, down);
				 	*/
				}
			}
			savebb(fstate->ipos/opts->hardbs);
			updgraph(1);
			progress->fxfer += toread; progress->xfer += toread;
			if (opts->reverse) { 
				fstate->ipos -= toread; fstate->opos -= toread; 
			} else { 
				fstate->ipos += toread; fstate->opos += toread; 
			}
			/* exit if too many errs */
			if (opts->maxerr && fstate->nrerr >= opts->maxerr) {
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

		if (opts->syncfreq && !(progress->xfer % (opts->syncfreq*opts->softbs)))
			printstatus((opts->quiet? 0: stderr), 0, opts->hardbs, 1);
		else if (!opts->quiet && !(progress->xfer % (8*opts->softbs)))
			printstatus(stderr, 0, opts->hardbs, 0);
	} /* remain */
	return errs;
}

int copyfile_softbs(const loff_t max)
{
	ssize_t toread;
	int errs = 0, rc; int eno;
	errno = 0;
#if 0	
	fprintf(stderr, "%s%s%s%s copyfile (fstate->ipos=%.1fk, progress->xfer=%.1fk, max=%.1fk, bs=%i)                         ##\n%s%s%s%s",
		up, up, up, up,
		(double)fstate->ipos/1024, (double)progress->xfer/1024, (double)max/1024, opts->softbs,
		down, down, down, down);
#endif
	/* expand file to AT LEAST the right length 
	 * FIXME: 0 byte writes do NOT expand file */
	if (!fstate->o_chr && !opts->avoidwrite) {
		rc = pwrite(fstate->odes, fstate->buf, 0, fstate->opos);
		if (rc)
			fplog(stderr, WARN, "extending file %s to %skiB failed\n",
			      opts->oname, fmt_kiB(fstate->opos));
	}
	while ((toread = blockxfer(max, opts->softbs)) > 0 && !interrupted) {
		int err;
		ssize_t rd = readblock(toread);
		eno = errno;

		/* EOF */
		if (rd == 0 && !eno) {
			if (!opts->quiet)
				fplog(stderr, INFO, "read %s (%skiB): EOF\n", 
				      opts->iname, fmt_kiB(fstate->ipos));
			return errs;
		}
		/* READ ERROR or short read */
		if (rd < toread/* && errno*/) {
			int ret;
			loff_t new_max, old_xfer;
			if (eno) {
				++errs;
				/* Read error occurred: Print warning */
				printstatus(stderr, logfd, opts->softbs, 1);
			}
			/* Some errnos are fatal */
			exitfatalerr(eno);
			/* Non fatal error */
			new_max = progress->xfer + toread;
			/* Error with large blocks: Try small ones ... */
			if (opts->verbose & eno) {
				/*
				fprintf(stderr, DDR_INFO "problems at ipos %.1fk: %s \n                 fall back to smaller blocksize \n%s%s%s%s",
				        (double)fstate->ipos/1024, strerror(eno), down, down, down, down);
				 */
				fprintf(stderr, DDR_INFO "problems at ipos %skiB: %s \n               fall back to smaller blocksize \n",
				        fmt_kiB(fstate->ipos), strerror(eno));
				scrollup = 0;
				printstatus(stderr, logfd, opts->hardbs, 1);
			}
			/* But first: write available data and advance (optimization) */
			if ((ret = partialwrite(rd)) < 0)
				return ret;
			else
				errs += ret;
			old_xfer = progress->xfer;
			errs += (err = copyfile_hardbs(new_max));
			/* EOF */
			if (!err && old_xfer == progress->xfer)
				return errs;
			/*
			if (opts->reverse && rd) {
				fstate->ipos -= rd; fstate->opos -= rd;
				progress->xfer += rd; progress->sxfer += wr;
			}
			*/	
			/* Stay with small blocks, until we could read two whole 
			   large ones without errors */
			new_max = progress->xfer;
			while (err && (!max || (max-progress->xfer > 0)) && ((!opts->reverse) || (fstate->ipos > 0 && fstate->opos > 0))) {
				new_max += 2*opts->softbs; old_xfer = progress->xfer;
				if (max && new_max > max) 
					new_max = max;
				errs += (err = copyfile_hardbs(new_max));
			}
			errno = 0;
			/* EOF ? */      
			if (!err && progress->xfer == old_xfer)
				return errs;
			if (opts->verbose) {
				fprintf(stderr, DDR_INFO "ipos %skiB promote to large bs again! \n",
					fmt_kiB(fstate->ipos));
				scrollup = 0;
			}
		} else {
	      		err = dowrite_retry(rd);
			if (err < 0)
				return -err;
			else
				errs += err;
		} /* errno */

		if (opts->syncfreq && !(progress->xfer % (opts->syncfreq*opts->softbs)))
			printstatus((opts->quiet? 0: stderr), 0, opts->softbs, 1);
		else if (!opts->quiet && !(progress->xfer % (16*opts->softbs)))
			printstatus(stderr, 0, opts->softbs, 0);
	} /* remain */
	return errs;
}

#ifdef HAVE_SPLICE
int copyfile_splice(const loff_t max)
{
	ssize_t toread;
	int fd_pipe[2];
	LISTTYPE(ofile_t) *oft;
	if (pipe(fd_pipe) < 0)
		return copyfile_softbs(max);
	while ((toread	= blockxfer(max, opts->softbs) && !interrupted) > 0) {
		loff_t old_ipos = fstate->ipos, old_opos = fstate->opos;
		ssize_t rd = splice(fstate->ides, &fstate->ipos, fd_pipe[1], NULL, toread,
					SPLICE_F_MOVE | SPLICE_F_MORE);
		if (rd < 0) {
			if (!opts->quiet)
				fplog(stderr, INFO, "%s (%skiB): fall back to userspace copy\n",
				      opts->iname, fmt_kiB(fstate->ipos));
			close(fd_pipe[0]); close(fd_pipe[1]);
			return copyfile_softbs(max);
		}
		if (rd == 0) {
			if (!opts->quiet)
				fplog(stderr, INFO, "read %s (%skiB): EOF (splice)\n",
				      opts->iname, fmt_kiB(fstate->ipos));
			break;
		}
		while (rd) {
			ssize_t wr = splice(fd_pipe[0], NULL, fstate->odes, &fstate->opos, rd,
					SPLICE_F_MOVE | SPLICE_F_MORE);
			if (wr < 0) {
				fplog(stderr, FATAL, "write %s (%skiB): %s (splice)\n",
					opts->oname, fmt_kiB(fstate->opos), strerror(errno));

				close(fd_pipe[0]); close(fd_pipe[1]);
				exit_report(23);
			}
			rd -= wr; progress->xfer += wr; progress->sxfer += wr;
		}
		loff_t new_ipos = fstate->ipos, new_opos = fstate->opos;
		LISTFOREACH(ofiles, oft) {
			fstate->ipos = old_ipos; fstate->opos = old_opos;
			rd = splice(fstate->ides, &fstate->ipos, fd_pipe[1], NULL, toread,
					SPLICE_F_MOVE | SPLICE_F_MORE);
			/* Simplify error handling, it worked before ... */
			if (rd <= 0) {
				fplog(stderr, WARN, "Confused: splice() read failed unexpectedly: %s\n",
					strerror(errno));
				/* We should abort here .... */
				fstate->ipos = new_ipos; fstate->opos = new_opos;
				continue;
			}
			while (rd) {
				ssize_t wr = splice(fd_pipe[0], NULL, LISTDATA(oft).fd, &fstate->opos, rd,
						SPLICE_F_MOVE | SPLICE_F_MORE);
				if (wr < 0) {	
					fplog(stderr, WARN, "Confused: splice() write failed unexpectedly: %s\n",
						strerror(errno));
					/* We should abort here .... */
					fstate->ipos = new_ipos; fstate->opos = new_opos;
					continue;
				}
			rd -= wr;
			}
		}
		if (fstate->ipos != new_ipos || fstate->opos != new_opos) {
			fplog(stderr, WARN, "Confused: splice progress inconsistent: %zi %zi %zi %zi\n",
				fstate->ipos, new_ipos, fstate->opos, new_opos);
			fstate->ipos = new_ipos; fstate->opos = new_opos;
		}	
		advancepos(0, 0, 0);
		if (opts->syncfreq && !(progress->xfer % (opts->syncfreq*opts->softbs)))
			printstatus((opts->quiet? 0: stderr), 0, opts->softbs, 1);
		else if (!opts->quiet && !(progress->xfer % (16*opts->softbs)))
			printstatus(stderr, 0, opts->softbs, 0);
	}
	close(fd_pipe[0]); close(fd_pipe[1]);
	return 0;
}
#endif

int tripleoverwrite(const loff_t max)
{
	int ret = 0;
	loff_t orig_opos = fstate->opos;
	void* prng_state3 = frandom_stdup(dpstate->prng_state);
	clock_t orig_startclock = startclock;
	struct timeval orig_starttime;
	LISTTYPE(ofile_t) *of;
	memcpy(&orig_starttime, &starttime, sizeof(starttime));
	fprintf(stderr, "%s%s%s%s" DDR_INFO "Triple overwrite (BSI M7.15): first pass ... (frandom)      \n\n\n\n\n", up, up, up, up);
	ret += copyfile_softbs(max);
	fprintf(stderr, "syncing ... \n%s", up);
	ret += fsync(fstate->odes);
	LISTFOREACH(ofiles, of)
		fsync(LISTDATA(of).fd);
	/* TODO: better error handling */
	frandom_release(dpstate->prng_state);
	dpstate->prng_state = prng_state3; prng_state3 = 0;
	dpopts->bsim715_2ndpass = 1;
	if (!dpopts->bsim715_2) {
		fstate->opos = orig_opos; progress->xfer = 0; fstate->ipos = 0;
		startclock = clock(); gettimeofday(&starttime, NULL);
		fprintf(stderr, DDR_INFO "Triple overwrite (BSI M7.15): second pass ... (frandom_inv)\n\n\n\n\n");
		ret += copyfile_softbs(max);
		fprintf(stderr, "syncing ... \n%s", up);
		ret += fsync(fstate->odes);
		LISTFOREACH(ofiles, of)
			fsync(LISTDATA(of).fd);
		/* TODO: better error handling */
		dpopts->bsim715_2ndpass = 0;
		if (dpopts->bsim715_4) {
			frandom_bytes(dpstate->prng_state, fstate->buf, 16);
			fprintf(stderr, DDR_INFO "Triple overwrite (BSI M7.15): third pass ... (frandom) \n\n\n\n\n");
			fstate->opos = orig_opos; progress->xfer = 0; fstate->ipos = 0;
			startclock = clock(); gettimeofday(&starttime, NULL);
			ret += copyfile_softbs(max);
			fprintf(stderr, "syncing ... \n%s", up);
			ret += fsync(fstate->odes);
			LISTFOREACH(ofiles, of)
				fsync(LISTDATA(of).fd);
			dpopts->bsim715_2ndpass = 1;
			opts->iname = "FRND+invFRND+FRND2+ZERO";
		} else
			opts->iname = "FRND+invFRND+ZERO";
	} else
		opts->iname = "FRND+ZERO";
	fprintf(stderr, DDR_INFO "Triple overwrite (BSI M7.15): last pass ... (zeros) \n\n\n\n\n");
	frandom_release(dpstate->prng_state); dpstate->prng_state = 0;
	memset(fstate->buf, 0, opts->softbs); 
	opts->i_repeat = 1; repeat->i_rep_init = 1;
	fstate->opos = orig_opos; progress->xfer = 0; fstate->ipos = 0;
	startclock = clock(); gettimeofday(&starttime, NULL);
	ret += copyfile_softbs(max);
	startclock = orig_startclock;
	memcpy(&starttime, &orig_starttime, sizeof(starttime));
	progress->xfer = progress->sxfer;
	if (ret)
		fplog(stderr, WARN, "There were %i errors! %s may not be safely overwritten!\n", ret, opts->oname);
	//fprintf(stderr, "syncing ... \n%s", up);
	return ret;
}

static loff_t readint(const char* const ptr)
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
	return (loff_t)res;
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
	if (dpopts->prng_sfile) {
		int ln, fd = -1;
		unsigned char sbf[256];
		if (!strcmp(dpopts->prng_sfile, "-")) {
			fd = 0;
			if (opts->verbose)
				fplog(stderr, INFO, "reading random seed from <stdin> ...\n");
		} else
			fd = open(dpopts->prng_sfile, O_RDONLY);
		if (fd == -1) {
			fplog(stderr, FATAL, "Could not open \"%s\" for random seed!\n", dpopts->prng_sfile);
			/* ERROR */
			cleanup(); exit(28);
		}
		if (dpopts->prng_libc) {
			unsigned int* sval = (unsigned int*)sbf;
			ln = read(fd, sbf, 4);
			if (ln != 4) {
				fplog(stderr, FATAL, "failed to read 4 bytes from \"%s\"!\n", dpopts->prng_sfile);
				cleanup(); exit(29);
			}
			srand(*sval); rand();
		} else {
			ln = read(fd, sbf, 256);
			if (ln != 256) {
				fplog(stderr, FATAL, "failed to read 256 bytes from \"%s\"!\n", dpopts->prng_sfile);
				cleanup(); exit(29);
			}
			dpstate->prng_state = frandom_init(sbf);
		}
	} else {
		if (!dpopts->prng_seed)
			dpopts->prng_seed = frandom_getseedval();
		if (dpopts->prng_libc) {
			srand(dpopts->prng_seed); rand();
		} else
			dpstate->prng_state = frandom_init_lrand(dpopts->prng_seed);
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
#ifdef USE_LIBDL
	fprintf(stderr, "dl/libfallocate ");
#elif defined(HAVE_LIBFALLOCATE)
	fprintf(stderr, "libfallocate ");
#endif	
#if defined(HAVE_FALLOCATE64)
	fprintf(stderr, "fallocate ");
#endif
#ifdef HAVE_SPLICE
	fprintf(stderr, "splice ");
#endif
#ifdef FITRIM
	fprintf(stderr, "fitrim ");
#endif
#ifdef HAVE_ATTR_XATTR_H
	fprintf(stderr, "xattr ");
#endif
	fprintf(stderr, "%s", OPT_STR);
	fprintf(stderr, ")\n");
	fprintf(stderr, "dd_rescue is free software. It's protected by the terms of GNU GPL v2 or v3\n");
	fprintf(stderr, " (at your option).\n");
}


#ifdef HAVE_GETOPT_LONG
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
				{"rmvtrim", 0, NULL, 'u'}, {"plugins", 1, NULL, 'L'},
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


void printlonghelp()
{
	printversion();
	fprintf(stderr, "dd_rescue copies data from one file (or block device) to others.\n");
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
	fprintf(stderr, "         -t         truncate output file at start (def=no),\n");
	fprintf(stderr, "         -T         truncate output file at last pos (def=no),\n");
	fprintf(stderr, "         -u         undo writes by deleting outfile and issueing fstrim\n");
#ifdef O_DIRECT
	fprintf(stderr, "         -d/D       use O_DIRECT for input/output (def=no),\n");
#endif
#ifdef HAVE_SPLICE
	fprintf(stderr, "         -k         use efficient in-kernel zerocopy splice,\n");
#endif       	
#if defined(HAVE_FALLOCATE64) || defined(HAVE_LIBFALLOCATE)
	fprintf(stderr, "         -P         use fallocate to preallocate target space,\n");
#endif
#ifdef USE_LIBDL
	fprintf(stderr, "         -L plug1[=par1[:par2]][,plug2[,..]]    load plugins,\n");
#endif
	fprintf(stderr, "         -w         abort on Write errors (def=no),\n");
	fprintf(stderr, "         -W         read target block and avoid Writes if identical (def=no),\n");
	fprintf(stderr, "         -a         detect zero-filled blocks and write spArsely (def=no),\n");
	fprintf(stderr, "         -A         Always write blocks, zeroed if err (def=no),\n");
	fprintf(stderr, "         -i         interactive: ask before overwriting data (def=no),\n");
	fprintf(stderr, "         -f         force: skip some sanity checks (def=no),\n");
	fprintf(stderr, "         -p         preserve: preserve ownership, perms, times, attrs (def=no),\n");
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
	fprintf(stderr, " it does not normally abort or truncate the output.\n");
	fprintf(stderr, "It may also help with securly overwriting data.\n");
	fprintf(stderr, "Have a look a the man page for more details and long options.\n");
}

void shortusage()
{
	fplog(stderr, INFO, "USAGE: dd_rescue [options] infile outfile\n"
		"   or: dd_rescue [options] -z/Z/2/3/4 SEED[FILE] outfile\n"
		" Use dd_rescue -h or dd_rescue --help for more information\n"
		"  or consult the manpage dd_rescue(1).\n");
}

#define YESNO(flag) (flag? "yes": "no ")

void printinfo(FILE* const file)
{
	fplog(file, INFO, "about to transfer %s kiBytes from %s to %s\n",
	      fmt_kiB(opts->maxxfer), opts->iname, opts->oname);
	fplog(file, INFO, "blocksizes: soft %i, hard %i\n", opts->softbs, opts->hardbs);
	fplog(file, INFO, "starting positions: in %skiB, out %SkiB\n",
	      fmt_kiB(opts->init_ipos), fmt_kiB(opts->init_opos));
	fplog(file, INFO, "Logfile: %s, Maxerr: %li\n",
	      (opts->lname? opts->lname: "(none)"), opts->maxerr);
	fplog(file, INFO, "Reverse: %s, Trunc: %s, interactive: %s\n",
	      YESNO(opts->reverse), (opts->dotrunc? "yes": (opts->trunclast? "last": "no")), YESNO(opts->interact));
	fplog(file, INFO, "abort on Write errs: %s, spArse write: %s\n",
	      YESNO(opts->abwrerr), (opts->sparse? "yes": (opts->nosparse? "never": "if err")));
	fplog(file, INFO, "preserve: %s, splice: %s, avoidWrite: %s\n",
	      YESNO(opts->preserve), YESNO(opts->dosplice), YESNO(opts->avoidwrite));
	fplog(file, INFO, "fallocate: %s, Repeat: %s, O_DIRECT: %s/%s\n",
	      YESNO(opts->falloc), YESNO(opts->i_repeat), YESNO(opts->o_dir_in), YESNO(opts->o_dir_out));
	/*
	fplog(file, INFO, "opts->verbose: %s, opts->quiet: %s\n", 
	      YESNO(opts->verbose), YESNO(opts->quiet));
	*/
}

void breakhandler(int sig)
{
	int_by = sig;
	if (!interrupted++) {
		fplog(stderr, FATAL, "Caught signal %i \"%s\". Flush and exit after current block!\n",
		      sig, strsignal(sig));
	} else {
		fplog(stderr, FATAL, "Caught signal %i \"%s\". Flush and exit immediately!\n",
		      sig, strsignal(sig));
		printreport();
		cleanup();
		signal(sig, SIG_DFL);
		raise(sig);
	}
}

unsigned char* zalloc_aligned_buf(unsigned int bs, unsigned char**obuf)
{
	unsigned char *ptr;
#if defined (__DragonFly__) || defined(__NetBSD__) || defined(__BIONIC__)
	ptr = max_slack_pre%fstate->pagesize? 0: (unsigned char*)valloc(bs + max_slack_pre + max_slack_post);
#else
	void *mp;
	if (max_slack_pre%fstate->pagesize || posix_memalign(&mp, fstate->pagesize, bs + max_slack_pre + max_slack_post))
		ptr = 0;
	else
		ptr = (unsigned char*)mp;
#endif /* NetBSD */
	if (obuf) 
		*obuf = ptr;
	if (!ptr) {
		if (0 == max_slack_pre%fstate->pagesize)
			fplog(stderr, WARN, "allocation of aligned buffer failed -- use malloc\n");
		ptr = (unsigned char*)malloc(bs + fstate->pagesize + max_slack_pre + max_slack_post);
		if (!ptr) {
			fplog(stderr, FATAL, "allocation of buffer of size %li failed!\n", 
				bs+fstate->pagesize+max_slack_pre+max_slack_post);
			cleanup(); exit(18);
		}
		if (obuf)
			*obuf = ptr;
		ptr += max_slack_pre+fstate->pagesize-1;
		ptr -= (unsigned long)ptr % fstate->pagesize;
	} else
		ptr += max_slack_pre;
	memset(ptr-max_slack_pre, 0, bs+max_slack_pre+max_slack_post);
	return ptr;
}

/** Heuristic: strings starting with - or a digit are numbers, ev.thing else a ffstate->ilename. A pure "-" is a ffstate->ilename. */
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

#ifdef __BIONIC__
#define strdupa(str)				\
({						\
	char* _mem = alloca(strlen(str)+1);	\
 	strcpy(_mem, str);			\
 	_mem;					\
 })
#endif

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
		

/** Fix output ffstate->ilename if it's a directory */
const char* dirappfile(const char* onm)
{
	size_t oln = strlen(onm);
	if (!strcmp(onm, ".")) {
		char* ret = strdup(basename(strdupa(opts->iname)));
		LISTAPPEND(freenames, ret, charp);
		return ret;
	}
	if (oln > 0) {
		char lastchr = onm[oln-1];
		if (lastchr == '/') 
			return retstrdupcat3(onm, 0, opts->iname);
		else if ((lastchr == '.') &&
			  (oln > 1 && onm[oln-2] == '/'))
			return retstrdupcat3(onm, -1, opts->iname);
		else if ((lastchr == '.') &&
			   (oln > 2 && onm[oln-2] == '.' && onm[oln-3] == '/'))
			return retstrdupcat3(onm, '/', opts->iname);
		else { /* Not clear by name, so test */
			struct stat stbuf;
			int err = stat(onm, &stbuf);
			if (!err && S_ISDIR(stbuf.st_mode))
				return retstrdupcat3(onm, '/', opts->iname);
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

char* parse_opts(int argc, char* argv[], opt_t *op, dpopt_t *dop)
{
	int c;
	char* plugins = NULL;
	loff_t syncsz = -1;
	
  	/* defaults */
	memset(opts, 0, sizeof(opt_t));
	memset(dpopts, 0, sizeof(dpopt_t));
	memset(dpstate, 0, sizeof(dpstate_t));
	memset(fstate, 0, sizeof(fstate_t));
	memset(progress, 0, sizeof(progress_t));
	memset(repeat, 0, sizeof(repeat_t));
	op->init_ipos = (loff_t)-INT_MAX; 
	op->init_opos = (loff_t)-INT_MAX; 

	fstate->ides = -1; fstate->odes = -1;

	op->nocol = test_nocolor_term();

      	ofiles = NULL;

#ifdef LACK_GETOPT_LONG
	while ((c = getopt(argc, argv, ":rtTfihqvVwWaAdDkMRpPuc:b:B:m:e:s:S:l:L:o:y:z:Z:2:3:4:xY:")) != -1) 
#else
	while ((c = getopt_long(argc, argv, ":rtTfihqvVwWaAdDkMRpPuc:b:B:m:e:s:S:l:L:o:y:z:Z:2:3:4:xY:", longopts, NULL)) != -1) 
#endif
	{
		switch (c) {
			case 'r': op->reverse = 1; break;
			case 'R': op->i_repeat = 1; break;
			case 't': op->dotrunc = O_TRUNC; break;
			case 'T': op->trunclast = 1; break;
			case 'i': op->interact = 1; op->force = 0; break;
			case 'f': op->interact = 0; op->force = 1; break;
#ifdef O_DIRECT
			case 'd': op->o_dir_in  = O_DIRECT; break;
			case 'D': op->o_dir_out = O_DIRECT; break;
#endif
#ifdef HAVE_SPLICE
			case 'k': op->dosplice = 1; break;
#endif				  
			case 'p': op->preserve = 1; break;
			case 'P': op->falloc = 1; break;
			case 'a': op->sparse = 1; op->nosparse = 0; break;
			case 'A': op->nosparse = 1; op->sparse = 0; break;
			case 'w': op->abwrerr = 1; break;
			case 'W': op->avoidwrite = 1; break;
			case 'h': printlonghelp(); exit(0); break;
			case 'V': printversion(); exit(0); break;
			case 'v': op->quiet = 0; op->verbose = 1; break;
			case 'q': op->verbose = 0; op->quiet = 1; break;
			case 'c': op->nocol = !readbool(optarg); break;
			case 'b': op->softbs = (int)readint(optarg); break;
			case 'B': op->hardbs = (int)readint(optarg); break;
			case 'm': op->maxxfer = readint(optarg); break;
			case 'M': op->noextend = 1; break;
			case 'e': op->maxerr = (int)readint(optarg); break;
			case 'y': syncsz = readint(optarg); break;
			case 's': op->init_ipos = readint(optarg); break;
			case 'S': op->init_opos = readint(optarg); break;
			case 'l': op->lname = optarg; break;
			case 'L': plugins = optarg; break;
			case 'o': op->bbname = optarg; break;
			case 'x': op->extend = 1; break;
			case 'u': op->rmvtrim = 1; break;
			case 'Y': do { ofile_t of; of.name = optarg; of.fd = -1; of.cdev = 0; LISTAPPEND(ofiles, of, ofile_t); } while (0); break;
			case 'z': dop->prng_libc = 1; if (is_filename(optarg)) dop->prng_sfile = optarg; else dop->prng_seed = readint(optarg); break;
			case 'Z': dop->prng_frnd = 1; if (is_filename(optarg)) dop->prng_sfile = optarg; else dop->prng_seed = readint(optarg); break;
			case '2': dop->prng_frnd = 1; if (is_filename(optarg)) dop->prng_sfile = optarg; else dop->prng_seed = readint(optarg); dop->bsim715 = 1; dop->bsim715_2 = 1; break;
			case '3': dop->prng_frnd = 1; if (is_filename(optarg)) dop->prng_sfile = optarg; else dop->prng_seed = readint(optarg); dop->bsim715 = 1; break;
			case '4': dop->prng_frnd = 1; if (is_filename(optarg)) dop->prng_sfile = optarg; else dop->prng_seed = readint(optarg); dop->bsim715 = 1; dop->bsim715_4 = 1; break;
			case ':': fplog(stderr, FATAL, "option %c requires an argument!\n", optopt); 
				shortusage();
				exit(11); break;
			case '?': fplog(stderr, FATAL, "unknown option %c!\n", optopt, argv[0]);
				shortusage();
				exit(11); break;
			default: fplog(stderr, FATAL, "your getopt() is buggy!\n");
				exit(255);
		}
	}
  
	if (dop->prng_libc)
		op->iname = "PRNG_libc";
	else if (dop->prng_frnd)
		op->iname = "PRNG_frnd";
	else if (optind < argc)
		op->iname = argv[optind++];

	if (optind < argc) 
		op->oname = argv[optind++];
	if (optind < argc) {
		fplog(stderr, FATAL, "spurious options: %s ...\n", argv[optind]);
		shortusage();
		exit(12);
	}
	/* Defaults for blocksizes */
	if (op->softbs == 0) {
		if (op->o_dir_in)
			op->softbs = DIO_SOFTBLOCKSIZE;
		else
			op->softbs = BUF_SOFTBLOCKSIZE;
	}
	if (op->hardbs == 0) {
		if (op->o_dir_in)
			op->hardbs = DIO_HARDBLOCKSIZE;
		else
			op->hardbs = BUF_HARDBLOCKSIZE;
	}
	if (!op->quiet)
		fplog(stderr, INFO, "Using softbs=%skiB, hardbs=%skiB\n", 
			fmt_kiB(op->softbs), fmt_kiB(op->hardbs));

	/* sanity checks */
#ifdef O_DIRECT
	if ((op->o_dir_in || op->o_dir_out) && op->hardbs < 512) {
		op->hardbs = 512;
		fplog(stderr, WARN, "O_DIRECT requires hardbs of at least %i!\n",
		      op->hardbs);
	}

	if (op->o_dir_in || op->o_dir_out)
		fplog(stderr, WARN, "We don't handle misalignment of last block w/ O_DIRECT!\n");
				
#endif

	if (op->softbs < op->hardbs) {
		fplog(stderr, WARN, "setting hardbs from %i to softbs %i!\n",
		      op->hardbs, op->softbs);
		op->hardbs = op->softbs;
	}

	/* Set sync frequency */
	/*
	if (syncsz == -1)
		op->syncfreq = 512;
	else */ 
	if (syncsz <= 0)
		op->syncfreq = 0;
	else
		op->syncfreq = (syncsz + op->softbs - 1) / op->softbs;

	return plugins;
}



int main(int argc, char* argv[])
{

	detect_cpu_cap();
#ifdef _SC_PAGESIZE
	fstate->pagesize = sysconf(_SC_PAGESIZE);
#else
#warning Cant determine fstate->pagesize, setting to 4kiB
	fstate->pagesize = 4096;
#endif

#if 0
	if (sizeof(loff_t) <= 4/* || sizeof(size_t) <= 4*/)
		fplog(stderr, WARN, "Limited range: off_t %i/%i bits, size_t %i bits%\n", 
			8*sizeof(off_t), 8*sizeof(loff_t), 8*sizeof(size_t));
#endif
	char* plugins = parse_opts(argc, argv, opts, dpopts);

#ifdef USE_LIBDL
	if (plugins)
		load_plugins(plugins);
	if (not_sparse && opts->sparse) {
		fplog(stderr, FATAL, "not all plugins handle -a/--sparse!\n");
		exit(13);
	}
	if (not_sparse && !opts->nosparse) {
		fplog(stderr, WARN, "some plugins don't handle sparse, enabled -A/--nosparse!\n");
		opts->nosparse = 1;
	}
	if (have_block_cb && opts->reverse) {
		fplog(stderr, FATAL, "Plugins currently don't handle reverse\n");
		exit(13);
	}
	if (have_block_cb && opts->dosplice) {
		fplog(stderr, FATAL, "Plugins can't handle splice\n");
		exit(13);
	}
#endif

	if (!opts->iname || !opts->oname) {
		fplog(stderr, FATAL, "both input and output files have to be specified!\n");
		shortusage();
		exit(12);
	}

	if (opts->lname) {
		int fd = openfile(opts->lname, O_WRONLY | O_CREAT /*| O_EXCL*/);
		logfd = fdopen(fd, "a");
	}

	/* Have those been set by cmdline params? */
	if (opts->init_ipos == (loff_t)-INT_MAX)
		opts->init_ipos = 0;

	if (opts->dosplice && opts->avoidwrite) {
		fplog(stderr, WARN, "disable write avoidance (-W) for splice copy\n");
		opts->avoidwrite = 0;
	}
	max_slack_pre  += -max_neg_slack_pre *((opts->softbs+15)/16);
	max_slack_post += -max_neg_slack_post*((opts->softbs+15)/16);
	fstate->buf = zalloc_aligned_buf(opts->softbs, &fstate->origbuf);

	/* Optimization: Don't reread from /dev/zero over and over ... */
	if (!opts->dosplice && !strcmp(opts->iname, "/dev/zero")) {
		if (!opts->i_repeat && opts->verbose)
			fplog(stderr, INFO, "turning on repeat (-R) for /dev/zero\n");
		opts->i_repeat = 1;
		if (opts->reverse && !opts->init_ipos && opts->maxxfer)
			opts->init_ipos = opts->maxxfer > opts->init_opos? opts->init_opos: opts->maxxfer;
	}

	/* Properly append input basename if output name is dir */
	opts->oname = dirappfile(opts->oname);

	fstate->identical = check_identical(opts->iname, opts->oname);

	if (fstate->identical && opts->dotrunc && !opts->force) {
		fplog(stderr, FATAL, "infile and outfile are identical and trunc turned on!\n");
		cleanup(); exit(14);
	}

	/* Open input and output files */
	if (dpopts->prng_libc || dpopts->prng_frnd) {
		init_random();
		fstate->i_chr = 1; /* fstate->ides = 0; */
		opts->dosplice = 0; opts->sparse = 0;
	} else {
		fstate->ides = openfile(opts->iname, O_RDONLY | opts->o_dir_in);
		if (fstate->ides < 0) {
			fplog(stderr, FATAL, "could not open %s: %s\n", opts->iname, strerror(errno));
			cleanup(); exit(22);
		}
	}
	/* Overwrite? */
	/* Special case '-': stdout */
	if (strcmp(opts->oname, "-"))
		fstate->odes = open64(opts->oname, O_WRONLY | opts->o_dir_out, 0640);
	else {
		fstate->odes = 1;
		fstate->o_chr = 1;
	}

	if (fstate->odes > 1) 
		close(fstate->odes);

	if (fstate->odes > 1 && opts->interact) {
		int a;
		do {
			fprintf(stderr, "dd_rescue: (question): %s existing %s [y/n]? ", 
				(opts->dotrunc? "Overwrite": "Write into"), opts->oname);
			a = toupper(fgetc(stdin)); //fprintf(stderr, "\n");
		} while (a != 'Y' && a != 'N');
		if (a == 'N') {
			fplog(stderr, FATAL, "exit on user request!\n");
			cleanup(); exit(23);
		}
	}
	if (fstate->o_chr && opts->avoidwrite) {
		if (!strcmp(opts->oname, "/dev/null")) {
			fplog(stderr, INFO, "Avoid writes to /dev/null ...\n");
			opts->avoidnull = 1;
		} else {
			fplog(stderr, WARN, "Disabling -Write avoidance b/c ofile is not seekable\n");
			opts->avoidwrite = 0;
		}
	}
		
	/* Sanity checks for opts->rmvtrim */
	if ((fstate->o_chr || fstate->o_lnk || fstate->o_blk) && opts->rmvtrim) {
		fplog(stderr, FATAL, "Can't delete output file when it's not a normal file\n");
		cleanup(); exit(23);
	}

	if (opts->rmvtrim && !(opts->i_repeat || dpopts->prng_libc || dpopts->prng_frnd || opts->force)) {
		int a;
		do {
			fprintf(stderr, "dd_rescue: (question): really remove %s at the end [y/n]? ",
				opts->oname);
			a = toupper(fgetc(stdin)); //fprintf(stderr, "\n");
		} while (a != 'Y' && a != 'N');
		if (a == 'N') {
			fplog(stderr, FATAL, "exit on user request!\n");
			opts->rmvtrim = 0;
			cleanup(); exit(23);
		}
	}

	if (fstate->odes != 1) {
		if (opts->avoidwrite) {
			if (opts->dotrunc) {
				fplog(stderr, WARN, "Disable early trunc(-t) as we can't avoid writes otherwise.\n");
				opts->dotrunc = 0;
			}
			fstate->buf2 = zalloc_aligned_buf(opts->softbs, &fstate->origbuf2);
			fstate->odes = openfile(opts->oname, O_RDWR | O_CREAT | opts->o_dir_out /*| O_EXCL*/);
		} else
			fstate->odes = openfile(opts->oname, O_WRONLY | O_CREAT | opts->o_dir_out /*| O_EXCL*/ | opts->dotrunc);
	}

	if (fstate->odes < 0) {
		fplog(stderr, FATAL, "%s: %s\n", opts->oname, strerror(errno));
		cleanup(); exit(24);
	}

	if (opts->preserve)
		copyperm(fstate->ides, fstate->odes);
			
	check_seekable(fstate->ides, &fstate->i_chr, "input");
	check_seekable(fstate->odes, &fstate->o_chr, "output");
	
	if (!opts->extend)
		sparse_output_warn();
	if (fstate->o_chr) {
		if (!opts->nosparse)
			fplog(stderr, WARN, "Not using sparse writes for non-seekable output\n");
		opts->nosparse = 1; opts->sparse = 0; opts->dosplice = 0;
		if (opts->avoidwrite) {
			if (!strcmp(opts->oname, "/dev/null")) {
				fplog(stderr, INFO, "Avoid writes to /dev/null ...\n");
				opts->avoidnull = 1;
			} else {
				fplog(stderr, WARN, "Disabling -Write avoidance b/c ofile is not seekable\n");
				ZFREE(fstate->origbuf2);
				opts->avoidwrite = 0;
			}
		}
	}

	/* special case: opts->reverse with opts->init_ipos == 0 means opts->init_ipos = EOF */
	if (opts->reverse && opts->init_ipos == 0) {
		opts->init_ipos = lseek64(fstate->ides, 0, SEEK_END);
		if (opts->init_ipos == -1) {
			fplog(stderr, FATAL, "could not seek to end of file %s!\n", opts->iname);
			perror("dd_rescue"); cleanup(); exit(19);
		}
		if (opts->verbose) 
			fprintf(stderr, DDR_INFO "ipos set to the end: %skiB\n", 
			        fmt_kiB(opts->init_ipos));
		/* if opts->init_opos not set, assume same position */
		if (opts->init_opos == (loff_t)-INT_MAX) 
			opts->init_opos = opts->init_ipos;
		/* if explicitly set to zero, assume end of _existing_ file */
		if (opts->init_opos == 0) {
			opts->init_opos = lseek64(fstate->odes, 0, SEEK_END);
			if (opts->init_opos == (loff_t)-1) {
				fplog(stderr, FATAL, "could not seek to end of file %s!\n", opts->oname);
				perror("dd_rescue"); cleanup(); exit(19);
			}
			/* if existing empty, assume same position */
			if (opts->init_opos == 0)
				opts->init_opos = opts->init_ipos;
			if (opts->verbose) 
				fprintf(stderr, DDR_INFO "opos set to: %skiB\n",
					fmt_kiB(opts->init_opos));
    		}
	}

	/* if opts->init_opos not set, assume same position */
	if (opts->init_opos == (loff_t)-INT_MAX)
		opts->init_opos = opts->init_ipos;

	if (fstate->identical) {
		fplog(stderr, WARN, "infile and outfile are identical!\n");
		if (opts->init_opos > opts->init_ipos && !opts->reverse && !opts->force) {
			fplog(stderr, WARN, "turned on reverse, as ipos < opos!\n");
			opts->reverse = 1;
    		}
		if (opts->init_opos < opts->init_ipos && opts->reverse && !opts->force) {
			fplog(stderr, WARN, "turned off reverse, as opos < ipos!\n");
			opts->reverse = 0;
		}
  	}

	if (fstate->o_chr && opts->init_opos != 0) {
		if (opts->force)
			fplog(stderr, WARN, "ignore non-seekable output with opos != 0 due to --force\n");
		else {
			fplog(stderr, FATAL, "outfile not seekable, but opos !=0 requested!\n");
			cleanup(); exit(19);
		}
	}
	if (fstate->i_chr && opts->init_ipos != 0) {
		fplog(stderr, FATAL, "infile not seekable, but ipos !=0 requested!\n");
		cleanup(); exit(19);
	}
		
	if (opts->dosplice) {
		if (!opts->quiet)
			fplog(stderr, INFO, "splice copy, ignoring -a, -r, -y, -R, -W\n");
		opts->reverse = 0;
	}

	if (opts->noextend || opts->extend) {
		if (output_length() == -1) {
			fplog(stderr, FATAL, "asked to (not) extend output file but can't determine size\n");
			cleanup(); exit(19);
		}
		if (opts->extend)
			opts->init_opos += fstate->olen;
	}
	input_length();

	if (opts->init_ipos < 0 || opts->init_opos < 0) {
		fplog(stderr, FATAL, "negative position requested (%skiB)\n", 
			fmt_kiB(opts->init_ipos));
		cleanup(); exit(25);
	}


#if defined(HAVE_FALLOCATE64) || defined(HAVE_LIBFALLOCATE)
	if (opts->falloc && !fstate->o_chr)
		do_fallocate(fstate->odes, opts->oname);
#endif

	if (opts->verbose) {
		printinfo(stderr);
		if (logfd)
			printinfo(logfd);
	}

	if (dpopts->bsim715 && opts->avoidwrite) {
		fplog(stderr, WARN, "won't avoid writes for -3\n");
		opts->avoidwrite = 0;
		ZFREE(fstate->buf2);
	}
	if (dpopts->bsim715 && fstate->o_chr) {
		fplog(stderr, WARN, "triple overwrite with non-seekable output!\n");
	}
	if (opts->reverse && opts->trunclast)
		if (ftruncate(fstate->odes, opts->init_opos))
			fplog(stderr, WARN, "Could not truncate %s to %skiB: %s!\n",
				opts->oname, fmt_kiB(opts->init_opos), strerror(errno));

	LISTTYPE(ofile_t) *of;
	LISTFOREACH(ofiles, of) {
		int id;
		ofile_t *oft = &(LISTDATA(of));
		oft->name = dirappfile(oft->name);
		id = check_identical(opts->iname, oft->name);
		if (id)
			fplog(stderr, WARN, "Input file and secondary output file %s are identical!\n", oft->name);
		oft->fd = openfile(oft->name, (opts->avoidwrite? O_RDWR: O_WRONLY) | O_CREAT | opts->o_dir_out | opts->dotrunc);
		check_seekable(oft->fd, &(oft->cdev), NULL);
		if (opts->preserve)
			copyperm(fstate->ides, oft->fd);
#if defined(HAVE_FALLOCATE64) || defined(HAVE_LIBFALLOCATE)
		if (opts->falloc && !oft->cdev)
			do_fallocate(oft->fd, oft->name);
#endif
		if (opts->reverse && opts->trunclast)
			if (ftruncate(oft->fd, opts->init_opos))
				fplog(stderr, WARN, "Could not truncate %s to %skiB: %s!\n",
					oft->name, fmt_kiB(opts->init_opos), strerror(errno));
	}

	/* Install signal handler */
	signal(SIGHUP , breakhandler);
	signal(SIGINT , breakhandler);
	signal(SIGTERM, breakhandler);
	/* Used to signal clean abort from plugins */
	signal(SIGQUIT, breakhandler);

	/* Save time and start to work */
	fstate->ipos = opts->init_ipos;
	fstate->opos = opts->init_opos;
	int err = 0;

	startclock = clock();
	gettimeofday(&starttime, NULL);
	memcpy(&lasttime, &starttime, sizeof(lasttime));

	if (!opts->quiet) {
		scrollup = 0;
		printstatus(stderr, 0, opts->softbs, 0);
	}

	if (dpopts->bsim715) {
		err = tripleoverwrite(opts->maxxfer);
	} else {
		fadvise(0);
#ifdef HAVE_SPLICE
		if (opts->dosplice)
			err = copyfile_splice(opts->maxxfer);
		else 
#endif
		{
			call_plugins_open();
			if (opts->softbs > opts->hardbs)
				err = copyfile_softbs(opts->maxxfer);
			else
				err = copyfile_hardbs(opts->maxxfer);
		}
	}

	gettimeofday(&currenttime, NULL);
	printreport();
	fadvise(1);
	err += cleanup();
	if (int_by == SIGQUIT)
		++err;
	if (err && opts->verbose)
		fplog(stderr, WARN, "There were %i errors! \n", err);
	if (interrupted && int_by != SIGQUIT)
		return 128+int_by;
	else
		return err;
}
