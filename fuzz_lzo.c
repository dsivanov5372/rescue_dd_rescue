/** \file fuzz_lzo.c
 * \brief
 * This program produces broken LZO files to test robustness
 * of the libddr_lzo decompressor against broken files
 * as this is a potential attack vector for malicious folks.
 *
 * Overwriting random bytes is simple, but we can also be more
 * clever in fuzzing and fix checksums to see whether we can expose
 * vulnerabilities this way.
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 5/2014
 * License: GNU GPLv2 or v3.
 */

#include <lzo/lzo1x.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
//#include <sys/mman.h>
#include "list.h"

void usage()
{
	fprintf(stderr, "Usage: fuzz_lzo [options] input output.lzo\n");
	fprintf(stderr, " fuzz_lzo produces an lzo compressed file from input and writes\n"
			" it to output.lzo\n");
	fprintf(stderr, " fuzz_lzo applies distortions according to the options specified.\n");
	fprintf(stderr, " Many distortions can be done with and without fixing the checksums.\n"
			" The option -! toggles fixing for subsequent distortions, starting with on\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, " -h\t\tThis help\n");
	fprintf(stderr, " -d\t\tENable debug mode\n");
	fprintf(stderr, " -b BLKSZ\tBlocksize while compressing\n");
	fprintf(stderr, " -v/V XXX\tSet version/version to extract to hex XXX\n");
	fprintf(stderr, " -m/l YYY\tSet method/level to YYY\n");
	fprintf(stderr, " -n NAME\tSet name to string NAME\n");
	fprintf(stderr, " -f FLAGS\nSets hdr flags to hex XXX\n");
	fprintf(stderr, " -u BLK=VAL\tSet uncompressed len of block BLK to VAL\n");
	fprintf(stderr, " -c BLK=VAL\tSet   compressed len of block BLK to VAL\n");
	fprintf(stderr, " -x BLK:OFF=VAL\tSet byte at offset OFF in block BLK to VAL\n");
	exit(1);
}

char debug = 0;

enum disttype { NONE = 0, ULEN, CLEN, BYTE };

typedef struct {
	unsigned int blkno;
	unsigned int offset;
	unsigned int val;
	enum disttype dist;
	char fixup;
} blk_dist_t;

LISTDECL(blk_dist_t);
LISTTYPE(blk_dist_t) *blk_dists;

/* parses BLK=VAL */
void parse_two(blk_dist_t *dist, const char *arg)
{
	if (sscanf(arg, "%i=%i", &dist->blkno, &dist->val) != 2) {
		fprintf(stderr, "Error parsing %s; expect BLK=VAL\n", arg);
		usage();
	}
	dist->offset = 0;
}

/* parses BLK:OFF=VAL */
void parse_three(blk_dist_t *dist, const char *arg)
{
	if (sscanf(arg, "%i:%i=%i", &dist->blkno, &dist->offset, &dist->val) != 3) {
		fprintf(stderr, "Error parsing %s; expect BLK:OFF=VAL\n", arg);
		usage();
	}
}

void dist_append(char dst, const char* arg, char fix)
{
	blk_dist_t dist;
	dist.fixup = fix;
	switch (dst) {
		case 'u': dist.dist = ULEN;
			  parse_two(&dist, arg);
			  break;
		case 'c': dist.dist = CLEN;
			  parse_two(&dist, arg);
			  break;
		case 'x': dist.dist = BYTE;
			  parse_three(&dist, arg);
			  break;
	}
	LISTAPPEND(blk_dists, dist, blk_dist_t);
}

int write_header(int ofd, const char* nm, 
		 unsigned short hvers, unsigned short evers, 
		 unsigned char meth, unsigned char levl,
		 unsigned int flags, char hdr_fixup)
{
	return 0;
}

int compress(int ifd, int ofd, unsigned int blksz)
{
	return 0;
}

int main(int argc, char* argv[])
{
	char fixup = 1;
	char hdr_fixup = fixup;
	unsigned int blksize = 16*1024;
	unsigned short hversion = 0x1789;
	unsigned short extrvers = 0x0940;
	char *hname = NULL;
	char meth = 0;
	char levl = 5;
	unsigned int flags = 0x03000003UL;	/* UNIX | ADLER32_C | ADLER32_D */
	char c;
        while ((c = getopt(argc, argv, "hdb:v:V:m:l:n:f:u:c:x:!")) != -1) {
		switch (c) {
			case 'h':
				usage();
				break;
			case '!':
				fixup = !fixup;
				break;
			case 'd':
				debug = 1;
				break;
			case 'b':
				blksize = atoi(optarg);
				break;
			case 'v':
				hversion = atoi(optarg);
				hdr_fixup = fixup;
				break;
			case 'V':
				extrvers = atoi(optarg);
				hdr_fixup = fixup;
				break;
			case 'n':
				hname = optarg;
				hdr_fixup = fixup;
				break;
			case 'm':
				meth = atoi(optarg);
				hdr_fixup = fixup;
				break;
			case 'l':
				levl = atoi(optarg);
				hdr_fixup = fixup;
				break;
			case 'f':
				flags = atoi(optarg);
				hdr_fixup = fixup;
				break;
			case 'u':
			case 'c':
			case 'x':
				dist_append(c, optarg, fixup);
				break;
			case ':':
				fprintf(stderr, "ERROR: option -%c requires an argument!\n",
					optopt);
				usage();
				break;
			case '?':
				fprintf(stderr, "ERROR: unknown option -%c!\n", optopt);
				usage();
				break;
			default:
				fprintf(stderr, "ERROR: getopt() err!\n");
				abort();
		}

	}
	if (argc-optind != 2) {
		fprintf(stderr, "ERROR: Need exactly two non option arguments!\n");
		usage();
	}

	char *iname = argv[optind++];
	char *oname = argv[optind++];
	if (!hname)
		hname = iname;

	if (debug) {
		printf("Header: %1x.%3x %1x.%3x %i/%i %s %08x %c\n",
			hversion >> 12, hversion & 0xfff,
			extrvers >> 12, extrvers & 0xfff,
			meth, levl, hname, flags,
			hdr_fixup? ' ': '!');
		LISTTYPE(blk_dist_t) *dist;
		LISTFOREACH(blk_dists, dist) {
			if (LISTDATA(dist).dist == BYTE)
				printf("Blk %i: chg byte @ %x to %02x %c\n",
					LISTDATA(dist).blkno, 
					LISTDATA(dist).offset,
					LISTDATA(dist).val,
					LISTDATA(dist).fixup? ' ': '!');
			else
				printf("Blk %i: chg %s to %08x %c\n",
					LISTDATA(dist).blkno,
					(LISTDATA(dist).dist == ULEN? "ulen": "clen"),
					LISTDATA(dist).val,
					LISTDATA(dist).fixup? ' ': '!');
		}
	}

	int ifd = open(iname, O_RDONLY);
	if (ifd <= 0) {
		fprintf(stderr, "ERROR: Can't open %s for reading\n", iname);
		exit(2);
	}
	int ofd = open(oname, O_WRONLY | O_CREAT, 0644);
	if (ofd <= 0) {
		fprintf(stderr, "ERROR: Can't open %s for iwriting\n", oname);
		exit(3);
	}

	write_header(ofd, hname, hversion, extrvers, meth, levl, flags, hdr_fixup);
	compress(ifd, ofd, blksize);

	close(ofd);
	close(ifd);

	LISTTREEDEL(blk_dists, blk_dist_t);

	return 0;
}		



