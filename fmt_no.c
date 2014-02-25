/** Convert long integer to strings with highlighting 
 * (c) Kurt Garloff <kurt@garloff.de>, 2013
 * License: GNU GPL v2 or v3
 */

#define _LARGEFILE_SOURCE
#define _FILE_OFFSET_BITS 64

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "fmt_no.h"
#include <string.h>

#ifdef TEST
#define BOLD "\x1b[0;32m"
//#define BOLD "\x1b[0;1m"
#define NORM "\x1b[0;0m"
#endif

//typedef long long off_t;

static int mypow(int base, int pwr)
{
	int i;
	float pw = 1;
	for (i = 0; i < pwr; ++i)
		pw *= base;
	return pw;
}

static char fmtbufs[8][64];

/** Format integers: pre digits before the ., post digits after.
 * The integer is divided by scale prior to being returned as string.
 * The string has groups of <group> digits that are highlighted with bold
 * and norm strings. If leadbold is set, the number will be prefixed
 * with bold if the foremost group should be bold ...
 * Limitations: 
 * - We can't return more than 8 strings in parallel, before
 *   we start overwriting buffers. 
 * - The string can't be longer than 64 chars, which should be
 *   enough though to print all possible 64bit ints.
 */
char* fmt_int_b(unsigned char pre, unsigned char post, unsigned int scale,
	       	loff_t no, const char* bold, const char* norm, 
		const char leadbold, const unsigned char base,
		const unsigned char group)
{
	static int fbno = 0;
	const int blen = bold? strlen(bold): 0;
	const int nlen = norm? strlen(norm): 0;
	int idx = sizeof(fmtbufs[0])-1;
	char pos;
	loff_t my_no;
	char* fmtbuf = fmtbufs[fbno++];
	char isneg = no < 0;
	if (!scale)
		scale = 1;
	no = (no < 0? -no: no);
	fmtbuf[idx] = 0;
	fbno %= 8;
	if (post) {
		my_no = (no * mypow(base, post) + scale/2) / scale;
		while (post--) {
			int digit = my_no - base*(my_no/base);
			fmtbuf[--idx] = digit >= 10? 'a'-10+digit: '0' + digit;
			my_no /= base;
		}
		fmtbuf[--idx] = '.';
	} else
		my_no = (no + scale/2) / scale;
	for (pos = 0; pos < pre-isneg || (pre == 0 && (pos == 0 || my_no != 0)); ++pos) {
		int digit = my_no - base*(my_no/base);
		if (bold && pos && !(pos % 6)) {
			/* insert bold */
			memcpy(fmtbuf+idx-blen, bold, blen);
			idx -= blen;
		} else if (norm && !((pos+3) % 6)) {
			/* insert norm */
			memcpy(fmtbuf+idx-nlen, norm, nlen);
			idx -= nlen;
		}
		fmtbuf[--idx] = digit >= 10? 'a'-10+digit: '0' + digit;
		my_no /= base;
		if (!my_no)
			break;
	}
	/* overflow */
	if (post && my_no)
		fmtbuf[sizeof(fmtbufs[0])-1] = '+';
	else if (!isneg && my_no)
		++idx;
	/* Do we need a leading bold? */
	if (bold && leadbold && ((pos-1) % 6 >= 3)) {
		memcpy(fmtbuf+idx-blen, bold, blen);
		idx -= blen;
	}
	if (isneg) {
		if (my_no && !post)
			fmtbuf[idx] = '<';
		else
			fmtbuf[idx] = '-';
	} else if (my_no && !post)
		fmtbuf[idx] = '>';
	if (pos+isneg < pre) {
		memset(fmtbuf+idx+pos-pre, ' ', pre-pos);
		idx -= pre-pos;
	}
	return fmtbuf+idx;
}

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv)
{
	int i; loff_t l;
	for (i = 1; i < argc; ++i) {
		l = atoll(argv[i]);
		printf("%12.2f: %s %s %s %s\n",
			(double)l/1024.0, 
			fmt_int(13, 1, 1024, l, BOLD, NORM, 1),
			fmt_int(12, 1, 1024, l, BOLD, NORM, 1),
			fmt_int(11, 1, 1024, l, BOLD, NORM, 1),
			fmt_int(10, 2, 1024, l, BOLD, NORM, 1));
		printf(" %s %s %s %s %s %s\n",
			fmt_int(9, 0, 1024, l, BOLD, NORM, 1),
			fmt_int(8, 1, 1024, l, BOLD, NORM, 1),
			fmt_int(7, 1, 1024, l, BOLD, NORM, 1),
			fmt_int(6, 1, 1024, l, BOLD, NORM, 1),
			fmt_int(5, 1, 1024, l, ",", ",", 0),
			fmt_int(13, 1, 1024, l, ",", ",", 0));
		printf(" %s\n", fmt_int(0, 1, 1024, l, BOLD, NORM, 1));
	}
	return 0;
}
#endif



