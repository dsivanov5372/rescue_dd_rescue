#include <string.h>
#include <sys/types.h>

#define BOLD "\x1b[0;1m"
#define NORM "\x1b[0;0m"

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

/* Format integers: pre digits before the ., post digits after.
 * The integer is divided by scale prior to being returned as string.
 * The string has groups of 3 digits highlighted.
 * Limitations: We can't return more than 8 strings in parallel, before
 * we start overwriting buffers. The string can't be longer than 64 chars,
 * which should be enough though to print all possible 64bit ints.
 */
char* fmt_int(int pre, int post, int scale, off_t no)
{
	static int fbno = 0;
	const int blen = strlen(BOLD);
	const int nlen = strlen(NORM);
	int idx = sizeof(fmtbufs[0])-1;
	char pos;
	off_t my_no;
	char* fmtbuf = fmtbufs[fbno++];
	fmtbuf[idx] = 0;
	fbno %= 8;
	if (post) {
		my_no = (no * mypow(10, post) + scale/2) / scale;
		while (post--) {
			int digit = my_no - 10*(my_no/10);
			fmtbuf[--idx] = '0' + digit;
			my_no /= 10;
		}
		fmtbuf[--idx] = '.';
	} else
		my_no = (no + scale/2) / scale;
	for (pos = 0; pos < pre; ++pos) {
		int digit = my_no - 10*(my_no/10);
		if (pos && !(pos % 6)) {
			/* insert bold */
			memcpy(fmtbuf+idx-blen, BOLD, blen);
			idx -= blen;
		} else if (!((pos+3) % 6)) {
			/* insert norm */
			memcpy(fmtbuf+idx-nlen, NORM, nlen);
			idx -= nlen;
		}
		if (my_no < 1 && !digit)
			fmtbuf[--idx] = ' ';
		else	
			fmtbuf[--idx] = '0' + digit;
		my_no /= 10;
		/* overflow */
		if (pos == pre-1 && my_no)
			fmtbuf[idx] = '>';
	}
	/* Do we lack a bold? */
	if ((pre-1) % 6 >= 3) {
		memcpy(fmtbuf+idx-blen, BOLD, blen);
		idx -= blen;
	}
	return fmtbuf+idx;
}

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv)
{
	int i; unsigned long l;
	for (i = 1; i < argc; ++i) {
		l = atoll(argv[i]);
		printf("%12.2f: %s %s %s %s\n",
			(double)l/1024.0, 
			fmt_int(13, 1, 1024, l),
			fmt_int(12, 1, 1024, l),
			fmt_int(11, 1, 1024, l),
			fmt_int(10, 2, 1024, l));
		printf(" %s %s %s %s %s\n",
			fmt_int(9, 0, 1024, l),
			fmt_int(8, 1, 1024, l),
			fmt_int(7, 1, 1024, l),
			fmt_int(6, 1, 1024, l),
			fmt_int(5, 1, 1024, l));
	}
	return 0;
}
#endif



