/** Test & Benchmark program for find_nonzero()
 * (c) Kurt Garloff <kurt@garloff.de>, 2013
 * License: GNU GPL v2 or v3
 */

#define _GNU_SOURCE 1
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include "find_nonzero.h"

#define SIZE (64*1024*1024)

#define TEST(sz,routine,rep) 		\
	memset(buf, 0, sz);		\
	gettimeofday(&t1, NULL);	\
	for (i = 0; i < rep; ++i)	\
		ln = routine(buf, SIZE);\
	gettimeofday(&t2, NULL);	\
	printf("%5i x %24s (%8i): %.3fs => %8i\n",\
		rep, #routine, sz,	\
		t2.tv_sec-t1.tv_sec+0.000001*(t2.tv_usec-t1.tv_usec), ln)


#if defined(HAVE_SIMD)
#define TEST_SIMD(a,b,c) TEST(a,b,c)
#else
#define TEST_SIMD(a,b,c) do {} while (0)
#endif

int main()
{
	unsigned char* obuf = (unsigned char*)malloc(SIZE+15);
	unsigned char* buf = obuf+15;
	struct timeval t1, t2;
	int i, ln;
	buf -= (unsigned long)buf%16;
	memset(buf, 0xa5, SIZE);
	TEST(1024*1024, find_nonzero_c, 2048);
	TEST_SIMD(1024*1024, find_nonzero_simd, 2048);
	TEST(1024*1024+3, find_nonzero_c, 2048);
	TEST_SIMD(1024*1024+3, find_nonzero_simd, 2048);
	TEST(1024*1024+6, find_nonzero_c, 2048);
	TEST_SIMD(1024*1024+6, find_nonzero_simd, 2048);
	TEST(1024*1024+9, find_nonzero_c, 2048);
	TEST_SIMD(1024*1024+9, find_nonzero_simd, 2048);
	TEST(1024*1024+16, find_nonzero_c, 2048);
	TEST_SIMD(1024*1024+16, find_nonzero_simd, 2048);

	TEST(16*1024*1024+9, find_nonzero_c, 128);
	TEST_SIMD(16*1024*1024+9, find_nonzero_simd, 128);

	TEST(64*1024*1024, find_nonzero_c, 32);
	TEST_SIMD(64*1024*1024, find_nonzero_simd, 32);

	free(obuf);
	return 0;
}

