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
	for (i = 0; i < rep; ++i) {	\
		ln = routine(buf, SIZE);\
		asm ("": : : "memory");	\
	}				\
	gettimeofday(&t2, NULL);	\
	tdiff = t2.tv_sec-t1.tv_sec + 0.000001*(t2.tv_usec-t1.tv_usec);	\
	printf("%6i x %24s (%8i): %8i (%.3fs => %5.0fMB/s)\n",	\
		rep, #routine, sz, ln, tdiff, (double)(rep)*(double)(sz)/(1024*1024*tdiff))


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
	double tdiff;
	buf -= (unsigned long)buf%16;
	memset(buf, 0xa5, SIZE);
	TEST(8*1024-15, find_nonzero_c, 1024*256);
	TEST_SIMD(8*1024-15, find_nonzero_simd, 1024*256);
	TEST(32*1024-9, find_nonzero_c, 1024*64);
	TEST_SIMD(32*1024-9, find_nonzero_simd, 1024*64);
	TEST(128*1024-8, find_nonzero_c, 1024*16);
	TEST_SIMD(128*1024-8, find_nonzero_simd, 1024*16);
	TEST(1024*1024-7, find_nonzero_c, 2048);
	TEST_SIMD(1024*1024-7, find_nonzero_simd, 2048);
	TEST(4096*1024-1, find_nonzero_c, 512);
	TEST_SIMD(4096*1024-1, find_nonzero_simd, 512);
	TEST(16*1024*1024, find_nonzero_c, 128);
	TEST_SIMD(16*1024*1024, find_nonzero_simd, 128);
	TEST(64*1024*1024, find_nonzero_c, 32);
	TEST_SIMD(64*1024*1024, find_nonzero_simd, 32);

	free(obuf);
	return 0;
}

