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
	printf("%7i x %20s (%8i): %8i (%6.3fs => %5.0fMB/s)\n",	\
		rep, #routine, sz, ln, tdiff, (double)(rep)*(double)(sz)/(1024*1024*tdiff))


#if defined(HAVE_SIMD)
#define TEST_SIMD(a,b,c) TEST(a,b,c)
#else
#define TEST_SIMD(a,b,c) do {} while (0)
#endif

int main(int argc, char* argv[])
{
	unsigned char* obuf = (unsigned char*)malloc(SIZE+15);
	unsigned char* buf = obuf+15;
	struct timeval t1, t2;
	int i, ln = 0;
	double tdiff;
	int scale = 16;
	if (argc > 1)
		scale = atoi(argv[1]);
	buf -= (unsigned long)buf%16;
	memset(buf, 0xa5, SIZE);
	TEST(8*1024-15, find_nonzero_c, 1024*256*scale/16);
	TEST_SIMD(8*1024-15, find_nonzero_simd, 1024*256*scale/16);
	TEST(8*1024-15, find_nonzero, 1024*256*scale/16);
	buf++;
	TEST_SIMD(8*1024-15, find_nonzero, 1024*256*scale/16);
	buf--;
	TEST(32*1024-9, find_nonzero_c, 1024*64*scale/16);
	TEST_SIMD(32*1024-9, find_nonzero_simd, 1024*64*scale/16);
	TEST(32*1024-9, find_nonzero, 1024*64*scale/16);
	TEST(128*1024-8, find_nonzero_c, 1024*16*scale/16);
	TEST_SIMD(128*1024-8, find_nonzero_simd, 1024*16*scale/16);
	TEST(1024*1024-7, find_nonzero_c, 2048*scale/16);
	TEST_SIMD(1024*1024-7, find_nonzero_simd, 2048*scale/16);
	TEST(4096*1024-1, find_nonzero_c, 512*scale/16);
	TEST_SIMD(4096*1024-1, find_nonzero_simd, 512*scale/16);
	TEST(16*1024*1024, find_nonzero_c, 128*scale/16);
	TEST_SIMD(16*1024*1024, find_nonzero_simd, 128*scale/16);
	TEST(64*1024*1024, find_nonzero_c, 32*scale/16);
	TEST_SIMD(64*1024*1024, find_nonzero_simd, 32*scale/16);

	free(obuf);
	return 0;
}

