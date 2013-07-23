/** Test & Benchmark program for find_nonzero()
 * (c) Kurt Garloff <kurt@garloff.de>, 2013
 * License: GNU GPL v2 or v3
 */

#define _GNU_SOURCE 1
#define IN_FINDZERO
#include "find_nonzero.h"
#ifdef __SSE2__
#include <emmintrin.h>

size_t find_nonzero_simd(const unsigned char* blk, const size_t ln)
{
	__m128i xmm, zero = _mm_setzero_si128();
	unsigned /*long*/ register eax;
	size_t i = 0;
	for (; i < ln; i+= 16) {
		xmm = _mm_load_si128((__m128i*)(blk+i));
		_mm_cmpeq_epi8(xmm, zero);
		eax = _mm_movemask_epi8(xmm);
		if (eax) 
			return i + myffs(eax)-1;
	}
	return ln;
}

#ifdef NEED_SIMD_RUNTIME_DETECTION
#include <signal.h>
#include <stdio.h>
char have_simd = 0;

static void ill_handler(int sig)
{
	have_simd = 0;
}

#ifdef __SSE2__
void detect_simd()
{
	volatile __m128d xmm;
	double val = 3.14159265259;
	have_simd = 1;
	signal(SIGILL, ill_handler);
	xmm = _mm_set_sd(val);
	if (!have_simd)
		fprintf(stderr, "Disabling SSE2 ...\n");
	signal(SIGILL, SIG_DFL);
}
#endif
#endif

#endif

#ifdef TEST
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>

#define SIZE (64*1024*1024)

#define TESTC(sz,routine,rep) 		\
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
#define TEST_SIMD(a,b,c) TESTC(a,b,c)
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
#ifdef NEED_SIMD_RUNTIME_DETECTION
	detect_simd();
#endif
	if (argc > 1)
		scale = atoi(argv[1]);
	buf -= (unsigned long)buf%16;
	memset(buf, 0xa5, SIZE);
	TESTC(8*1024-15, find_nonzero_c, 1024*256*scale/16);
	TEST_SIMD(8*1024-15, find_nonzero_simd, 1024*256*scale/16);
	TESTC(8*1024-15, find_nonzero, 1024*256*scale/16);
	buf++;
	TEST_SIMD(8*1024-15, find_nonzero, 1024*256*scale/16);
	buf--;
	TESTC(32*1024-9, find_nonzero_c, 1024*64*scale/16);
	TEST_SIMD(32*1024-9, find_nonzero_simd, 1024*64*scale/16);
	TESTC(32*1024-9, find_nonzero, 1024*64*scale/16);
	TESTC(128*1024-8, find_nonzero_c, 1024*16*scale/16);
	TEST_SIMD(128*1024-8, find_nonzero_simd, 1024*16*scale/16);
	TESTC(1024*1024-7, find_nonzero_c, 2048*scale/16);
	TEST_SIMD(1024*1024-7, find_nonzero_simd, 2048*scale/16);
	TESTC(4096*1024-1, find_nonzero_c, 512*scale/16);
	TEST_SIMD(4096*1024-1, find_nonzero_simd, 512*scale/16);
	TESTC(16*1024*1024, find_nonzero_c, 128*scale/16);
	TEST_SIMD(16*1024*1024, find_nonzero_simd, 128*scale/16);
	TESTC(64*1024*1024, find_nonzero_c, 32*scale/16);
	TEST_SIMD(64*1024*1024, find_nonzero_simd, 32*scale/16);

	free(obuf);
	return 0;
}
#endif
