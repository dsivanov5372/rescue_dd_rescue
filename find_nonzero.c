/** Test & Benchmark program for find_nonzero()
 * (c) Kurt Garloff <kurt@garloff.de>, 2013
 * License: GNU GPL v2 or v3
 */

#define _GNU_SOURCE 1
#define IN_FINDZERO
#include "find_nonzero.h"

#if defined(TEST) && (defined(__i386__) || defined(__x86_64__))
/** Just for testing the speed of the good old x86 string instructions */
size_t find_nonzero_rep(const unsigned char* blk, const size_t ln)
{
	unsigned long register res;
	asm volatile (
	"	xor %%al, %%al	\n"
	"	repz scasb	\n"
	"	je 1f		\n"
#ifdef __i386__
	"	inc %%ecx	\n"
#else
	"	inc %%rcx	\n"
#endif
	"	1:		\n"
		: "=c"(res), "=D"(blk): "0"(ln), "1"(blk): "al");
	return ln - res;
}
#define HAVE_NONZERO_REP
#endif

#ifdef __SSE2__
#include <emmintrin.h>

#ifdef TEST
/** SSE2 version for measuring the initial zero bytes of aligned blk */
size_t find_nonzero_sse2o(const unsigned char* blk, const size_t ln)
{
	__m128i register xmm;
	const __m128i register zero = _mm_setzero_si128();
#ifdef SIMD_XOR
	const __m128i register mask = _mm_set_epi16(-1, -1, -1, -1, -1, -1, -1, -1);
#endif
	unsigned register eax;
	size_t i = 0;
	//asm(".align 32");
	for (; i < ln; i+= 16) {
		xmm = _mm_load_si128((__m128i*)(blk+i));
#ifdef BUGGY_136
		_mm_cmpeq_epi8(xmm, zero);
		eax = _mm_movemask_epi8(xmm);
#else
		xmm = _mm_cmpeq_epi8(xmm, zero);
#ifdef SIMD_XOR
		xmm = _mm_xor_si128(xmm, mask);
#endif
		eax = _mm_movemask_epi8(xmm);
#endif	/* BUGGY **/
#if defined(SIMD_XOR) || defined(BUGGY_136)
		if (eax) 
			return i + myffs(eax)-1;
#else
		if (eax != 0xffff)
			return i + myffs(eax^0xffff)-1;
#endif
	}
	return ln;
}
#endif

/** SSE2 version for measuring the initial zero bytes of 16b aligned blk */
size_t find_nonzero_sse2(const unsigned char* blk, const size_t ln)
{
	/*
	if (!ln || *blk)
		return 0;
	 */
	register __m128i xmm0, xmm1;
	register const __m128i zero = _mm_setzero_si128();
	register unsigned int eax, ebx;
	size_t i = 0;
	//asm(".p2align 5");
	for (; i < ln; i+= 32) {
#if 1
		xmm0 = _mm_load_si128((__m128i*)(blk+i));
		xmm1 = _mm_load_si128((__m128i*)(blk+i+16));
		xmm0 = _mm_cmpeq_epi8(xmm0, zero);
		xmm1 = _mm_cmpeq_epi8(xmm1, zero);
#else
		//xmm0 = _mm_cmpeq_epi8(*(__m128i*)(blk+i), zero);
		//xmm1 = _mm_cmpeq_epi8(*(__m128i*)(blk+i+16), zero);
#endif
		eax = _mm_movemask_epi8(xmm0);
		ebx = _mm_movemask_epi8(xmm1);
		eax = ~(eax | (ebx << 16));
		if (eax) 
			return i + myffs(eax)-1;
	}
	return ln;
}

#ifdef NEED_SIMD_RUNTIME_DETECTION
const char* SIMD_STR = "";
char have_simd;
/** Issue an SSE2 insn for runtime detection of SSE2 capability (x86) */
volatile __m128d _probe_xmm;
void probe_simd_sse2()
{
	double val = 3.14159265358979323844;
	_probe_xmm = _mm_set_sd(val);
}
#endif	/* NEED_SIMD_RUNTIME_DETECTION */

#endif	/* __SSE2__ */

#if defined(__arm__)
/** ASM optimized version for ARM.
 * Inspired by Linaro's strlen() implementation; 
 * we don't even need NEON here, ldmia does the 3x speedup on Cortexes */
size_t find_nonzero_arm6(const unsigned char *blk, const size_t ln)
{
	/*
	if (!ln || *blk)
		return 0;
	 */
	register unsigned char* res;
	const register unsigned char* end = blk+ln;
	asm volatile(
	//".align 4			\n"
	"1:				\n"
	"	ldmia %0!,{r2,r3}	\n"
	"	cmp r2, #0		\n"
	"	bne 2f			\n"
	"	ldmia %0!,{r4,r5}	\n"
	"	cmp r3, #0		\n"
	"	bne 3f			\n"
	"	cmp r4, #0		\n"
	"	bne 4f			\n"
	"	cmp r5, #0		\n"
	"	bne 5f			\n"
	"	cmp %0, %2		\n"	/* end? */
	"	blt 1b			\n"
	"	mov %0, %2		\n"	
	"	b 10f			\n"	/* exhausted search */
	"2:				\n"
	"	add %0, #4		\n"	/* First u32 is non-zero */
	"	mov r3, r2		\n"
	"3:				\n"
	"	sub %0, #4		\n"
	"	mov r4, r3		\n"
	"4:				\n"
	"	sub %0, #4		\n"
	"	mov r5, r4		\n"
	"5:				\n"
	"	sub %0, #4		\n"
//#ifndef __ARMEB__				/* Little endian bitmasks */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	"	tst r5, #0xff		\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff00		\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff0000	\n"
#else
	"	tst r5, #0xff000000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff0000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff00		\n"
#endif
	"	bne 10f			\n"
	"	add %0, #1		\n"	
	"10:				\n"
	: "=r"(res)
	: "0"(blk), "r"(end)
	: "r2", "r3", "r4", "r5");
	return res-blk;
}
#define find_nonzero_simd find_nonzero_arm6
#endif


#ifdef TEST
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>

#define SIZE (64*1024*1024)

#define mem_clobber	asm("": : : "memory")
#define RTESTC(sz,routine,rnm,rep,tsz) 	\
	memset(buf, 0, sz);		\
	expect = (tsz<sz? tsz: sz);	\
	gettimeofday(&t1, NULL);	\
	for (i = 0; i < rep; ++i) {	\
		mem_clobber;		\
		ln = routine(buf, tsz);	\
	}				\
	gettimeofday(&t2, NULL);	\
	tdiff = t2.tv_sec-t1.tv_sec + 0.000001*(t2.tv_usec-t1.tv_usec);	\
	printf("%7i x %20s (%8i): %8i (%6.3fs => %5.0fMB/s)\n",	\
		rep, rnm, sz, ln, tdiff, (double)(rep)*(double)(expect+1)/(1024*1024*tdiff));	\
	if (ln != expect)		\
		abort()


#define RTEST2C(sz,routine,rnm,rep,tsz) \
	memset(buf, 0, tsz);		\
	expect = (tsz<sz? tsz: sz);	\
	gettimeofday(&t1, NULL);	\
	buf[sz] = 0x4c;			\
	gettimeofday(&t1, NULL);	\
	for (i = 0; i < rep; ++i) {	\
		mem_clobber;		\
		ln = routine(buf, tsz);	\
	}				\
	gettimeofday(&t2, NULL);	\
	tdiff = t2.tv_sec-t1.tv_sec + 0.000001*(t2.tv_usec-t1.tv_usec);	\
	printf("%7i x %20s (%8i): %8i (%6.3fs => %5.0fMB/s)\n",	\
		rep, rnm, sz, ln, tdiff, (double)(rep)*(double)(expect+1)/(1024*1024*tdiff));	\
	if (ln != expect)		\
		abort()

#define TESTC(sz,rtn,rep,tsz) RTESTC(sz,rtn,#rtn,rep,tsz)
#define TEST2C(sz,rtn,rep,tsz) RTEST2C(sz,rtn,#rtn,rep,tsz)

#if defined(HAVE_SIMD)
#define TEST_SIMD(a,b,c,d) RTESTC(a,b,FNZ_SIMD,c*2,d)
#define TEST2_SIMD(a,b,c,d) RTEST2C(a,b,FNZ_SIMD,c*2,d)
#else
#define TEST_SIMD(a,b,c,d) do {} while (0)
#define TEST2_SIMD(a,b,c,d) do {} while (0)
#endif

#ifdef __SSE2__
#define TEST_SIMD2(a,b,c,d) TESTC(a,b,c*2,d)
#define TEST2_SIMD2(a,b,c,d) TEST2C(a,b,c*2,d)
#else
#define TEST_SIMD2(a,b,c,d) do {} while (0)
#define TEST2_SIMD2(a,b,c,d) do {} while (0)
#endif

#if defined(HAVE_NONZERO_REP)
#define TEST_REP(a,b,c,d) TESTC(a,b,c,d)
#else
#define TEST_REP(a,b,c,d) do {} while (0)
#endif

#define TESTFFS(val) printf("%08x: last %i first %i\n", val, myffsl(val), myflsl(val));
#if __WORDSIZE == 64
#define TESTFFS64(val) printf("%016Lx: last %i first %i\n", val, myffsl(val), myflsl(val));
#else
#define TESTFFS64(val) do {} while (0)
#endif

int main(int argc, char* argv[])
{
	unsigned char* obuf = (unsigned char*)malloc(SIZE+31);
	unsigned char* buf = (obuf+31)-((unsigned long)(obuf+31)%32);
	struct timeval t1, t2;
	int i, expect, ln = 0;
	double tdiff;
	int scale = 16;
#ifdef NEED_SIMD_RUNTIME_DETECTION
	detect_simd();
#endif
	printf("Using extensions: %s\n", SIMD_STR);
	TESTFFS(0x05000100);
	TESTFFS(0x00900002);
	TESTFFS(0x00000100);
	TESTFFS(0x80400000);
	TESTFFS64(0x0030000000000100ULL);
	TESTFFS64(0x1000000000000000ULL);
	TESTFFS64(0x0000000000001000ULL);

	if (argc > 1)
		scale = atoi(argv[1]);
	memset(buf, 0xa5, SIZE);
	
	TESTC    (0, find_nonzero_c,    1024*512*scale/16, SIZE);
	TEST_SIMD(0, find_nonzero_opt,  1024*512*scale/16, SIZE);
	TESTC    (0, find_nonzero,      1024*512*scale/16, SIZE);
	TEST_REP (0, find_nonzero_rep,  1024*512*scale/16, SIZE);
	
	TESTC    (8*1024-15, find_nonzero_c,    1024*128*scale/16, SIZE);
	TEST_SIMD(8*1024-15, find_nonzero_opt,  1024*128*scale/16, SIZE);
	TESTC    (8*1024-15, find_nonzero,      1024*128*scale/16, SIZE);
	TEST_REP (8*1024-15, find_nonzero_rep,  1024*128*scale/16, SIZE);
	buf++;
	TESTC    (8*1024-15, find_nonzero,      1024*128*scale/16, SIZE);
	TEST_REP (8*1024-15, find_nonzero_rep,  1024*128*scale/16, SIZE);
	buf--;
	TESTC     (32*1024-9, find_nonzero_c,     1024*32*scale/16, SIZE);
	TEST_SIMD (32*1024-9, find_nonzero_opt,   1024*32*scale/16, SIZE);
	TEST_SIMD2(32*1024-9, find_nonzero_sse2o, 1024*32*scale/16, SIZE);
	TESTC     (32*1024-9, find_nonzero,       1024*32*scale/16, SIZE);
	TEST_REP  (32*1024-9, find_nonzero_rep,   1024*32*scale/16, SIZE);
	TESTC    (128*1024-8, find_nonzero_c,    1024*8*scale/16, SIZE);
	TEST_SIMD(128*1024-8, find_nonzero_opt,  1024*8*scale/16, SIZE);
	TEST_REP (128*1024-8, find_nonzero_rep,  1024*8*scale/16, SIZE);
	TESTC    (1024*1024-7, find_nonzero_c,    1024*scale/16, SIZE);
	TEST_SIMD(1024*1024-7, find_nonzero_opt,  1024*scale/16, SIZE);
	TEST_REP (1024*1024-7, find_nonzero_rep,  1024*scale/16, SIZE);
	TESTC    (4096*1024-1, find_nonzero_c,    256*scale/16, SIZE);
	TEST_SIMD(4096*1024-1, find_nonzero_opt,  256*scale/16, SIZE);
	TESTC    (16*1024*1024, find_nonzero_c,    64*scale/16, SIZE);
	TEST_SIMD(16*1024*1024, find_nonzero_opt,  64*scale/16, SIZE);
	TESTC    (64*1024*1024, find_nonzero_c,    16*scale/16, SIZE);
	TEST_SIMD(64*1024*1024, find_nonzero_opt,  16*scale/16, SIZE);
	
	TESTC    (64*1024*1024, find_nonzero_c,    1+scale/16, SIZE-16);
	TEST_SIMD(64*1024*1024, find_nonzero_opt,  1+scale/16, SIZE-16);
	TESTC    (64*1024*1024, find_nonzero,      1+scale/16, SIZE-16);
	TEST_REP (64*1024*1024, find_nonzero_rep,  1+scale/16, SIZE-16);

	TESTC    (64*1024*1024, find_nonzero_c,    1+scale/16, SIZE-5);
	TEST_SIMD(64*1024*1024, find_nonzero_opt,  1+scale/16, SIZE-5);
	TESTC    (64*1024*1024, find_nonzero,      1+scale/16, SIZE-5);
	TEST_REP (64*1024*1024, find_nonzero_rep,  1+scale/16, SIZE-5);

	TEST2C     (12*1024*1024, find_nonzero_c,     80*scale/16, SIZE);
	TEST2_SIMD (12*1024*1024, find_nonzero_opt,   80*scale/16, SIZE);
	TEST2_SIMD2(12*1024*1024, find_nonzero_sse2o, 80*scale/16, SIZE);

	free(obuf);
	return 0;
}
#endif
