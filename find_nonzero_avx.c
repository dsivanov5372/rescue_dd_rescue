/** find_nonzero_avx.c
  * AVX2 optimized search for non-zero bytes
  * taken straight from SSE2 and adapted to use AVX registers
  * Needs recent (2.23+) binutils to compile ...
  * (c) Kurt Garloff <kurt@garloff.de>, 2013
  * License: GNU GPL v2 or v3
  */

#define _GNU_SOURCE 1
#include "find_nonzero.h"
size_t find_nonzero_sse2(const unsigned char* blk, const size_t ln);

#ifdef __AVX2__
#if defined(__GNUC__) || defined(__llvm__)
# warning AVX2 version untested and runtime detection only with gcc 4.8+
#endif
#include <immintrin.h>
#include <stdio.h>
#if defined( __GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8))
char detect_avx() 
{
	return !!__builtin_cpu_supports("avx2");
}
#else
#include <signal.h>
#include <setjmp.h>
static jmp_buf no_avx_jmp;
static int avx_support;
__m256i _test_ymm;
void sigill_hdlr(int signo)
{
	avx_support = 0;
	longjmp(no_avx_jmp, 1);
}

char detect_avx()
{
	signal(SIGILL, sigill_hdlr);
	avx_support = 1;
	if (setjmp(no_avx_jmp) == 0) {
		char tst[4]; *tst = 0;
		volatile __m256i register _zero_ymm = _mm256_setzero_si256();
		_test_ymm = _zero_ymm;
		fprintf(stderr, "%s", tst);
	}
	signal(SIGILL, SIG_DFL);
	return avx_support;
}
#endif
/** AVX2 version for measuring the initial zero bytes of 32b aligned blk */
size_t find_nonzero_avx2(const unsigned char* blk, const size_t ln)
{
	static char firstrun = 1;
	char supports_avx = 0;
	if (firstrun) {
		firstrun = 0;
		supports_avx = detect_avx();
		if (!supports_avx)
			fprintf(stderr, "disabling AVX2\n");
	}
	if (!supports_avx)
		return find_nonzero_sse2(blk, ln);
	__m256i register ymm;
	const __m256i register zero = _mm256_setzero_si256();
	unsigned register eax;
	size_t i = 0;
	//asm(".p2align 5");
	for (; i < ln; i+= 32) {
		//ymm = _mm256_load_si256((__m256i*)(blk+i));
		ymm = _mm256_cmpeq_epi8(*(__m256i*)(blk+i), zero);
		eax = ~(_mm256_movemask_epi8(ymm));
		if (eax) 
			return i + myffs(eax)-1;
	}
	return ln;
}
#endif


