#define _GNU_SOURCE 1
#include "find_nonzero.h"
size_t find_nonzero_sse2(const unsigned char* blk, const size_t ln);
#ifdef __AVX2__
#if defined(__GNUC__) || defined(__llvm__)
# warning AVX2 version untested and runtime detection only with gcc 4.8+
#endif
#include <immintrin.h>
/** AVX2 version for measuring the initial zero bytes of 32b aligned blk */
size_t find_nonzero_avx2(const unsigned char* blk, const size_t ln)
{
#if defined( __GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8))
	if (!(__builtin_cpu_supports("avx2")))
		return find_nonzero_sse2(blk, ln);
#endif
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


