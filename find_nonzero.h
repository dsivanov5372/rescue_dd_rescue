#ifndef _FIND_NONZERO_H
#define _FIND_NONZERO_H
#include <sys/types.h>

/* FIXME: Is there no library function to find the first non-null byte?
 * Here is an optimized version using SSE2 intrinsics, but there should be
 * be versions for NEON ... etc. */

#if defined(__SSE2__) & !defined(NO_SSE2)
#include <emmintrin.h>
#define HAVE_SIMD

#define find_nonzero find_nonzero_simd
static inline size_t find_nonzero_simd(const unsigned char* blk, const size_t ln)
{
	__m128i xmm, zero = _mm_setzero_si128();
	long register rax;
	size_t i;
	for (i = 0; i < ln; i+= 16) {
		xmm = _mm_load_si128((__m128i*)(blk+i));
		_mm_cmpeq_epi8(xmm, zero);
		rax = _mm_movemask_epi8(xmm);
		if (rax)
			break;
	}
	return i;
}

#else
#define find_nonzero find_nonzero_c
#endif
/** return length of zero bytes, rounded to sizeof(long) */
static inline size_t find_nonzero_c(const unsigned char* blk, const size_t ln)
{
	const unsigned long* ptr = (const unsigned long*)blk;
	const unsigned long* const bptr = ptr;
	while ((size_t)(ptr-bptr) < ln/sizeof(unsigned long))
		if (*(ptr++)) 
			return sizeof(unsigned long)*(--ptr-bptr);
	return ln;
}

#endif
