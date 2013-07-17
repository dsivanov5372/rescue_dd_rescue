#ifndef _FIND_NONZERO_H
#define _FIND_NONZERO_H
#include <sys/types.h>

/* TODO: Can't we use library functions to find the first non-null byte?
 * There should be optimized versions, using SSE4.x insns e.g. */
#ifdef __SSE2__
#include <emmintrin.h>

static inline size_t find_nonzero(const unsigned char* blk, const size_t ln)
{
	__m128i xmm, zero = _mm_setzero_pi128();
	long register rax;
	int i;
	for (i = 0; i < ln; i+= 16) {
		xmm = _mm_load_si128((__mm128i*)(blk+i));
		_mm_cmpeq_epi8(xmm, zero);
		rax = _mm_movemask_epi8(xmm);
		if (rax)
			break;
	}
	return i;
}

#else
/** return length of zero bytes, rounded to sizeof(long) */
static inline size_t find_nonzero(const unsigned char* blk, const size_t ln)
{
	const unsigned long* ptr = (const unsigned long*)blk;
	const unsigned long* const bptr = ptr;
	while ((size_t)(ptr-bptr) < ln/sizeof(unsigned long))
		if (*(ptr++)) 
			return sizeof(unsigned long)*(--ptr-bptr);
	return ln;
}
#endif

#endif
