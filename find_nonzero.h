/** Helper to find length of block with zero bytes
 * (c) Kurt Garloff <kurt@garloff.de>, 2013
 * License: GNU GPL v2 or v3
 */

#ifndef _FIND_NONZERO_H
#define _FIND_NONZERO_H
#include <string.h>
#include <sys/types.h>

#if defined(__GLIBC__) && !defined(HAVE_FFS) && !defined(NOFFS)
# define HAVE_FFS
#endif

#ifdef HAVE_FFS
# define myffs(x) ffs(x)
# define myffsl(x) ffsl(x)
#elif defined(__SSE4_2__)
# include <smmintrin.h>
# define myffs(x) _mm_popcnt_u32(x^(~(-x)))
# ifdef __x86_64__
#  define myffsl(x) _mm_popcnt_u64(x^(~(-x)))
# else
#  define myffsl(x) _mm_popcnt_u32(x^(~(-x)))
# endif
#else
# define myffsl(x) myffs(x)
static inline int myffsl(unsigned long val)
{
	int i;
	for (i = 1; i <= sizeof(val)*8; ++i) {
		if (val & 0x01)
			return i;
		val >>= 1;
	}
	return 0;
}
#endif


/* FIXME: Is there no library function to find the first non-null byte?
 * Something like ffs() for a long byte array?
 * Here is an optimized version using SSE2 intrinsics, but there should be
 * be versions for NEON ... etc. */

#if defined(__SSE2__) & !defined(NO_SSE2)
#include <emmintrin.h>

#define HAVE_SIMD
/* This could be replaced by runtime detection later */
const static char have_simd = 1;

#define find_nonzero_opt find_nonzero_simd
/* This has been inspired by http://developer.amd.com/community/blog/faster-string-operations/ */
#ifdef __GNUC__
static size_t find_nonzero_simd(const unsigned char* blk, const size_t ln) __attribute__((noinline));
#endif
static size_t find_nonzero_simd(const unsigned char* blk, const size_t ln)
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

#else
#define find_nonzero_opt find_nonzero_c
/* This could be replaced by runtime detection later */
const static char have_simd = 0;
#endif
/** return length of zero bytes */
static size_t find_nonzero_c(const unsigned char* blk, const size_t ln)
{
	const unsigned long* ptr = (const unsigned long*)blk;
	const unsigned long* const bptr = ptr;
	for (; (size_t)(ptr-bptr) < ln/sizeof(*ptr); ++ptr)
		if (*ptr)
			return sizeof(unsigned long)*(ptr-bptr) + ((myffsl(*ptr)-1)>>3);
	return ln;
}

/* Generic version, does not require an aligned buffer blk */
inline static size_t find_nonzero(const unsigned char* blk, const size_t ln)
{
	const int off = ((unsigned long)blk) % 16;
	if (off) {
		size_t i;
		for (i = 0; i < 16-off; ++i)
			if (blk[i])
				return i;
		return i+(have_simd? find_nonzero_opt(blk+i, ln-i): find_nonzero_c(blk+i, ln-i));	} else
		return (have_simd? find_nonzero_opt(blk, ln): find_nonzero_c(blk, ln));
}


#endif
