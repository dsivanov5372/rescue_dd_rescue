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

/* x86: need to detect SSE2 at runtime, unless main program is compiled with -msse2 anyways */
#if defined(__i386__) && !defined(__x86_64__) && !defined(NO_SSE2) && (!defined(__SSE2__) || defined(IN_FINDZERO)) && !(defined(IN_FINDZERO) && !defined(__SSE2__))
#define HAVE_SSE2
#warning NEED TO DETECT SSE2 CAPABILITY AT RUNTIME
#define NEED_SIMD_RUNTIME_DETECTION
#include <signal.h>
#include <stdio.h>
static char have_simd;
static void ill_handler(int sig)
{
	have_simd = 0;
}

void probe_simd();
static inline void detect_simd()
{
	signal(SIGILL, ill_handler);
	signal(SIGSEGV, ill_handler);
	have_simd = 1;
	probe_simd();
	if (!have_simd)
		fprintf(stderr, "Disabling SSE2 ...\n");
	signal(SIGSEGV, SIG_DFL);
	signal(SIGILL, SIG_DFL);
}
#endif

/* Other sse2 cases ... */
#if !defined(HAVE_SSE2) && defined(__SSE2__)
#define HAVE_SSE2
/* No need for runtime detection here */
const static char have_simd = 1;
#endif

#ifdef __arm__
const static char have_simd = 1;
#endif

#if defined(HAVE_SSE2) || defined(__arm__)
#define HAVE_SIMD

/* FIXME: Is there no library function to find the first non-null byte?
 * Something like ffs() for a long byte array?
 * Here is an optimized version using SSE2 intrinsics, but there should be
 * be versions for NEON ... etc. */
#define find_nonzero_opt(ptr, ln) (have_simd? find_nonzero_simd(ptr, ln): find_nonzero_c(ptr, ln))
/* This has been inspired by http://developer.amd.com/community/blog/faster-string-operations/ */
size_t find_nonzero_simd(const unsigned char* blk, const size_t ln);
#else
#define find_nonzero_opt(ptr, ln) find_nonzero_c(ptr, ln)
/* No need for runtime detection here */
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
		int i;
		for (i = 0; i < 16-off; ++i)
			if (blk[i])
				return i;
		return i+find_nonzero_opt(blk+i, ln-i);
	} else
		return find_nonzero_opt(blk, ln);
}


#endif
