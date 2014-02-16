/** Helper to find length of block with zero bytes
 * (c) Kurt Garloff <kurt@garloff.de>, 2013
 * License: GNU GPL v2 or v3
 */

#ifndef _FIND_NONZERO_H
#define _FIND_NONZERO_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <sys/types.h>

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
#else /* NOFFS */
# define myffsl(x) myffs(x)
/** Find first (lowest) bit set in word val, returns a val b/w 1 and __WORDSIZE, 0 if no bit is set */
static inline int myffsl(unsigned long val)
{
	int res = 1;
	if (!val)
		return 0;
#if __WORDSIZE == 64
	unsigned int vlo = val;
	unsigned int vhi = val >> 32;
	if (!vlo) {
		res += 32;
		vlo = vhi;
	}
#else
	unsigned int vlo = val;
#endif
	unsigned int mask = 0x0000ffff;
	unsigned int shift = 16;
	while (shift > 0) {
		if (!(vlo & mask)) {
			res += shift;
			vlo >>= shift;
		}
		shift >>= 1;
		mask >>= shift;
	}
	return res;
}
#endif
#if __BYTE_ORDER == __BIG_ENDIAN || defined(TEST)
/** Find last (highest) bit set in word val, returns a val b/w __WORDSIZE and 1, 0 if no bit is set */
static inline int myflsl(unsigned long val)
{
	int res = __WORDSIZE;
	if (!val)
		return 0;
#if __WORDSIZE == 64
	unsigned int vlo = val;
	unsigned int vhi = val >> 32;
	if (!vhi) {
		res -= 32;
		vhi = vlo;
	}
#else
	unsigned int vhi = val;
#endif
	unsigned int mask = 0xffff0000;
	unsigned int shift = 16;
	while (shift > 0) {
		if (!(vhi & mask)) {
			res -= shift;
			vhi <<= shift;
		}
		shift >>= 1;
		mask <<= shift;
	}
	return res;
}
#endif

/* x86: need to detect SSE2 at runtime, unless main program is compiled with -msse2 anyways */
#if defined(__i386__) && !defined(__x86_64__) && !defined(NO_SSE2) && (!defined(__SSE2__) || defined(IN_FINDZERO)) && !(defined(IN_FINDZERO) && !defined(__SSE2__))
#define HAVE_SSE2
#warning NEED TO DETECT SSE2 CAPABILITY AT RUNTIME
#define NEED_SIMD_RUNTIME_DETECTION
#include <signal.h>
#include <stdio.h>
#include <setjmp.h>
extern jmp_buf no_simd_jmp;
static sig_atomic_t have_simd;
static void ill_handler(int sig)
{
	have_simd = 0;
	longjmp(no_simd_jmp, 1);
}

void probe_simd();
static inline void detect_simd()
{
	signal(SIGILL, ill_handler);
	signal(SIGSEGV, ill_handler);
	if (setjmp(no_simd_jmp) == 0) {
		probe_simd();
		asm volatile("" : : : "memory");
		have_simd = 1;
	}
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

#ifdef HAVE_AVX2
#define find_nonzero_simd find_nonzero_avx2
#elif defined(HAVE_SSE2)
#define find_nonzero_simd find_nonzero_sse2
#elif defined(__arm__)
#define find_nonzero_simd find_nonzero_arm6
#endif

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
/** return number of bytes at beginning of blk that are all zero, assumes __WORDSIZE bit alignment */
static size_t find_nonzero_c(const unsigned char* blk, const size_t ln)
{
	const unsigned long* ptr = (const unsigned long*)blk;
	const unsigned long* const bptr = ptr;
	for (; (size_t)(ptr-bptr) < ln/sizeof(*ptr); ++ptr)
		if (*ptr)
#if __BYTE_ORDER == __BIG_ENDIAN
			return sizeof(unsigned long)*(ptr-bptr) + sizeof(long)-((myflsl(*ptr)+7)>>3);
#else
			return sizeof(unsigned long)*(ptr-bptr) + ((myffsl(*ptr)-1)>>3);
#endif
	return ln;
}

/** return number of bytes at beginning of blk that are all zero 
  * Generic version, does not require an aligned buffer blk or even ln ... */
inline static size_t find_nonzero(const unsigned char* blk, const size_t ln)
{
	if (!ln || *blk)
		return 0;
	const unsigned off = (-(unsigned char)(unsigned long)blk) & 0x1f;
	size_t remain = ln - off;
	size_t i;
	for (i = 0; i < off; ++i)
		if (blk[i])
			return i;
	int r2 = remain % 0x1f;
	size_t res = find_nonzero_opt(blk+off, remain-r2);
	if (!r2 || res != remain-r2)
		return off+res;
	for (i = off+remain; i < ln; ++i)
		if (blk[i])
			return i;
	return ln;
}


#endif
