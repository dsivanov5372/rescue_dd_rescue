/** Helper to find length of block with zero bytes
 * (c) Kurt Garloff <kurt@garloff.de>, 2013
 * License: GNU GPL v2 or v3
 */

#ifndef _FIND_NONZERO_H
#define _FIND_NONZERO_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "ffs.h"

extern char cap_str[32];

char detect(const char* feature, void (*probe)(void))
{
#if defined( __GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)) && !defined(DO_OWN_DETECT)
	char cap = !!__builtin_cpu_supports(feature);
#else
	char cap = probe_procedure(probe);
#endif
	if (cap) {
		strcat(cap_str, feature);
		strcat(cap_str, " ");
	}
	return cap;
}

void detect_cpu_cap()
{
	*cap_str = 0;
	ARCH_DETECT
}


/* x86: need to detect SSE2 at runtime, unless main program is compiled with -msse2 anyways */
#if defined(__i386__) && !defined(__x86_64__) && !defined(NO_SSE2) && !defined(__SSE2__) 
#define HAVE_SSE2
#define NEED_SIMD_RUNTIME_DETECTION
#define TO_DETECT "sse2"
#define DET_FBCK ""
#endif
/* x86-64: Detect AVX2 */
#if defined(__x86_64__) && !defined(NO_AVX2) 
#define HAVE_AVX2
#define NEED_SIMD_RUNTIME_DETECTION
#define TO_DETECT "avx2"
#define DET_FBCK "sse2"
#endif

#ifdef NEED_SIMD_RUNTIME_DETECTION
#include <stdio.h>
extern const char* SIMD_STR;
static char FNZ_SIMD[32];
extern char have_simd;
#if defined( __GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)) && !defined(DO_OWN_DETECT)
#ifdef IN_FINDZERO
#warning Using SSE2/AVX2 runtime detection from gcc 4.8+
#endif
static inline void detect_simd()
{
	if (__builtin_cpu_supports(TO_DETECT)) {
		SIMD_STR = TO_DETECT;
		have_simd = 1;
	} else {
		SIMD_STR = DET_FBCK;
		have_simd = 0;
	}
	sprintf(FNZ_SIMD, "find_nonzero_%s", *SIMD_STR? SIMD_STR: "c");
}
#else
#ifdef IN_FINDZERO
#warning Trapping SIGILL for SSE2/AVX2 runtime detection
#endif
#include <signal.h>
#include <setjmp.h>
static jmp_buf no_simd_jmp;
static void ill_handler(int sig)
{
	have_simd = 0;
	longjmp(no_simd_jmp, 1);
}

#ifdef __x86_64__
void probe_simd_avx2();
#else
void probe_simd_sse2();
#endif
static inline void detect_simd()
{
	signal(SIGILL, ill_handler);
	signal(SIGSEGV, ill_handler);
	if (setjmp(no_simd_jmp) == 0) {
#ifdef __x86_64__
		probe_simd_avx2();
#else
		probe_simd_sse2();
#endif
		asm volatile("" : : : "memory");
		have_simd = 1;
		SIMD_STR = TO_DETECT;
	} else {
		have_simd = 0;
		SIMD_STR = DET_FBCK;
	}
	signal(SIGSEGV, SIG_DFL);
	signal(SIGILL, SIG_DFL);
	sprintf(FNZ_SIMD, "find_nonzero_%s", *SIMD_STR? SIMD_STR: "c");
}
#endif
#endif

/* Other sse2 cases ... */
#if !defined(HAVE_SSE2) && !defined(HAVE_AVX2) && defined(__SSE2__) && !defined(NO_SSE2)
#define HAVE_SSE2
/* No need for runtime detection here */
const static char have_simd = 1;
#define SIMD_STR "sse2"
#define FNZ_SIMD "find_nonzero_sse2"
#endif

#ifdef __arm__
const static char have_simd = 1;
#define SIMD_STR "ldmia"
#define FNZ_SIMD "find_nonzero_ldmia"
#endif

#if defined(HAVE_SSE2) || defined(__arm__) || defined(HAVE_AVX2)
#define HAVE_SIMD

#ifdef HAVE_AVX2
#define find_nonzero_simd find_nonzero_avx2
#define find_nonzero_fbck find_nonzero_sse2
size_t find_nonzero_fbck(const unsigned char* blk, const size_t ln);
#elif defined(HAVE_SSE2)
#define find_nonzero_simd find_nonzero_sse2
#define find_nonzero_fbck find_nonzero_c
#elif defined(__arm__)
#define find_nonzero_simd find_nonzero_arm6
#define find_nonzero_fbck find_nonzero_c
#endif

/* FIXME: Is there no library function to find the first non-null byte?
 * Something like ffs() for a long byte array?
 * Here is an optimized version using SSE2 intrinsics, but there should be
 * be versions for NEON ... etc. */
#define find_nonzero_opt(ptr, ln) (have_simd? find_nonzero_simd(ptr, ln): find_nonzero_fbck(ptr, ln))
/* This has been inspired by http://developer.amd.com/community/blog/faster-string-operations/ */
size_t find_nonzero_simd(const unsigned char* blk, const size_t ln);

#else /* NO SIMD VERSION VAILABLE */

#define SIMD_STR ""
#define FNZ_SIMD "find_nonzero_c"

#define find_nonzero_opt(ptr, ln) find_nonzero_c(ptr, ln)
/* No need for runtime detection here */
const static char have_simd = 0;
#endif

#if !defined(__x86_64__) || defined(TEST)
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
#endif

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
