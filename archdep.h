/** archdep.h */
/**
 * Abstract away the dependencies on specific features
 */

#ifndef _ARCHDEP_H
#define _ARCHDEP_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(__x86_64__) || defined(__i386__)
#define HAVE_OPT

#ifdef __i386__
extern char have_sse2;
void probe_sse2();
#define ARCH_DECL_386 char have_sse2;
#define ARCH_DETECT_386 ; have_sse2 = detect("sse2", probe_sse2)
#else /* x86_64 */
#define have_sse2 1
#define ARCH_DECL_386
#define ARCH_DETECT_386
#endif

#ifdef NO_SSE42	/* compiler does not support -msse4.2 (nor -mavx2) */
#define have_avx2 0
#define have_sse42 0
#define have_rdrand 0
#define have_aesni 0
#define ARCH_DETECT do {} while (0)
#define ARCH_DECLS ARCH_DECL_386

#elif defined(NO_AVX2) /* compiler does not support -mavx2 */
#define have_avx2 0
#define have_rdrand 0
#define have_aesni 0
extern char have_sse42;
void probe_sse42();
#define ARCH_DECLS char have_sse42; ARCH_DECL_386
#define ARCH_DETECT have_sse42 = detect("sse4.2", probe_sse42) ARCH_DETECT_386

#else /* compiler supports both extensions */
extern char have_avx2;
extern char have_sse42;

#ifdef NO_RDRND	/* SSE42 and AVX2 but no rdrand+aesni */
#define have_rdrand 0
#define have_aesni 0
void probe_avx2(); void probe_sse42();
#define ARCH_DECLS char have_avx2; char have_sse42; ARCH_DECL_386
#define ARCH_DETECT have_avx2 = detect("avx2", probe_avx2); have_sse42 = detect("sse4.2", probe_sse42) \
			ARCH_DETECT_386

#else /* Probe everything */
extern char have_rdrand;
extern char have_aesni;
void probe_avx2(); void probe_sse42(); void probe_rdrand(); void probe_aesni();
#define ARCH_DECLS char have_aesni; char have_rdrand; char have_avx2; char have_sse42; ARCH_DECL_386
#define ARCH_DETECT have_avx2 = detect("avx2", probe_avx2); have_sse42 = detect("sse4.2", probe_sse42); \
			have_rdrand = detect2("rdrand", probe_rdrand); have_aesni = detect2("aes", probe_aesni) \
			ARCH_DETECT_386
#endif	/* RDRND / AESNI */
#endif	/* SSE42 / AVX2 */

#define FIND_NONZERO_OPT(x,y) (have_avx2? find_nonzero_avx2(x,y): (have_sse2? find_nonzero_sse2(x,y): find_nonzero_c(x,y)))
#define OPT_STR (have_avx2? "avx2": (have_sse42? "sse4.2": (have_sse2? "sse2": "c")))
#define OPT_STR2 (have_avx2? "avx2": (have_sse2? "sse2": "c"))

#elif defined(__arm__)
#define HAVE_OPT
#define have_arm  1
#define have_avx2 0
#define have_sse2 0
#define have_sse42 0
#define have_aesni 0
#define ARCH_DECLS
#define ARCH_DETECT do {} while (0)
#define FIND_NONZERO_OPT(x,y) find_nonzero_arm6(x,y)
#define OPT_STR "arm6"
#define OPT_STR2 "arm6"

#elif defined(__aarch64__)
#define HAVE_OPT
#define have_arm  1
#define have_avx2 0
#define have_sse2 0
#define have_sse42 0
#define have_aesni 0
#define ARCH_DECLS
#define ARCH_DETECT do {} while (0)
#define FIND_NONZERO_OPT(x,y) find_nonzero_arm8(x,y)
#define OPT_STR "arm8"
#define OPT_STR2 "arm8"

#else	/* other CPU arch */
#define have_ldmia 0
#define have_avx2 0
#define have_sse2 0
#define have_sse42 0
#define have_aesni 0
#define FIND_NONZERO_OPT(x,y) find_nonzero_c(x,y)
#define ARCH_DECLS
#define ARCH_DETECT do {} while (0)
#define OPT_STR "c"
#define OPT_STR2 "c"
#endif

#endif /* _ARCHDEP_H */
