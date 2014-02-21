/** archdep.h */
/**
 * Abstract away the dependencies on specific features
 */

#ifndef _ARCHDEP_H
#define _ARCHDEP_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __x86_64__
#define HAVE_OPT
extern char have_avx2;
#define have_sse2 1
extern char have_sse42;
#define ARCH_DECLS char have_avx2; char have_sse42;
void probe_avx2(); void probe_sse42();
#define ARCH_DETECT have_avx2 = detect("avx2", probe_avx2); have_sse42 = detect("sse4.2", probe_sse42)
#define FIND_NONZERO_OPT(x,y) (have_avx2? find_nonzero_avx2(x,y): find_nonzero_sse2(x,y))
#define OPT_STR (have_avx2? "avx2": (have_sse42? "sse4.2": "sse2"))
#define OPT_STR2 (have_avx2? "avx2": "sse2")

#elif defined(__i386__)
#define HAVE_OPT
extern char have_avx2;
extern char have_sse2;
extern char have_sse42;
#define ARCH_DECLS char have_avx2; char have_sse42; char have_sse2;
void probe_avx2(); void probe_sse2(); void probe_sse42();
#define ARCH_DETECT have_avx2 = detect("avx2", probe_avx2); have_sse42 = detect("sse4.2", probe_sse42); have_sse2 = detect("sse2", probe_sse2)
#define FIND_NONZERO_OPT(x,y) (have_avx2? find_nonzero_avx2(x,y): (have_sse2? find_nonzero_sse2(x,y): find_nonzero_c(x,y)))
#define OPT_STR (have_avx2? "avx2": (have_sse42? "sse4.2": (have_sse2? "sse2": "c")))
#define OPT_STR2 (have_avx2? "avx2": (have_sse2? "sse2": "c"))

#elif defined(__arm__)
#define HAVE_OPT
#define have_arm  1
#define have_avx2 0
#define have_sse2 0
#define have_sse42 0
#define ARCH_DECLS
#define ARCH_DETECT do {} while (0)
#define FIND_NONZERO_OPT(x,y) find_nonzero_arm(x,y)
#define OPT_STR "arm"
#define OPT_STR2 "arm"

#else
#define have_ldmia 0
#define have_avx2 0
#define have_sse2 0
#define have_sse42 0
#define FIND_NONZERO_OPT(x,y) find_nonzero_c(x,y)
#define ARCH_DECLS
#define ARCH_DETECT do {} while (0)
#define OPT_STR "c"
#define OPT_STR2 "c"
#endif

#endif /* _ARCHDEP_H */
