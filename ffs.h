/** ffs.h
 *
 * bit search functions
 */

#ifndef _FFS_H
#define _FFS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE 1
#include <string.h>
#include <sys/types.h>

#ifdef HAVE_FFS
# define myffs(x) ffs(x)
# define myffsl(x) ffsl(x)
#elif defined(__i386__) || defined(__x86_64)
# define myffs(x) (have_sse42? myffs_sse42(x): myffs_c(x))
# define myffsl(x) (have_sse42? myffsl_sse42(x): myffsl_c(x))
#else
# define myffs(x) myffs_c(x)
# define myffsl(x) myffsl_c(x)
#endif
#define myffs_c(x) myffsl_c(x)
/** Find first (lowest) bit set in word val, returns a val b/w 1 and __WORDSIZE, 0 if no bit is set */
static int myffsl_c(unsigned long val)
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
static int myflsl_c(unsigned long val)
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

#endif /* _FFS_H */
