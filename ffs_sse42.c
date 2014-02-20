/** ffs_sse42.c
 *
 * Implements ffs/ffsl() using SSE4.2 intrinsics --
 * just in case our libc does not provide ffs().
 */

#if defined(__SSE4_2__)
# include <smmintrin.h>
# define _myffs_sse42(x) _mm_popcnt_u32(x^(~(-x)))
# ifdef __x86_64__
#  define _myffsl_sse42(x) _mm_popcnt_u64(x^(~(-x)))
# else
#  define _myffsl_sse42(x) _mm_popcnt_u32(x^(~(-x)))
# endif

int myffs_sse42(unsigned long val)
{
	return _myffs_sse42(val);
}

int myffsl_sse42(unsigned long val)
{
	return _myffsl_sse42(val);

}
#endif

