/** find_nonzero_arm64.c
 *
 * ARMv8 (aarch64) assembler optimized version to find first non-zero byte in a block
 * (c) Kurt Garloff <kurt@garloff.de>, GNU GPL v2 or v3
 */

#include "find_nonzero.h"

#if defined(__a64__)
/** ASM optimized version for ARMv8.
 * transform the armv6 ldmia form into ldp
 */
size_t find_nonzero_arm8(const unsigned char *blk, const size_t ln)
{
	/*
	if (!ln || *blk)
		return 0;
	 */
	register unsigned char* res;
	const register unsigned char* end = blk+ln;
	asm volatile(
	//".align 4			\n"
	"1:				\n"
	"	ldp x10,x11,[%0],#8!	\n"	/* #16 would do just as #8! ? */
	"	cmp x10, #0		\n"
	"	bne 2f			\n"
	"	ldp x12,x13,[%0],#8!	\n"	/* Should we use ldnp - don't cache ? */
	"	cmp x11, #0		\n"
	"	bne 3f			\n"
	"	cmp x12, #0		\n"
	"	bne 4f			\n"
	"	cmp x13, #0		\n"
	"	bne 5f			\n"
	"	cmp %0, %2		\n"	/* end? */
	"	blt 1b			\n"
	"	mov %0, %2		\n"	
	"	b 10f			\n"	/* exhausted search */
	"2:				\n"
	"	add %0, #8		\n"	/* First u32 is non-zero */
	"	mov x11, x10		\n"
	"3:				\n"
	"	sub %0, #8		\n"
	"	mov x12, x11		\n"
	"4:				\n"
	"	sub %0, #8		\n"
	"	mov x13, x12		\n"
	"5:				\n"
	"	sub %0, #8		\n"
//#ifndef __ARMEB__				/* Little endian bitmasks */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	"	tst x13, #0xff		\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff00	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff0000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff000000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff00000000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff0000000000\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff000000000000	\n"
#else
	"	tst x13, #0xff00000000000000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff000000000000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff0000000000\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff00000000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff000000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff0000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst x13, #0xff00	\n"
#endif
	"	bne 10f			\n"
	"	add %0, #1		\n"	
	"10:				\n"
	: "=r"(res)
	: "0"(blk), "r"(end)
	: "x10", "x11", "x12", "x13");
	return res-blk;
}
#else
#warning no point compiling this on non-ARM arch
#endif
