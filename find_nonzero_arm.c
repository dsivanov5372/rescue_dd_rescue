/** find_nonzero_arm.c
 *
 * ARM assembler optimized version to find first non-zero byte in a block
 * (c) Kurt Garloff <kurt@garloff.de>, GNU GPL v2 or v3
 */

#include "find_nonzero.h"

#if defined(__arm__) && !defined(__a64__)
/** ASM optimized version for ARM.
 * Inspired by Linaro's strlen() implementation; 
 * we don't even need NEON here, ldmia does the 3x speedup on Cortexes */
size_t find_nonzero_arm6(const unsigned char *blk, const size_t ln)
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
	"	ldmia %0!,{r2,r3}	\n"
	"	cmp r2, #0		\n"
	"	bne 2f			\n"
	"	ldmia %0!,{r4,r5}	\n"
	"	cmp r3, #0		\n"
	"	bne 3f			\n"
	"	cmp r4, #0		\n"
	"	bne 4f			\n"
	"	cmp r5, #0		\n"
	"	bne 5f			\n"
	"	cmp %0, %2		\n"	/* end? */
	"	blt 1b			\n"
	"	mov %0, %2		\n"	
	"	b 10f			\n"	/* exhausted search */
	"2:				\n"
	"	add %0, #4		\n"	/* First u32 is non-zero */
	"	mov r3, r2		\n"
	"3:				\n"
	"	sub %0, #4		\n"
	"	mov r4, r3		\n"
	"4:				\n"
	"	sub %0, #4		\n"
	"	mov r5, r4		\n"
	"5:				\n"
	"	sub %0, #4		\n"
//#ifndef __ARMEB__				/* Little endian bitmasks */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	"	tst r5, #0xff		\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff00		\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff0000	\n"
#else
	"	tst r5, #0xff000000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff0000	\n"
	"	bne 10f			\n"
	"	add %0, #1		\n"
	"	tst r5, #0xff00		\n"
#endif
	"	bne 10f			\n"
	"	add %0, #1		\n"	
	"10:				\n"
	: "=r"(res)
	: "0"(blk), "r"(end)
	: "r2", "r3", "r4", "r5");
	return res-blk;
}
#else
#warning no point compiling this on non-ARM 32bit arch
#endif
