/**
 * aes_arm32.c
 *
 * Here we transform the rijndael C implementation
 * (rijndael-alg-fst.c from Vincent Rijmen, Antoon Bosselaers
 *  and Paulo Barreto, under the Public Domain)
 * into an AArch64 optimized version, taking advantage of the
 * ARMv8 crypto extensions.
 *
 * (C) Kurt Garloff <kurt@garloff.de>, 8-9/2015
 * License: GNU GPL v2 or v3 (at your option)
 */

#include "aes_c.h"
#include "aes_arm64.h"
#include "secmem.h"

#include <string.h>
#include <assert.h>

#define MAXKC (256 / 32)
#define MAXKB (256 / 8)
#define MAXNR 14

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

int AES_ARM8_KeySetupEnc(u32 rk[/*4*(Nr + 1)*/], const u8 cipherKey[], int keyBits, int rounds);
int AES_ARM8_KeySetupDec(u32 rk[/*4*(Nr + 1)*/], const u8 cipherKey[], int keyBits, int rounds);
void AES_ARM8_Encrypt(const u8 *rkeys/*[16*(Nr + 1)]*/, uint Nr, const u8 pt[16], u8 ct[16]);
void AES_ARM8_Decrypt(const u8 *rkeys/*[16*(Nr + 1)]*/, uint Nr, const u8 ct[16], u8 pt[16]);


/*
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


static inline u32 ror32_8(u32 in)
{
	asm volatile (
	"	ror	%r[out], %r[in], #8	\n"
	: [out] "=r"(in)
	: [in] "0"(in)
	);
	return in;
}

static inline u32 aes_sbox(u32 in)
{
	u32 ret;
	asm volatile (
	"	vdup 	q1, %r[in]		\n"
	"	vmovi	q0, #0			\n"
	"	aese.8	q0, q1			\n"
	"	vumov	%r[out], q0[0]		\n"
	: [out] "=r"(ret)
	: [in] "r"(in)
	: "q0", "q1"
	);
	return ret;
}

int AES_ARM8_KeySetupEnc(u32 rk[/*4*(Nr + 1)*/], const u8 cipherKey[], int keyBits, int rounds)
{
	static u8 const rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
		0x1b, 0x36, 0x6c, 0xd8 };
	const int keyln32 = keyBits/32;
	int i;
	memcpy(rk, cipherKey, keyBits/8);
	switch (keyBits) {
		case 128:
			if (!rounds)
				rounds = 10;
			break;
		case 192:
			if (!rounds)
				rounds = 12;
			break;
		case 256:
			if (!rounds)
				rounds = 14;
			break;
		default:
			return 0;
	}
	for (i = 0; i < sizeof(rcon); ++i) {
		const u32* rki = rk+i*keyln32;
		u32* rko = rk+(i+1)*keyln32;

		rko[0] = ror32_8(aes_sbox(rki[keyln32-1])) ^ rcon[i] ^ rki[0];
		rko[1] = rko[0] ^ rki[1];
		rko[2] = rko[1] ^ rki[2];
		rko[3] = rko[2] ^ rki[3];
		
		if (keyBits == 192) {
			if (3*(i+1)/2 >= rounds)
				return rounds;
			rko[4] = rko[3] ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
		} else if (keyBits == 256) {
			if (2*i+2 >= rounds)
				return rounds;
			rko[4] = aes_sbox(rko[3]) ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
			rko[6] = rko[5] ^ rki[6];
			rko[7] = rko[6] ^ rki[7];
		} else if (keyBits == 128) {
			if (i+1 >= rounds)
				return rounds;
		} 
	}
	return 0;
}

inline void AES_ARM8_EKey_DKey(const u32* ekey,
			   u32* dkey,
			   int rounds)
{
	int i;
	memcpy(dkey, ekey+rounds*4, 16);
	for (i = 1, rounds--; rounds > 0; i++, rounds--) {
		asm volatile(
		"	vld1.8		{q0}, %1	\n"
		"	aesimc.8	q1, q0		\n"
		"	vst1.8		{q1}, %0	\n"
		: "=Q"(dkey[i*4])
		: "Q"(ekey[rounds*4])
		: "q0", "q1"
		);
	}
	memcpy(dkey+4*i, ekey, 16);
}

/**
 * Expand the cipher key into the decryption key schedule.
 *
 * @return	the number of rounds for the given cipher key size.
 */
int AES_ARM8_KeySetupDec(u32 rk[/*4*(Nr + 1)*/], const u8 cipherKey[], int keyBits, int rounds)
{
	/* expand the cipher key: */
	int Nr = AES_ARM8_KeySetupEnc((u32*)crypto->xkeys, cipherKey, keyBits, rounds);
	AES_ARM8_EKey_DKey((u32*)crypto->xkeys, rk, Nr);
	return Nr;
}

void AES_ARM8_Encrypt(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 pt[16], u8 ct[16])
{
	u8 *rk = (u8*)rkeys;
	uint dummy1;
	asm volatile(
	"	vld1.8	{q0}, [%[pt]]		\n"
	"	vld1.8	{q1, q2}, [%[rk]]!	\n"
	"//	veor	q0, q0, q1		\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	".align 4				\n"
	"1:					\n"
	"	aese.8	q0, q1			\n"
	"	aesmc.8	q0, q0			\n"
	"	vld1.8	{q1}, [%[rk]]!		\n"
	"	beq	2f			\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	"	aese.8	q0, q2			\n"
	"	aesmc.8	q0, q0			\n"
	"	vld1.8	{q2}, [%[rk]]!		\n"
	"	bpl	1b			\n"
	"					\n"
	"	aese.8	q0, q1			\n"
	"	veor	q0, q0, q2		\n"	
	"	b	3f			\n"
	"2:					\n"
	"	aese.8	q0, q2			\n"
	"	veor	q0, q0, q1		\n"	
	"3:					\n"
	"	vst1.8	{q0}, [%[ct]]		\n"
	: [rk] "=r" (rk), [nr] "=r" (dummy1)
	: "0" (rkeys), "1" (Nr), [pt] "r" (pt), [ct] "r" (ct)
	: "q0", "q1", "q2", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}



void AES_ARM8_Decrypt(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 ct[16], u8 pt[16])
{
	u8 *rk = (u8*)rkeys;
	uint dummy1;
	asm volatile(
	"	vld1.8	{q0}, [%[ct]]		\n"
	"	vld1.8	{q1, q2}, [%[rk]]!	\n"
	"//	veor	q0, q0, q1		\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	".align 4				\n"
	"1:					\n"
	"	aesd.8	q0, q1			\n"
	"	aesimc.8	q0, q0		\n"
	"	vld1.8	{q1}, [%[rk]]!		\n"
	"	beq	2f			\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	"	aesd.8	q0, q2			\n"
	"	aesimc.8	q0, q0		\n"
	"	vld1.8	{q2}, [%[rk]]!		\n"
	"	bpl	1b			\n"
	"					\n"
	"	aesd.8	q0, q1			\n"
	"	veor	q0, q0, q2		\n"
	"	b	3f			\n"
	"2:					\n"
	"	aesd.8	q0, q2			\n"
	"	veor	q0, q0, q1		\n"
	"3:					\n"
	"	vst1.8	{q0}, [%[pt]]		\n"
	: [rk] "=r" (rk), [nr] "=r" (dummy1)
	: "0" (rkeys), "1" (Nr), [ct] "r" (ct), [pt] "r" (pt)
	: "q0", "q1", "q2", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}

void AES_ARM8_Encrypt4(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 pt[64], u8 ct[64])
{
	u8 *rk = (u8*)rkeys;
	uint dummy1;
	asm volatile(
	"	ld1	{v2.16b-v5.16b}, [%[pt]]	\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"//	prfm	PLDL1STRM, [%[pt],#64]	\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	".align 4				\n"
	"1:					\n"
	"	aese.8	v2.16b, v0.16b		\n"
	"	aese.8	v3.16b, v0.16b		\n"
	"	aese.8	v4.16b, v0.16b		\n"
	"	aese.8	v5.16b, v0.16b		\n"
	"	aesmc.8	v2.16b, v2.16b		\n"
	"	aesmc.8	v3.16b, v3.16b		\n"
	"	aesmc.8	v4.16b, v4.16b		\n"
	"	aesmc.8	v5.16b, v5.16b		\n"
	"	ld1	{v0.4s}, [%[rk]], #16	\n"
	"	beq	2f			\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	"	aese.8	v2.16b, v1.16b		\n"
	"	aese.8	v3.16b, v1.16b		\n"
	"	aese.8	v4.16b, v1.16b		\n"
	"	aese.8	v5.16b, v1.16b		\n"
	"	aesmc.8	v2.16b, v2.16b		\n"
	"	aesmc.8	v3.16b, v3.16b		\n"
	"	aesmc.8	v4.16b, v4.16b		\n"
	"	aesmc.8	v5.16b, v5.16b		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	bpl	1b			\n"
	"					\n"
	"	aese.8	v2.16b, v0.16b		\n"
	"	aese.8	v3.16b, v0.16b		\n"
	"	aese.8	v4.16b, v0.16b		\n"
	"	aese.8	v5.16b, v0.16b		\n"
	"	veor	v2.16b, v2.16b, v1.16b	\n"	
	"	veor	v3.16b, v3.16b, v1.16b	\n"	
	"	veor	v4.16b, v4.16b, v1.16b	\n"	
	"	veor	v5.16b, v5.16b, v1.16b	\n"	
	"	b	3f			\n"
	"2:					\n"
	"	aese.8	v2.16b, v1.16b		\n"
	"	aese.8	v3.16b, v1.16b		\n"
	"	aese.8	v4.16b, v1.16b		\n"
	"	aese.8	v5.16b, v1.16b		\n"
	"	veor	v2.16b, v2.16b, v0.16b	\n"	
	"	veor	v3.16b, v3.16b, v0.16b	\n"	
	"	veor	v4.16b, v4.16b, v0.16b	\n"	
	"	veor	v5.16b, v5.16b, v0.16b	\n"	
	"3:					\n"
	"	st1	{v2.16b-v5.16b}, [%[ct]]	\n"
	: [rk] "=r" (rk), [nr] "=r" (dummy1)
	: "0" (rkeys), "1" (Nr), [pt] "r" (pt), [ct] "r" (ct)
	: "q0", "q1", "q2", "q3", "q4", "q5", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}

void AES_ARM8_Decrypt4(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 ct[64], u8 pt[64])
{
	u8 *rk = (u8*)rkeys;
	uint dummy1;
	asm volatile(
	"	ld1	{v2.16b-v5.16b}, [%[ct]]	\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"//	prfm	PLDL1STRM, [%[ct],#64]	\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	".align 4				\n"
	"1:					\n"
	"	aesd.8	v2.16b, v0.16b		\n"
	"	aesd.8	v3.16b, v0.16b		\n"
	"	aesd.8	v4.16b, v0.16b		\n"
	"	aesd.8	v5.16b, v0.16b		\n"
	"	aesimc.8	v2.16b, v2.16b		\n"
	"	aesimc.8	v3.16b, v3.16b		\n"
	"	aesimc.8	v4.16b, v4.16b		\n"
	"	aesimc.8	v5.16b, v5.16b		\n"
	"	ld1	{v0.4s}, [%[rk]], #16	\n"
	"	beq	2f			\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	"	aesd.8	v2.16b, v1.16b		\n"
	"	aesd.8	v3.16b, v1.16b		\n"
	"	aesd.8	v4.16b, v1.16b		\n"
	"	aesd.8	v5.16b, v1.16b		\n"
	"	aesimc.8	v2.16b, v2.16b		\n"
	"	aesimc.8	v3.16b, v3.16b		\n"
	"	aesimc.8	v4.16b, v4.16b		\n"
	"	aesimc.8	v5.16b, v5.16b		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	bpl	1b			\n"
	"					\n"
	"	aesd.8	v2.16b, v0.16b		\n"
	"	aesd.8	v3.16b, v0.16b		\n"
	"	aesd.8	v4.16b, v0.16b		\n"
	"	aesd.8	v5.16b, v0.16b		\n"
	"	veor	v2.16b, v2.16b, v1.16b	\n"
	"	veor	v3.16b, v3.16b, v1.16b	\n"
	"	veor	v4.16b, v4.16b, v1.16b	\n"
	"	veor	v5.16b, v5.16b, v1.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aesd.8	v2.16b, v1.16b		\n"
	"	aesd.8	v3.16b, v1.16b		\n"
	"	aesd.8	v4.16b, v1.16b		\n"
	"	aesd.8	v5.16b, v1.16b		\n"
	"	veor	v2.16b, v2.16b, v0.16b	\n"
	"	veor	v3.16b, v3.16b, v0.16b	\n"
	"	veor	v4.16b, v4.16b, v0.16b	\n"
	"	veor	v5.16b, v5.16b, v0.16b	\n"
	"3:					\n"
	"	st1	{v2.16b-v5.16b}, [%[pt]]	\n"
	: [rk] "=r" (rk), [nr] "=r" (dummy1)
	: "0" (rkeys), "1" (Nr), [ct] "r" (ct), [pt] "r" (pt)
	: "q0", "q1", "q2", "q3", "q4", "q5", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}

void AES_ARM8_Encrypt_CTR(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 pt[16], u8 ct[16], u8 iv[16])
{
	u8 *rk = (u8*)rkeys;
	uint dummy1;
	unsigned long long inc1[] = {0ULL, 1ULL};
	asm volatile(
	"	ld1	{v2.16b}, [%[iv]]	\n"
	"	ld1	{v4.2d}, %[inc]	\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"	ld1	{v3.16b}, [%[pt]]	\n"
	"	rev64	v2.16b, v2.16b		\n"
	"	add	v4.2d, v2.2d, v4.2d	\n"
	"	rev64	v2.16b, v2.16b		\n"
	"	rev64	v4.16b, v4.16b		\n"
	"	st1	{v4.16b}, [%[iv]]	\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	".align 4				\n"
	"1:					\n"
	"	aese.8	v2.16b, v0.16b		\n"
	"	aesmc.8	v2.16b, v2.16b		\n"
	"	ld1	{v0.4s}, [%[rk]], #16	\n"
	"	beq	2f			\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	"	aese.8	v2.16b, v1.16b		\n"
	"	aesmc.8	v2.16b, v2.16b		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	bpl	1b			\n"
	"					\n"
	"	aese.8	v2.16b, v0.16b		\n"
	"	veor	v2.16b, v2.16b, v1.16b	\n"	
	"	b	3f			\n"
	"2:					\n"
	"	aese.8	v2.16b, v1.16b		\n"
	"	veor	v2.16b, v2.16b, v0.16b	\n"	
	"3:					\n"
	"	veor	v3.16b, v3.16b, v2.16b	\n"	
	"	st1	{v3.16b}, [%[ct]]	\n"
	: [rk] "=r" (rk), [nr] "=r" (dummy1)
	: "0" (rkeys), "1" (Nr), [pt] "r" (pt), [ct] "r" (ct), [iv] "r" (iv), [inc] "Q" (inc1)
	: "q0", "q1", "q2", "q3", "q4", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}

void AES_ARM8_Encrypt4_CTR(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 pt[64], u8 ct[64], u8 iv[16])
{
	u8 *rk = (u8*)rkeys;
	uint dummy1;
	unsigned long long inc1[] = {0ULL, 1ULL};
	asm volatile(
	"	vld1	{v2.16b}, [%[iv]]	\n"
	"	vld1	{v10.2d}, %[inc]	\n"
	"	vld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"	vld1	{v6.16b-v9.16b}, [%[pt]]\n"
	"	vrev64	v2.16b, v2.16b		\n"
	"	vadd	v3.2d, v2.2d, v10.2d	\n"
	"	vadd	v4.2d, v3.2d, v10.2d	\n"
	"	vadd	v5.2d, v4.2d, v10.2d	\n"
	"	vadd	v10.2d, v5.2d, v10.2d	\n"
	"	vrev64	v2.16b, v2.16b		\n"
	"	vrev64	v3.16b, v3.16b		\n"
	"	vrev64	v4.16b, v4.16b		\n"
	"	vrev64	v5.16b, v5.16b		\n"
	"	vrev64	v10.16b, v10.16b	\n"
	"	vst1	{v10.16b}, [%[iv]]	\n"
	"	//prfm	PLDL1STRM, [%[pt],#64]	\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	".align 4				\n"
	"1:					\n"
	"	aese.8	v2.16b, v0.16b		\n"
	"	aese.8	v3.16b, v0.16b		\n"
	"	aese.8	v4.16b, v0.16b		\n"
	"	aese.8	v5.16b, v0.16b		\n"
	"	aesmc.8	v2.16b, v2.16b		\n"
	"	aesmc.8	v3.16b, v3.16b		\n"
	"	aesmc.8	v4.16b, v4.16b		\n"
	"	aesmc.8	v5.16b, v5.16b		\n"
	"	vld1	{v0.4s}, [%[rk]], #16	\n"
	"	beq	2f			\n"
	"	subs	%r[nr], %r[nr], #2	\n"
	"	aese.8	v2.16b, v1.16b		\n"
	"	aese.8	v3.16b, v1.16b		\n"
	"	aese.8	v4.16b, v1.16b		\n"
	"	aese.8	v5.16b, v1.16b		\n"
	"	aesmc.8	v2.16b, v2.16b		\n"
	"	aesmc.8	v3.16b, v3.16b		\n"
	"	aesmc.8	v4.16b, v4.16b		\n"
	"	aesmc.8	v5.16b, v5.16b		\n"
	"	vld1	{v1.4s}, [%[rk]], #16	\n"
	"	bpl	1b			\n"
	"					\n"
	"	aese.8	v2.16b, v0.16b		\n"
	"	aese.8	v3.16b, v0.16b		\n"
	"	aese.8	v4.16b, v0.16b		\n"
	"	aese.8	v5.16b, v0.16b		\n"
	"	veor	v2.16b, v2.16b, v1.16b	\n"	
	"	veor	v3.16b, v3.16b, v1.16b	\n"	
	"	veor	v4.16b, v4.16b, v1.16b	\n"	
	"	veor	v5.16b, v5.16b, v1.16b	\n"	
	"	b	3f			\n"
	"2:					\n"
	"	aese.8	v2.16b, v1.16b		\n"
	"	aese.8	v3.16b, v1.16b		\n"
	"	aese.8	v4.16b, v1.16b		\n"
	"	aese.8	v5.16b, v1.16b		\n"
	"	veor	v2.16b, v2.16b, v0.16b	\n"	
	"	veor	v3.16b, v3.16b, v0.16b	\n"	
	"	veor	v4.16b, v4.16b, v0.16b	\n"	
	"	veor	v5.16b, v5.16b, v0.16b	\n"	
	"3:					\n"
	"	veor	v6.16b, v6.16b, v2.16b	\n"	
	"	veor	v7.16b, v7.16b, v3.16b	\n"	
	"	veor	v8.16b, v8.16b, v4.16b	\n"	
	"	veor	v9.16b, v9.16b, v5.16b	\n"	
	"	vst1	{v6.16b-v9.16b}, [%[ct]]	\n"
	: [rk] "=r" (rk), [nr] "=r" (dummy1)
	: "0" (rkeys), "1" (Nr), [pt] "r" (pt), [ct] "r" (ct), [iv] "r" (iv), [inc] "Q" (inc1)
	: "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}



#define DECL_KEYSETUP(MODE, BITS)	\
void AES_ARM8_KeySetup_##BITS##_##MODE(const uchar *usrkey, uchar *rkeys, uint rounds)	\
{											\
	AES_ARM8_KeySetup##MODE((u32*)rkeys, usrkey, BITS, rounds);			\
}

DECL_KEYSETUP(Enc, 128);
DECL_KEYSETUP(Dec, 128);
DECL_KEYSETUP(Enc, 192);
DECL_KEYSETUP(Dec, 192);
DECL_KEYSETUP(Enc, 256);
DECL_KEYSETUP(Dec, 256);


#define AES_ARM8_Encrypt_Blk AES_ARM8_Encrypt
#define AES_ARM8_Decrypt_Blk AES_ARM8_Decrypt
#define AES_ARM8_Encrypt_4Blk AES_ARM8_Encrypt4
#define AES_ARM8_Decrypt_4Blk AES_ARM8_Decrypt4
#define AES_ARM8_Encrypt_Blk_CTR AES_ARM8_Encrypt_CTR
#define AES_ARM8_Encrypt_4Blk_CTR AES_ARM8_Encrypt4_CTR

#define CLR_NEON3			\
	asm volatile(			\
	" veor q0,q0,q0		\n"	\
	" veor q1,q1,q1		\n"	\
	" veor q2,q2,q2		\n"	\
	::: "q0", "q1", "q2")

#define CLR_NEON6			\
	asm volatile(			\
	" veor q0,q0,q0		\n"	\
	" veor q1,q1,q1		\n"	\
	" veor q2,q2,q2		\n"	\
	" veor q3,q3,q3		\n"	\
	" veor q4,q4,q4		\n"	\
	" veor q5,q5,q5		\n"	\
	::: "q0", "q1", "q2", "q3", "q4", "q5")

#define CLR_NEON11			\
	asm volatile(			\
	" veor q0,q0,q0		\n"	\
	" veor q1,q1,q1		\n"	\
	" veor q2,q2,q2		\n"	\
	" veor q3,q3,q3		\n"	\
	" veor q4,q4,q4		\n"	\
	" veor q5,q5,q5		\n"	\
	" veor q6,q6,q6		\n"	\
	" veor q7,q7,q7		\n"	\
	" veor q8,q8,q8		\n"	\
	" veor q9,q9,q9		\n"	\
	" veor q10,q10,q10	\n"	\
	::: "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10")

int  AES_ARM8_ECB_Encrypt(const uchar* rkeys, uint rounds, uchar *iv, uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	int r = AES_Gen_ECB_Enc4(AES_ARM8_Encrypt_4Blk, AES_ARM8_Encrypt_Blk, 
				rkeys, rounds, pad, in, out, len, olen);
	CLR_NEON6;
	return r;
}
int  AES_ARM8_ECB_Decrypt(const uchar* rkeys, uint rounds, uchar *iv, uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	int r = AES_Gen_ECB_Dec4(AES_ARM8_Decrypt_4Blk, AES_ARM8_Decrypt_Blk, 
				rkeys, rounds, pad, in, out, len, olen);
	CLR_NEON6;
	return r;
}

int  AES_ARM8_CBC_Encrypt(const uchar* rkeys, uint rounds, uchar *iv, uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	int r = AES_Gen_CBC_Enc(AES_ARM8_Encrypt_Blk, 
				rkeys, rounds, iv, pad, in, out, len, olen);
	CLR_NEON3;
	return r;
}
int  AES_ARM8_CBC_Decrypt(const uchar* rkeys, uint rounds, uchar *iv, uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	int r = AES_Gen_CBC_Dec4(AES_ARM8_Decrypt_4Blk, AES_ARM8_Decrypt_Blk, 
				rkeys, rounds, iv, pad, in, out, len, olen);
	CLR_NEON6;
	return r;
}

int  AES_ARM8_CTR_Crypt(const uchar* rkeys, uint rounds, uchar *ctr, uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	*olen = len;
	int r = AES_Gen_CTR_Crypt_Opt(AES_ARM8_Encrypt_4Blk_CTR, AES_ARM8_Encrypt_Blk_CTR, 
				     rkeys, rounds, ctr, in, out, len);
	CLR_NEON11;
	return r;
}

/* Double de/encryption methods */

#include "sha256.h"

static inline
void AES_ARM8_KeySetupX2_Bits_Enc(const uchar *usrkey, uchar *rkeys, uint rounds, uint bits)
{
	assert(0 == rounds%2);
	AES_ARM8_KeySetupEnc((u32*)rkeys, usrkey, bits, rounds/2);
	/* Second half: Calc sha256 from usrkey and expand */
	hash_t hv;
	sha256_init(&hv);
	sha256_calc(usrkey, bits/8, bits/8, &hv);
	sha256_beout(crypto->userkey2, &hv);
	sha256_init(&hv);
	AES_ARM8_KeySetupEnc((u32*)(rkeys+16+8*rounds), crypto->userkey2, bits, rounds/2);
	//memset(crypto->usrkey2, 0, 32);
	asm("":::"memory");
}

static inline
void AES_ARM8_KeySetupX2_Bits_Dec(const uchar* usrkey, uchar *rkeys, uint rounds, uint bits)
{
	assert(0 == rounds%2);
	AES_ARM8_KeySetupDec((u32*)rkeys, usrkey, bits, rounds/2);
	/* Second half: Calc sha256 from usrkey and expand */
	hash_t hv;
	sha256_init(&hv);
	sha256_calc(usrkey, bits/8, bits/8, &hv);
	sha256_beout(crypto->userkey2, &hv);
	sha256_init(&hv);
	AES_ARM8_KeySetupDec((u32*)(rkeys+16+8*rounds), crypto->userkey2, bits, rounds/2);
	//memset(crypto->userkey2, 0, 32);
	asm("":::"memory");
}

#define DECL_KEYSETUP2(MODE, BITS)	\
void AES_ARM8_KeySetupX2_##BITS##_##MODE(const uchar *usrkey, uchar *rkeys, uint rounds)	\
{											\
	AES_ARM8_KeySetupX2_Bits_##MODE(usrkey, rkeys, rounds, BITS);			\
}

DECL_KEYSETUP2(Enc, 128);
DECL_KEYSETUP2(Dec, 128);
DECL_KEYSETUP2(Enc, 192);
DECL_KEYSETUP2(Dec, 192);
DECL_KEYSETUP2(Enc, 256);
DECL_KEYSETUP2(Dec, 256);

inline
void AES_ARM8_Encrypt_BlkX2(const uchar* rkeys, uint rounds, const uchar in[16], uchar out[16])
{
	AES_ARM8_Encrypt(rkeys, rounds/2, in, out);
	AES_ARM8_Encrypt(rkeys+16+8*rounds, rounds/2, out, out);
}
inline
void AES_ARM8_Decrypt_BlkX2(const uchar* rkeys, uint rounds, const uchar in[16], uchar out[16])
{
	AES_ARM8_Decrypt(rkeys+16+8*rounds, rounds/2, in, out);
	AES_ARM8_Decrypt(rkeys, rounds/2, out, out);
}

int  AES_ARM8_ECB_EncryptX2(const uchar* rkeys, uint rounds, uchar *iv, uint pad,
			 const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	return AES_Gen_ECB_Enc(AES_ARM8_Encrypt_BlkX2, rkeys, rounds, pad, in, out, len, olen);
}
int  AES_ARM8_ECB_DecryptX2(const uchar* rkeys, uint rounds, uchar *iv, uint pad,
			 const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	return AES_Gen_ECB_Dec(AES_ARM8_Decrypt_BlkX2, rkeys, rounds, pad, in, out, len, olen);
}

int  AES_ARM8_CBC_EncryptX2(const uchar* rkeys, uint rounds, uchar *iv, uint pad,
			 const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	return AES_Gen_CBC_Enc(AES_ARM8_Encrypt_BlkX2, rkeys, rounds, iv, pad, in, out, len, olen);
}
int  AES_ARM8_CBC_DecryptX2(const uchar* rkeys, uint rounds, uchar *iv, uint pad,
			 const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	return AES_Gen_CBC_Dec(AES_ARM8_Decrypt_BlkX2, rkeys, rounds, iv, pad, in, out, len, olen);
}

int  AES_ARM8_CTR_CryptX2(const uchar* rkeys, uint rounds, uchar *ctr, uint pad,
			const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	*olen = len;
	return AES_Gen_CTR_Crypt(AES_ARM8_Encrypt_BlkX2, rkeys, rounds, ctr, in, out, len);
}

ciph_desc_t AES_ARM8_Methods[] = {{"AES128-ECB"  , 128, 10, 16, 11*16, &aes_stream_ecb, 
					AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Dec,
					AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release},
			       {"AES128-CBC"  , 128, 10, 16, 11*16, &aes_stream_cbc,
					AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Dec,
					AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release},
			       {"AES128-CTR"  , 128, 10, 16, 11*16, &aes_stream_ctr,
					AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Enc,
					AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release},
			       {"AES192-ECB"  , 192, 12, 16, 13*16, &aes_stream_ecb,
					AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Dec,
					AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release},
			       {"AES192-CBC"  , 192, 12, 16, 13*16, &aes_stream_cbc,
					AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Dec,
					AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release},
			       {"AES192-CTR"  , 192, 12, 16, 13*16, &aes_stream_ctr,
					AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Enc,
					AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release},
			       {"AES256-ECB"  , 256, 14, 16, 15*16, &aes_stream_ecb,
					AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Dec,
					AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release},
			       {"AES256-CBC"  , 256, 14, 16, 15*16, &aes_stream_cbc,
					AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Dec,
					AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release},
			       {"AES256-CTR"  , 256, 14, 16, 15*16, &aes_stream_ctr,
					AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Enc,
					AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release},
			       {"AES128+-ECB" , 128, 12, 16, 13*16, &aes_stream_ecb,
					AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Dec,
					AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release},
			       {"AES128+-CBC" , 128, 12, 16, 13*16, &aes_stream_cbc,
					AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Dec,
					AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release},
			       {"AES128+-CTR" , 128, 12, 16, 13*16, &aes_stream_ctr,
					AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Enc,
					AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release},
			       {"AES192+-ECB" , 192, 15, 16, 16*16, &aes_stream_ecb,
					AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Dec,
					AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release},
			       {"AES192+-CBC" , 192, 15, 16, 16*16, &aes_stream_cbc,
					AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Dec,
					AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release},
			       {"AES192+-CTR" , 192, 15, 16, 16*16, &aes_stream_ctr,
					AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Enc,
					AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release},
			       {"AES256+-ECB" , 256, 18, 16, 19*16, &aes_stream_ecb,
					AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Dec,
					AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release},
			       {"AES256+-CBC" , 256, 18, 16, 19*16, &aes_stream_cbc,
					AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Dec,
					AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release},
			       {"AES256+-CTR" , 256, 18, 16, 19*16, &aes_stream_ctr,
					AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Enc,
					AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release},
			       {"AES128x2-ECB", 128, 20, 16, 22*16, &aes_stream_ecb,
					AES_ARM8_KeySetupX2_128_Enc, AES_ARM8_KeySetupX2_128_Dec,
					AES_ARM8_ECB_EncryptX2, AES_ARM8_ECB_DecryptX2, AES_Gen_Release},
			       {"AES128x2-CBC", 128, 20, 16, 22*16, &aes_stream_cbc,
					AES_ARM8_KeySetupX2_128_Enc, AES_ARM8_KeySetupX2_128_Dec,
					AES_ARM8_CBC_EncryptX2, AES_ARM8_CBC_DecryptX2, AES_Gen_Release},
			       {"AES128x2-CTR", 128, 20, 16, 22*16, &aes_stream_ctr,
					AES_ARM8_KeySetupX2_128_Enc, AES_ARM8_KeySetupX2_128_Enc,
					AES_ARM8_CTR_CryptX2, AES_ARM8_CTR_CryptX2, AES_Gen_Release},
			       {"AES192x2-ECB", 192, 24, 16, 26*16, &aes_stream_ecb,
					AES_ARM8_KeySetupX2_192_Enc, AES_ARM8_KeySetupX2_192_Dec,
					AES_ARM8_ECB_EncryptX2, AES_ARM8_ECB_DecryptX2, AES_Gen_Release},
			       {"AES192x2-CBC", 192, 24, 16, 26*16, &aes_stream_cbc,
					AES_ARM8_KeySetupX2_192_Enc, AES_ARM8_KeySetupX2_192_Dec,
					AES_ARM8_CBC_EncryptX2, AES_ARM8_CBC_DecryptX2, AES_Gen_Release},
			       {"AES192x2-CTR", 192, 24, 16, 26*16, &aes_stream_ctr,
					AES_ARM8_KeySetupX2_192_Enc, AES_ARM8_KeySetupX2_192_Enc,
					AES_ARM8_CTR_CryptX2, AES_ARM8_CTR_CryptX2, AES_Gen_Release},
			       {"AES256x2-ECB", 256, 28, 16, 30*16, &aes_stream_ecb,
					AES_ARM8_KeySetupX2_256_Enc, AES_ARM8_KeySetupX2_256_Dec,
					AES_ARM8_ECB_EncryptX2, AES_ARM8_ECB_DecryptX2, AES_Gen_Release},
			       {"AES256x2-CBC", 256, 28, 16, 30*16, &aes_stream_cbc,
					AES_ARM8_KeySetupX2_256_Enc, AES_ARM8_KeySetupX2_256_Dec,
					AES_ARM8_CBC_EncryptX2, AES_ARM8_CBC_DecryptX2, AES_Gen_Release},
			       {"AES256x2-CTR", 256, 28, 16, 30*16, &aes_stream_ctr,
					AES_ARM8_KeySetupX2_256_Enc, AES_ARM8_KeySetupX2_256_Enc,
					AES_ARM8_CTR_CryptX2, AES_ARM8_CTR_CryptX2, AES_Gen_Release},
			      { NULL, /* ... */}
};


