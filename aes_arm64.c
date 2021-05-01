/**
 * aes_arm64.c
 *
 * Here we transform the rijndael C implementation
 * (rijndael-alg-fst.c from Vincent Rijmen, Antoon Bosselaers
 *  and Paulo Barreto, under the Public Domain)
 * into an ARM64/AArch64 optimized version, taking advantage of the
 * ARMv8 crypto extensions.
 *
 * (C) Kurt Garloff <kurt@garloff.de>, 8-9/2015
 * License: GNU GPL v2 or v3 (at your option)
 */

#include "aes_c.h"
#include "aes_arm64.h"
#include "secmem.h"
#include "archdep.h"

#include <string.h>
#include <assert.h>
//#include <stdio.h>

#define MAXKC (256 / 32)
#define MAXKB (256 / 8)
#define MAXNR 14

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

static int AES_ARM8_probe()
{
	return !have_arm8crypto;
}

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
	"	ror	%w[out], %w[in], #8	\n"
	: [out] "=r"(in)
	: [in] "0"(in)
	);
	return in;
}

static inline u32 aes_sbox(u32 in)
{
	u32 ret;
	asm volatile (
	"	dup 	v1.4s, %w[in]		\n"
	"	movi	v0.16b, #0		\n"
	"	aese	v0.16b, v1.16b		\n"
	"	umov	%w[out], v0.s[0]	\n"
	: [out] "=r"(ret)
	: [in] "r"(in)
	: "v0", "v1"
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
	if (!rounds) {
		switch (keyBits) {
			case 128:
				rounds = 10; break;
			case 192:
				rounds = 12; break;
			case 256:
				rounds = 14; break;
			default:
				return 0;
		}
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

inline void AES_ARM8_EKey_DKey(const u32 *ekey, u32* dkey, int rounds)
{
	asm volatile(
		"	ld1	{v0.16b}, [%1]		\n"
		"	sub	%1, %1, #16		\n"
		"	st1	{v0.16b}, [%0], #16	\n"
		"1:					\n"
		"	ld1	{v0.16b}, [%1]		\n"
		"	aesimc	v0.16b, v0.16b		\n"
		"	sub	%1, %1, #16		\n"
		"	subs 	%w2, %w2, #1		\n"
		"	st1	{v0.16b}, [%0], #16	\n"
		"	b.pl	1b			\n"
		"	ld1	{v0.16b}, [%1]		\n"
		"//	sub	%1, %1, #16		\n"
		"	st1	{v0.16b}, [%0], #16	\n"
		: "=r"(dkey), "=r"(ekey), "=r"(rounds), "=m"(*(roundkey(*)[rounds+1])ekey)
		: "0"(dkey), "1"(ekey+4*rounds), "2"(rounds-2), "m"(*(roundkey(*)[rounds+1])dkey)
		: "v0");
}


/**
 * Expand the cipher key into the decryption key schedule.
 *
 * @return	the number of rounds for the given cipher key size.
 */
int AES_ARM8_KeySetupDec(u32 rk[/*4*(Nr + 1)*/], const u8 cipherKey[], int keyBits, int rounds)
{
	/* expand the cipher key: */
	int Nr = AES_ARM8_KeySetupEnc(crypto->xkeys->data32, cipherKey, keyBits, rounds);
	AES_ARM8_EKey_DKey(crypto->xkeys->data32, rk, Nr);
	return Nr;
}

#define CLR_NEON3			\
	asm volatile(			\
	" movi	v0.16b, #0	\n"	\
	" movi	v1.16b, #0	\n"	\
	" movi	v2.16b, #0	\n"	\
	::: "v0", "v1", "v2")

#define CLR_NEON6			\
	asm volatile(			\
	" movi	v0.16b, #0	\n"	\
	" movi	v1.16b, #0	\n"	\
	" movi	v2.16b, #0	\n"	\
	" movi	v3.16b, #0	\n"	\
	" movi	v4.16b, #0	\n"	\
	" movi	v5.16b, #0	\n"	\
	::: "v0", "v1", "v2", "v3", "v4", "v5")

#define CLR_NEON10			\
	asm volatile(			\
	" movi	v0.16b, #0	\n"	\
	" movi	v1.16b, #0	\n"	\
	" movi	v2.16b, #0	\n"	\
	" movi	v3.16b, #0	\n"	\
	" movi	v4.16b, #0	\n"	\
	" movi	v5.16b, #0	\n"	\
	" movi	v6.16b, #0	\n"	\
	" movi	v7.16b, #0	\n"	\
	" movi	v8.16b, #0	\n"	\
	" movi	v9.16b, #0	\n"	\
	::: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9")

#define CLR_NEON10_14			\
	asm volatile(			\
	" movi	v10.16b, #0	\n"	\
	" movi	v11.16b, #0	\n"	\
	" movi	v12.16b, #0	\n"	\
	" movi	v13.16b, #0	\n"	\
	" movi	v14.16b, #0	\n"	\
	::: "v10", "v11", "v12", "v13", "v14")


void AES_ARM8_Encrypt(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 pt[16], u8 ct[16])
{
	asm volatile(
	"	ld1	{v0.16b}, [%[pt]]	\n"
	"	ld1	{v1.4s, v2.4s}, [%[rk]], #32	\n"
	"//	eor	v0.16b, v0.16b, v3.16b	\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	".align 4				\n"
	"1:					\n"
	"	aese	v0.16b, v1.16b		\n"
	"	aesmc	v0.16b, v0.16b		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	b.eq	2f			\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	"	aese	v0.16b, v2.16b		\n"
	"	aesmc	v0.16b, v0.16b		\n"
	"	ld1	{v2.4s}, [%[rk]], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aese	v0.16b, v1.16b		\n"
	"	eor	v0.16b, v0.16b, v2.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aese	v0.16b, v2.16b		\n"
	"	eor	v0.16b, v0.16b, v1.16b	\n"
	"3:					\n"
	"	st1	{v0.16b}, [%[ct]]	\n"
	: [rk] "=r" (rkeys), [nr] "=r" (Nr), "=m" (*(char(*)[16])ct)
	//: "0" (rkeys), "1" (Nr), [pt] "r" (pt), [ct] "r" (ct), "m" (*(const char(*)[640])rkeys), "m" (*pt)
	: "0" (rkeys), "1" (Nr), [pt] "r" (pt), [ct] "r" (ct), "m" (*(const char(*)[16*(Nr+1)])rkeys), "m" (*(const char(*)[16])pt)
	: "v0", "v1", "v2", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}



void AES_ARM8_Decrypt(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 ct[16], u8 pt[16])
{
	asm volatile(
	"	ld1	{v0.16b}, [%[ct]]	\n"
	"	ld1	{v1.4s, v2.4s}, [%[rk]], #32	\n"
	"//	eor	v0.16b, v0.16b, v1.16b	\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	".align 4				\n"
	"1:					\n"
	"	aesd	v0.16b, v1.16b		\n"
	"	aesimc	v0.16b, v0.16b		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	b.eq	2f			\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	"	aesd	v0.16b, v2.16b		\n"
	"	aesimc	v0.16b, v0.16b		\n"
	"	ld1	{v2.4s}, [%[rk]], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aesd	v0.16b, v1.16b		\n"
	"	eor	v0.16b, v0.16b, v2.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aesd	v0.16b, v2.16b		\n"
	"	eor	v0.16b, v0.16b, v1.16b	\n"
	"3:					\n"
	"	st1	{v0.16b}, [%[pt]]	\n"
	: [rk] "=r" (rkeys), [nr] "=r" (Nr), "=m" (*pt)
	: "0" (rkeys), "1" (Nr), [ct] "r" (ct), [pt] "r" (pt), "m" (*(const char(*)[16*(Nr+1)])rkeys), "m" (*ct)
	: "v0", "v1", "v2", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}

void AES_ARM8_Encrypt4(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 pt[64], u8 ct[64])
{
	/* FIXME: We might need to ensure that pt and ct are not pointing to
	 * the same register -- we saw this on arm32 (armhf/armv7) */
	asm volatile(
	"	ld1	{v2.16b-v5.16b}, [%[pt]]	\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"//	prfm	PLDL1STRM, [%[pt],#64]	\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	".align 4				\n"
	"1:					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	aese	v3.16b, v0.16b		\n"
	"	aesmc	v3.16b, v3.16b		\n"
	"	aese	v4.16b, v0.16b		\n"
	"	aesmc	v4.16b, v4.16b		\n"
	"	aese	v5.16b, v0.16b		\n"
	"	aesmc	v5.16b, v5.16b		\n"
	"	ld1	{v0.4s}, [%[rk]], #16	\n"
	"	b.eq	2f			\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	"	aese	v2.16b, v1.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	aese	v3.16b, v1.16b		\n"
	"	aesmc	v3.16b, v3.16b		\n"
	"	aese	v4.16b, v1.16b		\n"
	"	aesmc	v4.16b, v4.16b		\n"
	"	aese	v5.16b, v1.16b		\n"
	"	aesmc	v5.16b, v5.16b		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	eor	v2.16b, v2.16b, v1.16b	\n"
	"	aese	v3.16b, v0.16b		\n"
	"	eor	v3.16b, v3.16b, v1.16b	\n"
	"	aese	v4.16b, v0.16b		\n"
	"	eor	v4.16b, v4.16b, v1.16b	\n"
	"	aese	v5.16b, v0.16b		\n"
	"	eor	v5.16b, v5.16b, v1.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aese	v2.16b, v1.16b		\n"
	"	eor	v2.16b, v2.16b, v0.16b	\n"
	"	aese	v3.16b, v1.16b		\n"
	"	eor	v3.16b, v3.16b, v0.16b	\n"
	"	aese	v4.16b, v1.16b		\n"
	"	eor	v4.16b, v4.16b, v0.16b	\n"
	"	aese	v5.16b, v1.16b		\n"
	"	eor	v5.16b, v5.16b, v0.16b	\n"
	"3:					\n"
	"	st1	{v2.16b-v5.16b}, [%[ct]]	\n"
	: [rk] "=r" (rkeys), [nr] "=r" (Nr), "=m" (*ct)
	: "0" (rkeys), "1" (Nr), [pt] "r" (pt), [ct] "r" (ct), "m" (*(const char(*)[16*(Nr+1)])rkeys), "m" (*pt)
	: "v0", "v1", "v2", "v3", "v4", "v5", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}

void AES_ARM8_Decrypt4(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 ct[64], u8 pt[64])
{
	asm volatile(
	"	ld1	{v2.16b-v5.16b}, [%[ct]]	\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"//	prfm	PLDL1STRM, [%[ct],#64]	\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	".align 4				\n"
	"1:					\n"
	"	aesd	v2.16b, v0.16b		\n"
	"	aesimc	v2.16b, v2.16b		\n"
	"	aesd	v3.16b, v0.16b		\n"
	"	aesimc	v3.16b, v3.16b		\n"
	"	aesd	v4.16b, v0.16b		\n"
	"	aesimc	v4.16b, v4.16b		\n"
	"	aesd	v5.16b, v0.16b		\n"
	"	aesimc	v5.16b, v5.16b		\n"
	"	ld1	{v0.4s}, [%[rk]], #16	\n"
	"	b.eq	2f			\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	"	aesd	v2.16b, v1.16b		\n"
	"	aesimc	v2.16b, v2.16b		\n"
	"	aesd	v3.16b, v1.16b		\n"
	"	aesimc	v3.16b, v3.16b		\n"
	"	aesd	v4.16b, v1.16b		\n"
	"	aesimc	v4.16b, v4.16b		\n"
	"	aesd	v5.16b, v1.16b		\n"
	"	aesimc	v5.16b, v5.16b		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aesd	v2.16b, v0.16b		\n"
	"	eor	v2.16b, v2.16b, v1.16b	\n"
	"	aesd	v3.16b, v0.16b		\n"
	"	eor	v3.16b, v3.16b, v1.16b	\n"
	"	aesd	v4.16b, v0.16b		\n"
	"	eor	v4.16b, v4.16b, v1.16b	\n"
	"	aesd	v5.16b, v0.16b		\n"
	"	eor	v5.16b, v5.16b, v1.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aesd	v2.16b, v1.16b		\n"
	"	eor	v2.16b, v2.16b, v0.16b	\n"
	"	aesd	v3.16b, v1.16b		\n"
	"	eor	v3.16b, v3.16b, v0.16b	\n"
	"	aesd	v4.16b, v1.16b		\n"
	"	eor	v4.16b, v4.16b, v0.16b	\n"
	"	aesd	v5.16b, v1.16b		\n"
	"	eor	v5.16b, v5.16b, v0.16b	\n"
	"3:					\n"
	"	st1	{v2.16b-v5.16b}, [%[pt]]	\n"
	: [rk] "=r" (rkeys), [nr] "=r" (Nr), "=m" (*pt)
	: "0" (rkeys), "1" (Nr), [ct] "r" (ct), [pt] "r" (pt), "m" (*rkeys), "m" (*ct)
	: "v0", "v1", "v2", "v3", "v4", "v5", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}

// Little-Endian 64bit 1,2,3,4
static const unsigned long long inc1234[] = {0ULL, 1ULL, 0ULL, 2ULL, 0ULL, 3ULL, 0ULL, 4ULL};
static const unsigned long long inc1[] = {0ULL, 1ULL};

void AES_ARM8_Encrypt_CTR(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 pt[16], u8 ct[16], u8 iv[16])
{
	asm volatile(
	"	ld1	{v2.16b}, [%[iv]]	\n"
	"	//prfm	PLDL1STRM, [%[pt]]	\n"
	"	ld1	{v3.2d}, %[inc]		\n"
	"	subs	w7, %w[nr], #2		\n"
	"	rev64	v4.16b, v2.16b		\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"	add	v4.2d, v4.2d, v3.2d	\n"
	"	rev64	v4.16b, v4.16b		\n"
	"	ld1	{v3.16b}, [%[pt]]	\n"
	"	st1	{v4.16b}, [%[iv]]	\n"
	".align 4				\n"
	"1:					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	ld1	{v0.4s}, [%[rk]], #16	\n"
	"	b.eq	2f			\n"
	"	aese	v2.16b, v1.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	subs	w7, w7, #2		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	eor	v2.16b, v2.16b, v1.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aese	v2.16b, v1.16b		\n"
	"	eor	v2.16b, v2.16b, v0.16b	\n"
	"3:					\n"
	"	eor	v3.16b, v3.16b, v2.16b	\n"
	"	st1	{v3.16b}, [%[ct]]	\n"
	: [rk] "=r" (rkeys), "=m" (*ct), "=m" (*iv)
	: "0" (rkeys), [nr] "r" (Nr), [pt] "r" (pt), [ct] "r" (ct), [iv] "r" (iv),
	  [inc] "Q" (inc1), "m" (*(const char(*)[16*(Nr+1)])rkeys), "m" (*pt)
	: "v0", "v1", "v2", "v3", "v4", "w7", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}

void AES_ARM8_Encrypt4_CTR(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 pt[64], u8 ct[64], u8 iv[16])
{
	asm volatile(
	"	ld1	{v2.16b}, [%[iv]]	\n"
	"	ld1	{v6.2d-v9.2d}, [%[inc]] \n"
	"	subs	w7, %w[nr], #2		\n"
	"	//prfm	PLDL1STRM, [%[pt]]	\n"
	"	rev64	v5.16b, v2.16b		\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"	add	v9.2d, v5.2d, v9.2d	\n"
	"	rev64	v9.16b, v9.16b		\n"
	"	add	v3.2d, v5.2d, v6.2d	\n"
	"	rev64	v3.16b, v3.16b		\n"
	"	add	v4.2d, v5.2d, v7.2d	\n"
	"	rev64	v4.16b, v4.16b		\n"
	"	add	v5.2d, v5.2d, v8.2d	\n"
	"	//prfm	PLDL1STRM, [%[pt],#64]	\n"
	"	rev64	v5.16b, v5.16b		\n"
	"	st1	{v9.16b}, [%[iv]]	\n"
	"	ld1	{v6.16b-v9.16b}, [%[pt]]\n"
	".align 4				\n"
	"1:					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	aese	v3.16b, v0.16b		\n"
	"	aesmc	v3.16b, v3.16b		\n"
	"	aese	v4.16b, v0.16b		\n"
	"	aesmc	v4.16b, v4.16b		\n"
	"	aese	v5.16b, v0.16b		\n"
	"	aesmc	v5.16b, v5.16b		\n"
	"	ld1	{v0.4s}, [%[rk]], #16	\n"
	"	b.eq	2f			\n"
	"	subs	w7, w7, #2		\n"
	"	aese	v2.16b, v1.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	aese	v3.16b, v1.16b		\n"
	"	aesmc	v3.16b, v3.16b		\n"
	"	aese	v4.16b, v1.16b		\n"
	"	aesmc	v4.16b, v4.16b		\n"
	"	aese	v5.16b, v1.16b		\n"
	"	aesmc	v5.16b, v5.16b		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	eor	v2.16b, v2.16b, v1.16b	\n"
	"	aese	v3.16b, v0.16b		\n"
	"	eor	v3.16b, v3.16b, v1.16b	\n"
	"	aese	v4.16b, v0.16b		\n"
	"	eor	v4.16b, v4.16b, v1.16b	\n"
	"	aese	v5.16b, v0.16b		\n"
	"	eor	v5.16b, v5.16b, v1.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aese	v2.16b, v1.16b		\n"
	"	eor	v2.16b, v2.16b, v0.16b	\n"
	"	aese	v3.16b, v1.16b		\n"
	"	eor	v3.16b, v3.16b, v0.16b	\n"
	"	aese	v4.16b, v1.16b		\n"
	"	eor	v4.16b, v4.16b, v0.16b	\n"
	"	aese	v5.16b, v1.16b		\n"
	"	eor	v5.16b, v5.16b, v0.16b	\n"
	"3:					\n"
	"	eor	v6.16b, v6.16b, v2.16b	\n"
	"	eor	v7.16b, v7.16b, v3.16b	\n"
	"	eor	v8.16b, v8.16b, v4.16b	\n"
	"	eor	v9.16b, v9.16b, v5.16b	\n"
	"	st1	{v6.16b-v9.16b}, [%[ct]]	\n"
	: [rk] "=r" (rkeys), "=m" (*ct), "=m" (*iv)
	: "0" (rkeys), [nr] "r" (Nr), [pt] "r" (pt), [ct] "r" (ct),
	  [iv] "r" (iv), [inc] "r" (inc1234), "m" (*inc1234),
	  "m" (*(const char(*)[16*(Nr+1)])rkeys), "m" (*pt)
	: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "w7", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}

#ifndef NO_ASM_CTR
int  AES_ARM8_CTR_Crypt(const uchar* rkeys, uint rounds, uchar *ctr, uint pad,
			const uchar *input, uchar *output, ssize_t len, ssize_t *olen)
{
	*olen = len;
	asm volatile(
	"	subs	%[len], %[len], #64	\n"
	"	ld1	{v10.16b}, [%[iv]]	\n"
	"	rev64	v10.16b, v10.16b	\n"
	"	ld1	{v11.2d-v14.2d}, [%[inc]]	\n"
	"	b.mi	9f			\n"
	"//.align 4				\n"
	"0:					\n"
	"	mov	x8, %[rk]		\n"
	"	subs	w9, %w[nr], #2		\n"
	"	ld1	{v0.4s, v1.4s}, [x8], #32	\n"
	"	//prfm	PSTR2KEEP, [%[ct]]	\n"
	"	//prfm	PLDL1STRM, [%[pt]]	\n"
	"	rev64	v2.16b, v10.16b		\n"
	"	add	v3.2d, v10.2d, v11.2d	\n"
	"	rev64	v3.16b, v3.16b		\n"
	"	add	v4.2d, v10.2d, v12.2d	\n"
	"	rev64	v4.16b, v4.16b		\n"
	"	add	v5.2d, v10.2d, v13.2d	\n"
	"	rev64	v5.16b, v5.16b		\n"
	"	add	v10.2d, v10.2d, v14.2d	\n"
	"	ld1	{v6.16b-v9.16b}, [%[pt]], #64	\n"
	".align 4				\n"
	"1:					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	aese	v3.16b, v0.16b		\n"
	"	aesmc	v3.16b, v3.16b		\n"
	"	aese	v4.16b, v0.16b		\n"
	"	aesmc	v4.16b, v4.16b		\n"
	"	aese	v5.16b, v0.16b		\n"
	"	aesmc	v5.16b, v5.16b		\n"
	"	ld1	{v0.4s}, [x8], #16	\n"
	"	b.eq	2f			\n"
	"	subs	w9, w9, #2		\n"
	"	aese	v2.16b, v1.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	aese	v3.16b, v1.16b		\n"
	"	aesmc	v3.16b, v3.16b		\n"
	"	aese	v4.16b, v1.16b		\n"
	"	aesmc	v4.16b, v4.16b		\n"
	"	aese	v5.16b, v1.16b		\n"
	"	aesmc	v5.16b, v5.16b		\n"
	"	ld1	{v1.4s}, [x8], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	eor	v2.16b, v2.16b, v1.16b	\n"
	"	aese	v3.16b, v0.16b		\n"
	"	eor	v3.16b, v3.16b, v1.16b	\n"
	"	aese	v4.16b, v0.16b		\n"
	"	eor	v4.16b, v4.16b, v1.16b	\n"
	"	aese	v5.16b, v0.16b		\n"
	"	eor	v5.16b, v5.16b, v1.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aese	v2.16b, v1.16b		\n"
	"	eor	v2.16b, v2.16b, v0.16b	\n"
	"	aese	v3.16b, v1.16b		\n"
	"	eor	v3.16b, v3.16b, v0.16b	\n"
	"	aese	v4.16b, v1.16b		\n"
	"	eor	v4.16b, v4.16b, v0.16b	\n"
	"	aese	v5.16b, v1.16b		\n"
	"	eor	v5.16b, v5.16b, v0.16b	\n"
	"3:					\n"
	"	subs	%[len], %[len], #64	\n"
	"	eor	v6.16b, v6.16b, v2.16b	\n"
	"	eor	v7.16b, v7.16b, v3.16b	\n"
	"	eor	v8.16b, v8.16b, v4.16b	\n"
	"	eor	v9.16b, v9.16b, v5.16b	\n"
	"	st1	{v6.16b-v9.16b}, [%[ct]], #64	\n"
	"	b.pl	0b			\n"
	"9:					\n"
	"	adds	%[len], %[len], #64	\n"
	"	b.eq	30f			\n"
	"10:					\n"
	"	mov	x8, %[rk]		\n"
	"	subs	w9, %w[nr], 2		\n"
	"	ld1	{v0.4s, v1.4s}, [x8], #32	\n"
	"	rev64	v2.16b, v10.16b		\n"
	"	add	v10.2d, v10.2d, v11.2d	\n"
	"	ld1	{v6.16b}, [%[pt]], #16	\n"
	"//.align 4				\n"
	"11:					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	ld1	{v0.4s}, [x8], #16	\n"
	"	b.eq	12f			\n"
	"	subs	w9, w9, #2		\n"
	"	aese	v2.16b, v1.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	ld1	{v1.4s}, [x8], #16	\n"
	"	b.pl	11b			\n"
	"					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	eor	v2.16b, v2.16b, v1.16b	\n"
	"	b	13f			\n"
	"12:					\n"
	"	aese	v2.16b, v1.16b		\n"
	"	eor	v2.16b, v2.16b, v0.16b	\n"
	"13:					\n"
	"	subs	%[len], %[len], #16	\n"
	"	eor	v6.16b, v6.16b, v2.16b	\n"
	"	b.mi	20f			\n"
	"	st1	{v6.16b}, [%[ct]], #16	\n"
	"	b.eq	30f			\n"
	"	b	10b			\n"
	"20:					\n"
	"//	add	%[len], %[len], #16	\n"
	"	tbz	%[len], #3, 21f		\n"
	"	st1	{v6.d}[0], [%[ct]], #8	\n"
	"	ext	v6.16b, v6.16b, v6.16b, #8 \n"
	"21:					\n"
	"	tbz	%[len], #2, 22f		\n"
	"	st1	{v6.s}[0], [%[ct]], #4	\n"
	"	ext	v6.16b, v6.16b, v6.16b, #4 \n"
	"22:					\n"
	"	tbz	%[len], #1, 23f		\n"
	"	st1	{v6.h}[0], [%[ct]], #2	\n"
	"	ext	v6.16b, v6.16b, v6.16b, #2 \n"
	"23:					\n"
	"	tbz	%[len], #0, 30f		\n"
	"	st1	{v6.b}[0], [%[ct]], #1 \n"
	"//	ext	v6.16b, v6.16b, v6.16b, #1 \n"
	"30:					\n"
	"	rev64	v10.16b, v10.16b	\n"
	"	st1	{v10.16b}, [%[iv]]	\n"
	: [len] "=r" (len), [pt] "=r" (input), [ct] "=r" (output),
	  "=m" (*(char(*)[16])ctr), "=m" (*(char(*)[len])output)
	: "0" (len), "1" (input), "2" (output), [rk] "r" (rkeys),
	  [nr] "r" (rounds), [iv] "r" (ctr), [inc] "r" (inc1234),
	  "m" (*(const char(*)[16*(rounds+1)])rkeys), "m" (*(const char(*)[len])input)
	: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "x8", "w9", "cc",
	  "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	CLR_NEON10;
	CLR_NEON10_14;
	//return r;
	return 0;
}
#endif

void AES_ARM8_EncryptX2_CTR(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 pt[16], u8 ct[16], u8 iv[16])
{
	assert(Nr > 4 && !(Nr%2));
	uint halfnr = Nr/2;
	asm volatile(
	"	ld1	{v2.16b}, [%[iv]]	\n"
	"	ld1	{v4.2d}, %[inc]		\n"
	"	rev64	v3.16b, v2.16b		\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"	add	v4.2d, v3.2d, v4.2d	\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	"	rev64	v4.16b, v4.16b		\n"
	"	ld1	{v3.16b}, [%[pt]]	\n"
	"	mov	w7, %w[nr]		\n"
	"	st1	{v4.16b}, [%[iv]]	\n"
	".align 4				\n"
	"1:					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	ld1	{v0.4s}, [%[rk]], #16	\n"
	"	b.eq	2f			\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	"	aese	v2.16b, v1.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	eor	v2.16b, v2.16b, v1.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aese	v2.16b, v1.16b		\n"
	"	eor	v2.16b, v2.16b, v0.16b	\n"
	"3:					\n"
	"	cmp	w7, #0			\n"
	"	b.eq	4f			\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"	mov	%w[nr], w7		\n"
	"	mov	w7, #0			\n"
	"	b 	1b			\n"
	"4:					\n"
	"	eor	v3.16b, v3.16b, v2.16b	\n"
	"	st1	{v3.16b}, [%[ct]]	\n"
	: [rk] "=r" (rkeys), [nr] "=r" (halfnr), "=m" (*ct), "=m" (*iv)
	: "0" (rkeys), "1" (halfnr), [pt] "r" (pt), [ct] "r" (ct), [iv] "r" (iv),
	  [inc] "Q" (inc1), "m" (*(const char(*)[16*(Nr+1)])rkeys), "m" (*pt)
	: "v0", "v1", "v2", "v3", "v4", "w7", "cc"
	);
	//printf("%i rounds left, %li rounds\n", Nr, (rkeys-rk)/16);
	return;
}

void AES_ARM8_Encrypt4X2_CTR(const u8 *rkeys /*u32 rk[4*(Nr + 1)]*/, uint Nr, const u8 pt[64], u8 ct[64], u8 iv[16])
{
	assert(Nr > 4 && !(Nr%2));
	uint halfnr = Nr/2;
	asm volatile(
	"	ld1	{v2.16b}, [%[iv]]	\n"
	"	ld1	{v6.2d-v9.2d}, [%[inc]]	\n"
	"	rev64	v5.16b, v2.16b		\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"	//prfm	PLDL1STRM, [%[pt]]	\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	"	add	v9.2d, v5.2d, v9.2d	\n"
	"	rev64	v9.16b, v9.16b		\n"
	"	add	v3.2d, v5.2d, v6.2d	\n"
	"	rev64	v3.16b, v3.16b		\n"
	"	add	v4.2d, v5.2d, v7.2d	\n"
	"	rev64	v4.16b, v4.16b		\n"
	"	add	v5.2d, v5.2d, v8.2d	\n"
	"	mov	w7, %w[nr]		\n"
	"	rev64	v5.16b, v5.16b		\n"
	"	st1	{v9.16b}, [%[iv]]	\n"
	"	//prfm	PLDL1STRM, [%[pt],#64]	\n"
	"	ld1	{v6.16b-v9.16b}, [%[pt]]\n"
	".align 4				\n"
	"1:					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	aese	v3.16b, v0.16b		\n"
	"	aesmc	v3.16b, v3.16b		\n"
	"	aese	v4.16b, v0.16b		\n"
	"	aesmc	v4.16b, v4.16b		\n"
	"	aese	v5.16b, v0.16b		\n"
	"	aesmc	v5.16b, v5.16b		\n"
	"	ld1	{v0.4s}, [%[rk]], #16	\n"
	"	b.eq	2f			\n"
	"	subs	%w[nr], %w[nr], #2	\n"
	"	aese	v2.16b, v1.16b		\n"
	"	aesmc	v2.16b, v2.16b		\n"
	"	aese	v3.16b, v1.16b		\n"
	"	aesmc	v3.16b, v3.16b		\n"
	"	aese	v4.16b, v1.16b		\n"
	"	aesmc	v4.16b, v4.16b		\n"
	"	aese	v5.16b, v1.16b		\n"
	"	aesmc	v5.16b, v5.16b		\n"
	"	ld1	{v1.4s}, [%[rk]], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aese	v2.16b, v0.16b		\n"
	"	eor	v2.16b, v2.16b, v1.16b	\n"
	"	aese	v3.16b, v0.16b		\n"
	"	eor	v3.16b, v3.16b, v1.16b	\n"
	"	aese	v4.16b, v0.16b		\n"
	"	eor	v4.16b, v4.16b, v1.16b	\n"
	"	aese	v5.16b, v0.16b		\n"
	"	eor	v5.16b, v5.16b, v1.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aese	v2.16b, v1.16b		\n"
	"	eor	v2.16b, v2.16b, v0.16b	\n"
	"	aese	v3.16b, v1.16b		\n"
	"	eor	v3.16b, v3.16b, v0.16b	\n"
	"	aese	v4.16b, v1.16b		\n"
	"	eor	v4.16b, v4.16b, v0.16b	\n"
	"	aese	v5.16b, v1.16b		\n"
	"	eor	v5.16b, v5.16b, v0.16b	\n"
	"3:					\n"
	"	cmp	w7, #0			\n"
	"	b.eq	4f			\n"
	"	ld1	{v0.4s, v1.4s}, [%[rk]], #32	\n"
	"	mov	%w[nr], w7		\n"
	"	mov	w7, #0			\n"
	"	b	1b			\n"
	"4:					\n"
	"	eor	v6.16b, v6.16b, v2.16b	\n"
	"	eor	v7.16b, v7.16b, v3.16b	\n"
	"	eor	v8.16b, v8.16b, v4.16b	\n"
	"	eor	v9.16b, v9.16b, v5.16b	\n"
	"	st1	{v6.16b-v9.16b}, [%[ct]]	\n"
	: [rk] "=r" (rkeys), [nr] "=r" (halfnr), "=m" (*ct), "=m" (*iv)
	: "0" (rkeys), "1" (halfnr), [pt] "r" (pt), [ct] "r" (ct),
          [iv] "r" (iv), [inc] "r" (inc1234), "m" (*inc1234),
	  "m" (*(const char(*)[16*(Nr+1)])rkeys), "m" (*pt)
	: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "w7", "cc"
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


#define AES_ARM8_Encrypt_Blk  AES_ARM8_Encrypt
#define AES_ARM8_Decrypt_Blk  AES_ARM8_Decrypt
#define AES_ARM8_Encrypt_4Blk AES_ARM8_Encrypt4
#define AES_ARM8_Decrypt_4Blk AES_ARM8_Decrypt4
#define AES_ARM8_Encrypt_Blk_CTR  AES_ARM8_Encrypt_CTR
#define AES_ARM8_Encrypt_4Blk_CTR AES_ARM8_Encrypt4_CTR
#define AES_ARM8_Encrypt_BlkX2_CTR  AES_ARM8_EncryptX2_CTR
#define AES_ARM8_Encrypt_4BlkX2_CTR AES_ARM8_Encrypt4X2_CTR

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
#if 0
int  AES_ARM8_CBC_Encrypt(const uchar* rkeys, uint rounds, uchar *iv, uint pad, const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	int r = AES_Gen_CBC_Enc(AES_ARM8_Encrypt_Blk, 
				rkeys, rounds, iv, pad, in, out, len, olen);
	CLR_NEON3;
	return r;
}
#else

#define XOR16(x1, x2, xout)	\
do {				\
	uint _i;		\
	for (_i = 0; _i < 16; _i+=sizeof(ulong))				\
		*(ulong*)(xout+_i) = *(ulong*)(x1+_i) ^ *(ulong*)(x2+_i);	\
} while(0)

#define FILL_BLK(in, bf, len, pad) 	\
do {					\
	uint i;				\
	uchar by = pad? 16-(len&0x0f) : 0;	\
	for (i = 0; i < len; ++i)	\
		bf[i] = in[i];		\
	for (; i < 16; ++i)		\
		bf[i] = by;		\
} while(0)


int  AES_ARM8_CBC_Encrypt(const uchar* rkeys, uint rounds,
		uchar *iv, uint pad,
		const uchar *input, uchar *output,
		ssize_t len, ssize_t *olen)
{
	*olen = len;
	asm volatile(
	"	subs	%[len], %[len], #16	\n"
	"	ld1	{v3.16b}, [%[iv]]	\n"
	"	b.mi	10f			\n"
	"//.align 4				\n"
	"0:					\n"
	"	ld1	{v0.16b}, [%[pt]], #16	\n"
	"	mov	x8, %[rk]		\n"
	"	eor	v0.16b, v0.16b, v3.16b	\n"
	"	ld1	{v1.4s, v2.4s}, [x8], #32	\n"
	"	subs	w9, %w[nr], #2		\n"
	".align 4				\n"
	"1:					\n"
	"	aese	v0.16b, v1.16b		\n"
	"	aesmc	v0.16b, v0.16b		\n"
	"	ld1	{v1.4s}, [x8], #16	\n"
	"	b.eq	2f			\n"
	"	subs	w9, w9, #2		\n"
	"	aese	v0.16b, v2.16b		\n"
	"	aesmc	v0.16b, v0.16b		\n"
	"	ld1	{v2.4s}, [x8], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aese	v0.16b, v1.16b		\n"
	"	eor	v0.16b, v0.16b, v2.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aese	v0.16b, v2.16b		\n"
	"	eor	v0.16b, v0.16b, v1.16b	\n"
	"3:					\n"
	"	subs	%[len], %[len], #16	\n"
	"	mov	v3.16b, v0.16b		\n"
	"	st1	{v0.16b}, [%[ct]], #16	\n"
	"	b.pl	0b			\n"
	"10:					\n"
	"	st1	{v3.16b}, [%[iv]]	\n"
	"	add	%[len], %[len], #16	\n"
	"	movi	v3.16b, #0		\n"
	: [len] "=r" (len), [pt] "=r" (input), [ct] "=r" (output),
	  "=m" (*(char(*)[16])iv), "=m" (*(char(*)[len])output)
	: "0" (len), "1" (input), "2" (output), [rk] "r" (rkeys),
	  [nr] "r" (rounds), [iv] "r" (iv),
	  "m" (*(const char(*)[16*(rounds+1)])rkeys), "m" (*(const char(*)[len])input)
	: "v0", "v1", "v2", "v3", "x8", "w9", "cc"
	);
	//printf("%li bytes left, %li done\n", len, *olen);
	if (len || pad == PAD_ALWAYS) {
		uchar *in = crypto->blkbuf2;
		FILL_BLK(input, in, len, pad);
		XOR16(iv, in, iv);
		AES_ARM8_Encrypt_Blk(rkeys, rounds, iv, output);
		/* Update last IV */
		memcpy(iv, output, 16);
		*olen += 16-(len&15);
		//memset(in, 0, 16);
		//LFENCE;
	}
	CLR_NEON3;
	return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;
}
#endif

#ifndef NO_CBC_DEC4X
int  AES_ARM8_CBC_Decrypt(const uchar* rkeys, uint rounds, uchar *iv, uint pad,
		          const uchar *input, uchar *output, ssize_t len, ssize_t *olen)
{
	*olen = len;
	asm volatile(
	"	subs	%[len], %[len], #64	\n"
	"	//prfm	PLDL1STRM, [%[ct]]	\n"
	"	ld1	{v2.16b}, [%[iv]]	\n"
	"	b.mi	10f			\n"
	"//.align 4				\n"
	"0:					\n"
	"	mov	x8, %[rk]		\n"
	"	ld1	{v3.16b-v6.16b}, [%[ct]], #64\n"
	"	//prfm	PLDL1STRM, [%[ct],#64]	\n"
	"	ld1	{v0.4s, v1.4s}, [x8], #32	\n"
	"	subs	w9, %w[nr], #2		\n"
	"	mov	v7.16b, v3.16b		\n"
	"	mov	v8.16b, v4.16b		\n"
	"	mov	v9.16b, v5.16b		\n"
	"	mov	v10.16b, v6.16b		\n"
	".align 4				\n"
	"1:					\n"
	"	aesd	v3.16b, v0.16b		\n"
	"	aesimc	v3.16b, v3.16b		\n"
	"	aesd	v4.16b, v0.16b		\n"
	"	aesimc	v4.16b, v4.16b		\n"
	"	aesd	v5.16b, v0.16b		\n"
	"	aesimc	v5.16b, v5.16b		\n"
	"	aesd	v6.16b, v0.16b		\n"
	"	aesimc	v6.16b, v6.16b		\n"
	"	ld1	{v0.4s}, [x8], #16	\n"
	"	b.eq	2f			\n"
	"	subs	w9, w9, #2		\n"
	"	aesd	v3.16b, v1.16b		\n"
	"	aesimc	v3.16b, v3.16b		\n"
	"	aesd	v4.16b, v1.16b		\n"
	"	aesimc	v4.16b, v4.16b		\n"
	"	aesd	v5.16b, v1.16b		\n"
	"	aesimc	v5.16b, v5.16b		\n"
	"	aesd	v6.16b, v1.16b		\n"
	"	aesimc	v6.16b, v6.16b		\n"
	"	ld1	{v1.4s}, [x8], #16	\n"
	"	b.pl	1b			\n"
	"					\n"
	"	aesd	v3.16b, v0.16b		\n"
	"	eor	v3.16b, v3.16b, v1.16b	\n"
	"	aesd	v4.16b, v0.16b		\n"
	"	eor	v4.16b, v4.16b, v1.16b	\n"
	"	aesd	v5.16b, v0.16b		\n"
	"	eor	v5.16b, v5.16b, v1.16b	\n"
	"	aesd	v6.16b, v0.16b		\n"
	"	eor	v6.16b, v6.16b, v1.16b	\n"
	"	b	3f			\n"
	"2:					\n"
	"	aesd	v3.16b, v1.16b		\n"
	"	eor	v3.16b, v3.16b, v0.16b	\n"
	"	aesd	v4.16b, v1.16b		\n"
	"	eor	v4.16b, v4.16b, v0.16b	\n"
	"	aesd	v5.16b, v1.16b		\n"
	"	eor	v5.16b, v5.16b, v0.16b	\n"
	"	aesd	v6.16b, v1.16b		\n"
	"	eor	v6.16b, v6.16b, v0.16b	\n"
	"3:					\n"
	"	subs	%[len], %[len], #64	\n"
	"	eor	v3.16b, v3.16b, v2.16b	\n"
	"	eor	v4.16b, v4.16b, v7.16b	\n"
	"	eor	v5.16b, v5.16b, v8.16b	\n"
	"	eor	v6.16b, v6.16b, v9.16b	\n"
	"	mov	v2.16b, v10.16b		\n"
	"	st1	{v3.16b-v6.16b}, [%[pt]], #64	\n"
	"	b.pl	0b			\n"
	"10:					\n"
	"	st1	{v2.16b}, [%[iv]]	\n"
	"	add	%[len], %[len], #64	\n"
	"	//movi	v6.16b, #0		\n"
	"	movi	v10.16b, #0		\n"
	: [len] "=r" (len), [ct] "=r" (input), [pt] "=r" (output),
	  "=m" (*(char(*)[16])iv), "=m" (*(char(*)[len])output)
	: "0" (len), "1" (input), "2" (output), [rk] "r" (rkeys),
	  [nr] "r" (rounds), [iv] "r" (iv),
	  "m" (*(const char(*)[16*(rounds+1)])rkeys), "m" (*(const char(*)[len])input)
	: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "x8", "w9", "cc",
	  "v7", "v8", "v9", "v10"
	);
	//printf("%li bytes left, %li done\n", len, *olen);
	while (len > 0) {
		uchar *ebf = crypto->blkbuf3;
		AES_ARM8_Decrypt_Blk(rkeys, rounds, input, ebf);
		XOR16(iv, ebf, output);
		/* Update last IV */
		memcpy(iv, input, 16);
		//memset(in, 0, 16);
		//LFENCE;
		len -= 16; input += 16; output += 16;
	}
	CLR_NEON10;
	if (pad)
		return dec_fix_olen_pad(olen, pad, output);
	else
		return 0;
	//return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;
}


#else
int  AES_ARM8_CBC_Decrypt(const uchar* rkeys, uint rounds, uchar *iv, uint pad,
			  const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	int r = AES_Gen_CBC_Dec4(AES_ARM8_Decrypt_4Blk, AES_ARM8_Decrypt_Blk, 
				rkeys, rounds, iv, pad, in, out, len, olen);
	CLR_NEON6;
	return r;
}
#endif

#ifdef NO_ASM_CTR
int  AES_ARM8_CTR_Crypt(const uchar* rkeys, uint rounds, uchar *ctr, uint pad,
			const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	*olen = len;
	int r = AES_Gen_CTR_Crypt_Opt(AES_ARM8_Encrypt_4Blk_CTR, AES_ARM8_Encrypt_Blk_CTR, 
				     rkeys, rounds, ctr, in, out, len);
	CLR_NEON10;
	return r;
}
#endif

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

void AES_ARM8_Encrypt_BlkX2(const uchar* rkeys, uint rounds, const uchar in[16], uchar out[16])
{
	AES_ARM8_Encrypt(rkeys, rounds/2, in, out);
	AES_ARM8_Encrypt(rkeys+16+8*rounds, rounds/2, out, out);
}
void AES_ARM8_Decrypt_BlkX2(const uchar* rkeys, uint rounds, const uchar in[16], uchar out[16])
{
	AES_ARM8_Decrypt(rkeys+16+8*rounds, rounds/2, in, out);
	AES_ARM8_Decrypt(rkeys, rounds/2, out, out);
}
void AES_ARM8_Encrypt_4BlkX2(const uchar* rkeys, uint rounds, const uchar in[64], uchar out[64])
{
	AES_ARM8_Encrypt4(rkeys, rounds/2, in, out);
	AES_ARM8_Encrypt4(rkeys+16+8*rounds, rounds/2, out, out);
}
void AES_ARM8_Decrypt_4BlkX2(const uchar* rkeys, uint rounds, const uchar in[64], uchar out[64])
{
	AES_ARM8_Decrypt4(rkeys+16+8*rounds, rounds/2, in, out);
	AES_ARM8_Decrypt4(rkeys, rounds/2, out, out);
}


int  AES_ARM8_ECB_EncryptX2(const uchar* rkeys, uint rounds, uchar *iv, uint pad,
			 const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	int r = AES_Gen_ECB_Enc4(AES_ARM8_Encrypt_4BlkX2, AES_ARM8_Encrypt_BlkX2,
				 rkeys, rounds, pad, in, out, len, olen);
	CLR_NEON6;
	return r;
}
int  AES_ARM8_ECB_DecryptX2(const uchar* rkeys, uint rounds, uchar *iv, uint pad,
			 const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	int r = AES_Gen_ECB_Dec4(AES_ARM8_Decrypt_4BlkX2, AES_ARM8_Decrypt_BlkX2,
				 rkeys, rounds, pad, in, out, len, olen);
	CLR_NEON6;
	return r;
}

int  AES_ARM8_CBC_EncryptX2(const uchar* rkeys, uint rounds, uchar *iv, uint pad,
			 const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	int r = AES_Gen_CBC_Enc(AES_ARM8_Encrypt_BlkX2, rkeys, rounds, iv, pad, in, out, len, olen);
	CLR_NEON3;
	return r;
}
int  AES_ARM8_CBC_DecryptX2(const uchar* rkeys, uint rounds, uchar *iv, uint pad,
			 const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	int r = AES_Gen_CBC_Dec4(AES_ARM8_Decrypt_4BlkX2, AES_ARM8_Decrypt_BlkX2,
				 rkeys, rounds, iv, pad, in, out, len, olen);
	CLR_NEON6;
	return r;
}

int  AES_ARM8_CTR_CryptX2(const uchar* rkeys, uint rounds, uchar *ctr, uint pad,
			const uchar *in, uchar *out, ssize_t len, ssize_t *olen)
{
	*olen = len;
	//int r = AES_Gen_CTR_Crypt(AES_ARM8_Encrypt_BlkX2, rkeys, rounds, ctr, in, out, len);
	int r = AES_Gen_CTR_Crypt_Opt(AES_ARM8_Encrypt_4BlkX2_CTR, AES_ARM8_Encrypt_BlkX2_CTR,
				     rkeys, rounds, ctr, in, out, len);
	CLR_NEON10;
	return r;
}

ciph_desc_t AES_ARM8_Methods[] = {
		{"AES128-ECB"  , 128, 10, 16, 11*16, &aes_stream_ecb, 
			AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Dec,
			AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES128-CBC"  , 128, 10, 16, 11*16, &aes_stream_cbc,
			AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Dec,
			AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES128-CTR"  , 128, 10, 16, 11*16, &aes_stream_ctr,
			AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Enc,
			AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES192-ECB"  , 192, 12, 16, 13*16, &aes_stream_ecb,
			AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Dec,
			AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES192-CBC"  , 192, 12, 16, 13*16, &aes_stream_cbc,
			AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Dec,
			AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES192-CTR"  , 192, 12, 16, 13*16, &aes_stream_ctr,
			AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Enc,
			AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES256-ECB"  , 256, 14, 16, 15*16, &aes_stream_ecb,
			AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Dec,
			AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES256-CBC"  , 256, 14, 16, 15*16, &aes_stream_cbc,
			AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Dec,
			AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES256-CTR"  , 256, 14, 16, 15*16, &aes_stream_ctr,
			AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Enc,
			AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES128+-ECB" , 128, 12, 16, 13*16, &aes_stream_ecb,
			AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Dec,
			AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES128+-CBC" , 128, 12, 16, 13*16, &aes_stream_cbc,
			AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Dec,
			AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES128+-CTR" , 128, 12, 16, 13*16, &aes_stream_ctr,
			AES_ARM8_KeySetup_128_Enc, AES_ARM8_KeySetup_128_Enc,
			AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES192+-ECB" , 192, 15, 16, 16*16, &aes_stream_ecb,
			AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Dec,
			AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES192+-CBC" , 192, 15, 16, 16*16, &aes_stream_cbc,
			AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Dec,
			AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES192+-CTR" , 192, 15, 16, 16*16, &aes_stream_ctr,
			AES_ARM8_KeySetup_192_Enc, AES_ARM8_KeySetup_192_Enc,
			AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES256+-ECB" , 256, 18, 16, 19*16, &aes_stream_ecb,
			AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Dec,
			AES_ARM8_ECB_Encrypt, AES_ARM8_ECB_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES256+-CBC" , 256, 18, 16, 19*16, &aes_stream_cbc,
			AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Dec,
			AES_ARM8_CBC_Encrypt, AES_ARM8_CBC_Decrypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES256+-CTR" , 256, 18, 16, 19*16, &aes_stream_ctr,
			AES_ARM8_KeySetup_256_Enc, AES_ARM8_KeySetup_256_Enc,
			AES_ARM8_CTR_Crypt, AES_ARM8_CTR_Crypt, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES128x2-ECB", 128, 20, 16, 22*16, &aes_stream_ecb,
			AES_ARM8_KeySetupX2_128_Enc, AES_ARM8_KeySetupX2_128_Dec,
			AES_ARM8_ECB_EncryptX2, AES_ARM8_ECB_DecryptX2, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES128x2-CBC", 128, 20, 16, 22*16, &aes_stream_cbc,
			AES_ARM8_KeySetupX2_128_Enc, AES_ARM8_KeySetupX2_128_Dec,
			AES_ARM8_CBC_EncryptX2, AES_ARM8_CBC_DecryptX2, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES128x2-CTR", 128, 20, 16, 22*16, &aes_stream_ctr,
			AES_ARM8_KeySetupX2_128_Enc, AES_ARM8_KeySetupX2_128_Enc,
			AES_ARM8_CTR_CryptX2, AES_ARM8_CTR_CryptX2, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES192x2-ECB", 192, 24, 16, 26*16, &aes_stream_ecb,
			AES_ARM8_KeySetupX2_192_Enc, AES_ARM8_KeySetupX2_192_Dec,
			AES_ARM8_ECB_EncryptX2, AES_ARM8_ECB_DecryptX2, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES192x2-CBC", 192, 24, 16, 26*16, &aes_stream_cbc,
			AES_ARM8_KeySetupX2_192_Enc, AES_ARM8_KeySetupX2_192_Dec,
			AES_ARM8_CBC_EncryptX2, AES_ARM8_CBC_DecryptX2, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES192x2-CTR", 192, 24, 16, 26*16, &aes_stream_ctr,
			AES_ARM8_KeySetupX2_192_Enc, AES_ARM8_KeySetupX2_192_Enc,
			AES_ARM8_CTR_CryptX2, AES_ARM8_CTR_CryptX2, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES256x2-ECB", 256, 28, 16, 30*16, &aes_stream_ecb,
			AES_ARM8_KeySetupX2_256_Enc, AES_ARM8_KeySetupX2_256_Dec,
			AES_ARM8_ECB_EncryptX2, AES_ARM8_ECB_DecryptX2, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES256x2-CBC", 256, 28, 16, 30*16, &aes_stream_cbc,
			AES_ARM8_KeySetupX2_256_Enc, AES_ARM8_KeySetupX2_256_Dec,
			AES_ARM8_CBC_EncryptX2, AES_ARM8_CBC_DecryptX2, AES_Gen_Release,
			AES_ARM8_probe},
		{"AES256x2-CTR", 256, 28, 16, 30*16, &aes_stream_ctr,
			AES_ARM8_KeySetupX2_256_Enc, AES_ARM8_KeySetupX2_256_Enc,
			AES_ARM8_CTR_CryptX2, AES_ARM8_CTR_CryptX2, AES_Gen_Release,
			AES_ARM8_probe},
	      { NULL, /* ... */}
};


