/** aesni.c
 * Implementation of AES en/decryption
 * using intel's AES-NI instruction set.
 * From
 * https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf
 * adapted by
 * Kurt Garloff <kurt@garloff.de>, 7/2014
 */

#include "aesni.h"
#include "secmem.h"
#include <wmmintrin.h>

#ifdef DONTMASK
#define MMCLEAR(xmmreg) xmmreg = _mm_setzero_si128()
#else
#define MMCLEAR(xmmreg) asm volatile ("pxor %0, %0 \n" : "=x"(xmmreg): "0"(xmmreg):)
#endif

#define MMCLEAR3					\
	asm volatile("	pxor %%xmm2, %%xmm2	\n"	\
		"	pxor %%xmm1, %%xmm1	\n"	\
		"	pxor %%xmm0, %%xmm0	\n"	\
		:					\
		:					\
		: "xmm2", "xmm1", "xmm0")

#define MMCLEAR4					\
	asm volatile("	pxor %%xmm3, %%xmm3	\n"	\
		"	pxor %%xmm2, %%xmm2	\n"	\
		"	pxor %%xmm1, %%xmm1	\n"	\
		"	pxor %%xmm0, %%xmm0	\n"	\
		:					\
		:					\
		: "xmm3", "xmm2", "xmm1", "xmm0")

#define MMCLEAR5					\
	asm volatile("	pxor %%xmm4, %%xmm4	\n"	\
		"	pxor %%xmm3, %%xmm3	\n"	\
		"	pxor %%xmm2, %%xmm2	\n"	\
		"	pxor %%xmm1, %%xmm1	\n"	\
		"	pxor %%xmm0, %%xmm0	\n"	\
		:					\
		:					\
		: "xmm4", "xmm3", "xmm2", "xmm1", "xmm0")


static inline __m128i KEY_128_ASSIST(__m128i temp1, __m128i temp2)
{
	register __m128i temp3;
       	temp2 = _mm_shuffle_epi32(temp2 ,0xff);
	temp3 = _mm_slli_si128(temp1, 0x04);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp3 = _mm_slli_si128(temp3, 0x04);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp3 = _mm_slli_si128(temp3, 0x04);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp1 = _mm_xor_si128(temp1, temp2);
	//MMCLEAR(temp3);
	return temp1;
}

void AESNI_128_EKey_Expansion_r(const unsigned char *userkey,
				      unsigned char *ekey,
				      unsigned int rounds)
{
	register __m128i temp1, temp2;
	__m128i *Key_Schedule = (__m128i*)ekey;

	temp1 = _mm_loadu_si128(( __m128i*)userkey);
	Key_Schedule[0] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[1] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x02);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[2] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x04);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[3] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x08);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[4] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[5] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[6] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[7] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[8] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[9] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
	temp1 = KEY_128_ASSIST(temp1, temp2);
	Key_Schedule[10] = temp1;
	if (rounds > 10) {
		temp2 = _mm_aeskeygenassist_si128(temp1, 0x6c);
		temp1 = KEY_128_ASSIST(temp1, temp2);
		Key_Schedule[11] = temp1;
		temp2 = _mm_aeskeygenassist_si128(temp1, 0xd8);
		temp1 = KEY_128_ASSIST(temp1, temp2);
		Key_Schedule[12] = temp1;
	}
	//MMCLEAR(temp2);
	//MMCLEAR(temp1);
	MMCLEAR3;
}

static inline void KEY_192_ASSIST(__m128i *temp1, __m128i *temp2, __m128i *temp3)
{
	register __m128i temp4;
	*temp2 = _mm_shuffle_epi32(*temp2, 0x55);
	 temp4 = _mm_slli_si128(*temp1, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	*temp1 = _mm_xor_si128(*temp1, *temp2);
	*temp2 = _mm_shuffle_epi32(*temp1, 0xff);
	 temp4 = _mm_slli_si128(*temp3, 0x04);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	*temp3 = _mm_xor_si128(*temp3, *temp2);
	//MMCLEAR(temp4);
} 

void AESNI_192_EKey_Expansion_r(const unsigned char *userkey,
				      unsigned char *key,
				      unsigned int rounds)
{
	__m128i temp1, temp2, temp3;
	__m128i *Key_Schedule = ( __m128i*)key;

	temp1 = _mm_loadu_si128(( __m128i*)userkey);
	temp3 = _mm_loadu_si128(( __m128i*)(userkey+16));

	Key_Schedule[0]  = temp1;
       	Key_Schedule[1]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[1]  = ( __m128i) _mm_shuffle_pd((__m128d)Key_Schedule[1],
				(__m128d)temp1, 0);
	Key_Schedule[2]  = ( __m128i) _mm_shuffle_pd((__m128d)temp1,
				(__m128d)temp3, 1);
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x02); 
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[3]  = temp1;
	Key_Schedule[4]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[4]  = ( __m128i) _mm_shuffle_pd((__m128d)Key_Schedule[4],
				(__m128d)temp1, 0);
	Key_Schedule[5]  = ( __m128i) _mm_shuffle_pd((__m128d)temp1,
			 	(__m128d)temp3, 1);
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[6]  = temp1; 
	Key_Schedule[7]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[7]  = ( __m128i) _mm_shuffle_pd((__m128d)Key_Schedule[7],
				(__m128d)temp1, 0);
	Key_Schedule[8]  = ( __m128i) _mm_shuffle_pd((__m128d)temp1,
			 	(__m128d)temp3, 1);
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[9]  = temp1;
	Key_Schedule[10] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[10] = ( __m128i) _mm_shuffle_pd((__m128d)Key_Schedule[10],
				(__m128d)temp1, 0);
	Key_Schedule[11] = ( __m128i) _mm_shuffle_pd((__m128d)temp1,
			 	(__m128d)temp3, 1);
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
	KEY_192_ASSIST(&temp1, &temp2, &temp3);
	Key_Schedule[12] = temp1; 
	if (rounds > 12) {
		Key_Schedule[13] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x1b);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[13] = ( __m128i) _mm_shuffle_pd((__m128d)Key_Schedule[13],
					(__m128d)temp1, 0);
		Key_Schedule[14] = ( __m128i) _mm_shuffle_pd((__m128d)temp1,
				 	(__m128d)temp3, 1);
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x36);
		KEY_192_ASSIST(&temp1, &temp2, &temp3);
		Key_Schedule[15] = temp1;
	}
	//MMCLEAR(temp3);
	//MMCLEAR(temp2);
	//MMCLEAR(temp1);
	MMCLEAR4;
} 


static inline void KEY_256_ASSIST_1(__m128i *temp1, __m128i *temp2)
{
	register __m128i temp4;
	*temp2 = _mm_shuffle_epi32(*temp2, 0xff);
	 temp4 = _mm_slli_si128(*temp1, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp1 = _mm_xor_si128(*temp1, temp4);
	*temp1 = _mm_xor_si128(*temp1, *temp2);
	//MMCLEAR(temp4);
}

static inline void KEY_256_ASSIST_2(__m128i *temp1, __m128i *temp3)
{
	register __m128i temp2, temp4;
	 temp4 = _mm_aeskeygenassist_si128(*temp1, 0x00);
	 temp2 = _mm_shuffle_epi32(temp4, 0xaa);
	 temp4 = _mm_slli_si128(*temp3, 0x04);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	 temp4 = _mm_slli_si128(temp4, 0x04);
	*temp3 = _mm_xor_si128(*temp3, temp4);
	*temp3 = _mm_xor_si128(*temp3, temp2);
	//MMCLEAR(temp4);
	//MMCLEAR(temp2);
}

void AESNI_256_EKey_Expansion_r(const unsigned char *userkey,
				      unsigned char *key,
				      unsigned int rounds)
{
	__m128i temp1, temp2, temp3;
	__m128i *Key_Schedule = (__m128i*)key;

	temp1 = _mm_loadu_si128((__m128i*)userkey);
	temp3 = _mm_loadu_si128((__m128i*)(userkey+16));

	Key_Schedule[0]  = temp1;
	Key_Schedule[1]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[2]  = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[3]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[4]  = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[5]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[6]  = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[7]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[8]  = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[9]  = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[10] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[11] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[12] = temp1;
	KEY_256_ASSIST_2(&temp1, &temp3);
	Key_Schedule[13] = temp3;
	temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
	KEY_256_ASSIST_1(&temp1, &temp2);
	Key_Schedule[14] = temp1;
	if (rounds > 14) {
		KEY_256_ASSIST_2(&temp1, &temp3);
		Key_Schedule[15] = temp3;
		temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
		KEY_256_ASSIST_1(&temp1, &temp2);
		Key_Schedule[16] = temp1;
		if (rounds > 16) {
			KEY_256_ASSIST_2(&temp1, &temp3);
			Key_Schedule[17] = temp3;
			temp2 = _mm_aeskeygenassist_si128(temp3, 0x1b);
			KEY_256_ASSIST_1(&temp1, &temp2);
			Key_Schedule[18] = temp1;
		}
	}
	MMCLEAR5;
} 

inline void AESNI_EKey_DKey(const unsigned char* ekey,
			   unsigned char* dkey,
			   int rounds)
{
	const __m128i *EKeys = (const __m128i*)ekey;
	__m128i *DKeys = (__m128i*)dkey;
	int r;
	DKeys[rounds] = EKeys[0];
	for (r = 1; r < rounds; ++r)
		DKeys[rounds-r] = _mm_aesimc_si128(EKeys[r]);
	DKeys[0] = EKeys[rounds];
}


void AESNI_128_DKey_Expansion_r(const unsigned char *userkey,
				unsigned char *dkey,
				unsigned int rounds)
{
	//unsigned char ekey[13*16];
	AESNI_128_EKey_Expansion_r(userkey, (unsigned char*)crypto->xkeys, rounds);
	AESNI_EKey_DKey((unsigned char*)crypto->xkeys, dkey, rounds);
}

void AESNI_192_DKey_Expansion_r(const unsigned char *userkey,
				unsigned char *dkey,
				unsigned int rounds)
{
	/* FIXME: Need secmem */
	//unsigned char ekey[16*16];
	AESNI_192_EKey_Expansion_r(userkey, (unsigned char*)crypto->xkeys, rounds);
	AESNI_EKey_DKey((unsigned char*)crypto->xkeys, dkey, rounds);
}

void AESNI_256_DKey_Expansion_r(const unsigned char *userkey,
				unsigned char *dkey,
				unsigned int rounds)
{
	/* FIXME: Need secmem */
	//unsigned char ekey[19*16];
	AESNI_256_EKey_Expansion_r(userkey, (unsigned char*)crypto->xkeys, rounds);
	AESNI_EKey_DKey((unsigned char*)crypto->xkeys, dkey, rounds);
}


static inline
__m128i Encrypt_Block(const __m128i in, const unsigned char *ekey, int rounds)
{
	int r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m128i tmp = _mm_xor_si128(in, rkeys[0]);
	for (r = 1; r < rounds; ++r)
		tmp = _mm_aesenc_si128(tmp, rkeys[r]);
	return _mm_aesenclast_si128(tmp, rkeys[rounds]);
}

static inline
__m128i Decrypt_Block(const __m128i in, const unsigned char *dkey, int rounds)
{
	int r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i tmp = _mm_xor_si128(in, rkeys[0]);
	for (r = 1; r < rounds; ++r)
		tmp = _mm_aesdec_si128(tmp, rkeys[r]);
	return _mm_aesdeclast_si128(tmp, rkeys[rounds]);
}

static inline
void Encrypt_4Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     const unsigned char *ekey, int rounds)
{
	int r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	for (r = 1; r < rounds; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesenc_si128(*i0, rk);
		*i1 = _mm_aesenc_si128(*i1, rk);
		*i2 = _mm_aesenc_si128(*i2, rk);
		*i3 = _mm_aesenc_si128(*i3, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+rounds);
	*i0 = _mm_aesenclast_si128(*i0, rk);
	*i1 = _mm_aesenclast_si128(*i1, rk);
	*i2 = _mm_aesenclast_si128(*i2, rk);
	*i3 = _mm_aesenclast_si128(*i3, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm5, %%xmm5\n" :::"xmm5");
}

static inline
void Decrypt_4Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     const unsigned char *dkey, int rounds)
{
	int r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	for (r = 1; r < rounds; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+rounds);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm5, %%xmm5\n" :::"xmm5");
}

static inline
void Encrypt_8Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
		     const unsigned char *ekey, int rounds)
{
	int r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (r = 1; r < rounds; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesenc_si128(*i0, rk);
		*i1 = _mm_aesenc_si128(*i1, rk);
		*i2 = _mm_aesenc_si128(*i2, rk);
		*i3 = _mm_aesenc_si128(*i3, rk);
		*i4 = _mm_aesenc_si128(*i4, rk);
		*i5 = _mm_aesenc_si128(*i5, rk);
		*i6 = _mm_aesenc_si128(*i6, rk);
		*i7 = _mm_aesenc_si128(*i7, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+rounds);
	*i0 = _mm_aesenclast_si128(*i0, rk);
	*i1 = _mm_aesenclast_si128(*i1, rk);
	*i2 = _mm_aesenclast_si128(*i2, rk);
	*i3 = _mm_aesenclast_si128(*i3, rk);
	*i4 = _mm_aesenclast_si128(*i4, rk);
	*i5 = _mm_aesenclast_si128(*i5, rk);
	*i6 = _mm_aesenclast_si128(*i6, rk);
	*i7 = _mm_aesenclast_si128(*i7, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm0, %%xmm0\n" :::"xmm0");
}


static inline
void Decrypt_8Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
		     const unsigned char *dkey, int rounds)
{
	int r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (r = 1; r < rounds; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
		*i4 = _mm_aesdec_si128(*i4, rk);
		*i5 = _mm_aesdec_si128(*i5, rk);
		*i6 = _mm_aesdec_si128(*i6, rk);
		*i7 = _mm_aesdec_si128(*i7, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+rounds);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	*i4 = _mm_aesdeclast_si128(*i4, rk);
	*i5 = _mm_aesdeclast_si128(*i5, rk);
	*i6 = _mm_aesdeclast_si128(*i6, rk);
	*i7 = _mm_aesdeclast_si128(*i7, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm0, %%xmm0\n" :::"xmm0");
}


static inline
__m128i _mkmask(char ln)
{
	ln &= 0x0f;
	return (ln >= 8? 
			_mm_set_epi64x((1ULL<<(8*ln-64))-1, 0xffffffffffffffffULL):
			_mm_set_epi64x(0ULL, (1ULL<<(8*ln))-1)
		);

}

void AESNI_ECB_encrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, int rounds)
{
	while (len >= sizeof(__m128i)) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		blk = Encrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= sizeof(__m128i);
		in  += sizeof(__m128i);
		out += sizeof(__m128i);
	}
	if (len) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		__m128i mask = _mkmask(len);
		blk = _mm_and_si128(blk, mask);
		blk = Encrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
	}
}

void AESNI_ECB_encrypt(const unsigned char* in, unsigned char* out,
		       ssize_t len, const unsigned char* key, int rounds)
{
	while (len >= 4*sizeof(__m128i)) {
		__m128i blk0 = _mm_loadu_si128((const __m128i*)in);
		__m128i blk1 = _mm_loadu_si128((const __m128i*)(in+sizeof(__m128i)));
		__m128i blk2 = _mm_loadu_si128((const __m128i*)(in+2*sizeof(__m128i)));
		__m128i blk3 = _mm_loadu_si128((const __m128i*)(in+3*sizeof(__m128i)));
		Encrypt_4Blocks(&blk0, &blk1, &blk2, &blk3, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk0);
		_mm_storeu_si128((__m128i*)(out+sizeof(__m128i)), blk1);
		_mm_storeu_si128((__m128i*)(out+2*sizeof(__m128i)), blk2);
		_mm_storeu_si128((__m128i*)(out+3*sizeof(__m128i)), blk3);
		len -= 4*sizeof(__m128i);
		in  += 4*sizeof(__m128i);
		out += 4*sizeof(__m128i);
	}
	while (len > 0) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		if (len < sizeof(__m128)) {
			__m128i mask = _mkmask(len);
			blk = _mm_and_si128(blk, mask);
		}
		blk = Encrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= sizeof(__m128i);
		in  += sizeof(__m128i);
		out += sizeof(__m128i);
	}
}

void AESNI_ECB_decrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, int rounds)
{
	while (len > 0) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		blk = Decrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= sizeof(__m128i);
		in  += sizeof(__m128i);
		out += sizeof(__m128i);
	}
}

void AESNI_ECB_decrypt(const unsigned char* in, unsigned char* out,
		       ssize_t len, const unsigned char* key, int rounds)
{
	while (len >= 4*sizeof(__m128i)) {
		__m128i blk0 = _mm_loadu_si128((const __m128i*)in);
		__m128i blk1 = _mm_loadu_si128((const __m128i*)(in+sizeof(__m128i)));
		__m128i blk2 = _mm_loadu_si128((const __m128i*)(in+2*sizeof(__m128i)));
		__m128i blk3 = _mm_loadu_si128((const __m128i*)(in+3*sizeof(__m128i)));
		Decrypt_4Blocks(&blk0, &blk1, &blk2, &blk3, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk0);
		_mm_storeu_si128((__m128i*)(out+sizeof(__m128i)), blk1);
		_mm_storeu_si128((__m128i*)(out+2*sizeof(__m128i)), blk2);
		_mm_storeu_si128((__m128i*)(out+3*sizeof(__m128i)), blk3);
		len -= 4*sizeof(__m128i);
		in  += 4*sizeof(__m128i);
		out += 4*sizeof(__m128i);
	}
	while (len > 0) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		blk = Decrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= sizeof(__m128i);
		in  += sizeof(__m128i);
		out += sizeof(__m128i);
	}
}

void AESNI_CBC_encrypt(const unsigned char* in, unsigned char* out,
		       const unsigned char* iv,
		       ssize_t len, const unsigned char* key, int rounds)
{
	register __m128i ivb = _mm_loadu_si128((const __m128i*)iv);
	while (len >= sizeof(__m128i)) {
		register __m128i dat = _mm_loadu_si128((const __m128i*)in);
		ivb = _mm_xor_si128(ivb, dat);
		ivb = Encrypt_Block(ivb, key, rounds);
		_mm_storeu_si128((__m128i*)out, ivb);
		len -= sizeof(__m128i);
		in  += sizeof(__m128i);
		out += sizeof(__m128i);
	}
	if (len) {
		register __m128i dat = _mm_loadu_si128((const __m128i*)in);
		__m128i mask = _mkmask(len);
		dat = _mm_and_si128(dat, mask);
		ivb = _mm_xor_si128(ivb, dat);
		ivb = Encrypt_Block(ivb, key, rounds);
		_mm_storeu_si128((__m128i*)out, ivb);
	}

}

void AESNI_CBC_decrypt(const unsigned char* in, unsigned char* out,
		       const unsigned char* iv,
		       ssize_t len, const unsigned char* key, int rounds)
{
	register __m128i ivb = _mm_loadu_si128((const __m128i*)iv);
	/* TODO: We could do 4 blocks in parallel for CBC decrypt (NOT: encrypt) */
	while (len >= 4*sizeof(__m128i)) {
		__m128i dat0 = _mm_loadu_si128((const __m128i*)in);
		__m128i dat1 = _mm_loadu_si128((const __m128i*)in+1);
		__m128i dat2 = _mm_loadu_si128((const __m128i*)in+2);
		__m128i dat3 = _mm_loadu_si128((const __m128i*)in+3);
		__m128i b0 = dat0, b1= dat1, b2 = dat2, b3 = dat3;
		Decrypt_4Blocks(&dat0, &dat1, &dat2, &dat3, key, rounds);
		_mm_storeu_si128((__m128i*)out  , _mm_xor_si128(dat0, ivb));
		_mm_storeu_si128((__m128i*)out+1, _mm_xor_si128(dat1, b0));
		_mm_storeu_si128((__m128i*)out+2, _mm_xor_si128(dat2, b1));
		_mm_storeu_si128((__m128i*)out+3, _mm_xor_si128(dat3, b2));
		ivb = b3;
		len -= 4*sizeof(__m128i);
		in  += 4*sizeof(__m128i);
		out += 4*sizeof(__m128i);
	}
	while (len > 0) {
		__m128i dat = _mm_loadu_si128((const __m128i*)in);
		register __m128i blk = Decrypt_Block(dat, key, rounds);
		_mm_storeu_si128((__m128i*)out, _mm_xor_si128(blk, ivb));
		ivb = dat;
		len -= sizeof(__m128i);
		in  += sizeof(__m128i);
		out += sizeof(__m128i);
	}
}

#ifdef DEBUG_CBLK_SETUP
#include <stdio.h>
void static _debug_print(const __m128i m)
{
	union { 
		unsigned char a[16];
		unsigned int b[4];
	} val;
	_mm_storeu_si128((__m128i*)&val, m);
	int i;
	printf("0x");
	for (i = 15; i >= 0; --i)
		printf("%02x ", val.a[i]);
	printf(" %08x %08x %08x %08x ", val.b[3], val.b[2], val.b[1], val.b[0]);
	for (i = 0; i < 16; ++i)
		printf(" %02x", val.a[i]);
	printf("\n");
}
#endif


#include <emmintrin.h>
#include <smmintrin.h>

/* CTR is big-endian */
void AESNI_CTR_prep_2(const unsigned char* iv, const unsigned char* nonce,
		      unsigned char* ctr, unsigned long long val)
{
	__m128i BSWAP_EPI64, VAL, tmp;
	VAL = _mm_set_epi64x(val, 0);
	BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8); 
	
	tmp = _mm_setzero_si128();
	tmp = _mm_insert_epi64(tmp, *(unsigned long long*)iv, 1);
	tmp = _mm_insert_epi32(tmp, *(unsigned int*)nonce, 1);
	/* Shift left by 32 bits */
	tmp = _mm_srli_si128(tmp, 4);
	tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
	tmp = _mm_add_epi64(tmp, VAL);
	_mm_storeu_si128((__m128i*)ctr, tmp);
#ifdef DEBUG_CBLK_SETUP
	static int c = 0;
	if (!c++) {
		_debug_print(tmp);
		__m128i ONE = _mm_set_epi32(0, 1, 0, 0);
		tmp = _mm_add_epi64(tmp, ONE);
		tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
		_debug_print(tmp);
	}
#endif
}

/* CTR is big-endian */
void AESNI_CTR_prep(const unsigned char* iv, unsigned char* ctr, unsigned long long val)
{
	__m128i BSWAP_EPI64, VAL, MSK, tmp;
	VAL = _mm_set_epi64x(val, 0);
	MSK = _mm_set_epi32(0xffffffff, 0, 0xffffffff, 0xffffffff);
	BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8); 
	
	tmp = _mm_loadu_si128((__m128i*)iv);
	tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
	tmp = _mm_and_si128(tmp, MSK);
	tmp = _mm_add_epi64(tmp, VAL);
	_mm_storeu_si128((__m128i*)ctr, tmp);
#ifdef DEBUG_CBLK_SETUP
	static int c = 0;
	if (!c++) {
		_debug_print(tmp);
		__m128i ONE = _mm_set_epi32(0, 1, 0, 0);
		tmp = _mm_add_epi64(tmp, ONE);
		tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
		_debug_print(tmp);
	}
#endif
}

void AESNI_CTR_crypt(const unsigned char* in, unsigned char* out,
		     unsigned char* ctr,
		     ssize_t len, const unsigned char* key, int rounds)
{
	__m128i ONE = _mm_set_epi32(0, 1, 0, 0);
	__m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8); 
	__m128i cblk = _mm_loadu_si128((__m128i*)ctr);
	while (len >= 4*sizeof(__m128i)) {
		__m128i tmp0 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp1 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp2 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp3 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp4 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp5 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp6 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp7 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		Encrypt_8Blocks(&tmp0, &tmp1, &tmp2, &tmp3, &tmp4, &tmp5, &tmp6, &tmp7, key, rounds);
		tmp0 = _mm_xor_si128(tmp0, _mm_loadu_si128((__m128i*)in));
		tmp1 = _mm_xor_si128(tmp1, _mm_loadu_si128((__m128i*)in+1));
		tmp2 = _mm_xor_si128(tmp2, _mm_loadu_si128((__m128i*)in+2));
		tmp3 = _mm_xor_si128(tmp3, _mm_loadu_si128((__m128i*)in+3));
		_mm_storeu_si128((__m128i*)out  , tmp0);
		_mm_storeu_si128((__m128i*)out+1, tmp1);
		_mm_storeu_si128((__m128i*)out+2, tmp2);
		_mm_storeu_si128((__m128i*)out+3, tmp3);
		tmp4 = _mm_xor_si128(tmp4, _mm_loadu_si128((__m128i*)in+4));
		tmp5 = _mm_xor_si128(tmp5, _mm_loadu_si128((__m128i*)in+5));
		tmp6 = _mm_xor_si128(tmp6, _mm_loadu_si128((__m128i*)in+6));
		tmp7 = _mm_xor_si128(tmp7, _mm_loadu_si128((__m128i*)in+7));
		_mm_storeu_si128((__m128i*)out+4, tmp4);
		_mm_storeu_si128((__m128i*)out+5, tmp5);
		_mm_storeu_si128((__m128i*)out+6, tmp6);
		_mm_storeu_si128((__m128i*)out+7, tmp7);
		len -= 8*sizeof(__m128i);
		in  += 8*sizeof(__m128i);
		out += 8*sizeof(__m128i);
	}
	while (len > 0) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		tmp = Encrypt_Block(tmp, key, rounds);
		if (len < sizeof(__m128i)) {
			__m128i mask = _mkmask(len);
			mask = _mm_and_si128(mask, _mm_loadu_si128((__m128i*)in));
			tmp = _mm_xor_si128(tmp, mask);
		} else
			tmp = _mm_xor_si128(tmp, _mm_loadu_si128((__m128i*)in));
		_mm_storeu_si128((__m128i*)out, tmp);
		len -= sizeof(__m128i);
		in  += sizeof(__m128i);
		out += sizeof(__m128i);
	}
	_mm_storeu_si128((__m128i*)ctr, cblk);
}

void AESNI_CTR_crypt4(const unsigned char* in, unsigned char* out,
		     unsigned char* ctr,
		     ssize_t len, const unsigned char* key, int rounds)
{
	__m128i ONE = _mm_set_epi32(0, 1, 0, 0);
	__m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8); 
	__m128i cblk = _mm_loadu_si128((__m128i*)ctr);
	while (len >= 4*sizeof(__m128i)) {
		__m128i tmp0 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp1 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp2 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		__m128i tmp3 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		Encrypt_4Blocks(&tmp0, &tmp1, &tmp2, &tmp3, key, rounds);
		tmp0 = _mm_xor_si128(tmp0, _mm_loadu_si128((__m128i*)in));
		tmp1 = _mm_xor_si128(tmp1, _mm_loadu_si128((__m128i*)in+1));
		tmp2 = _mm_xor_si128(tmp2, _mm_loadu_si128((__m128i*)in+2));
		tmp3 = _mm_xor_si128(tmp3, _mm_loadu_si128((__m128i*)in+3));
		_mm_storeu_si128((__m128i*)out  , tmp0);
		_mm_storeu_si128((__m128i*)out+1, tmp1);
		_mm_storeu_si128((__m128i*)out+2, tmp2);
		_mm_storeu_si128((__m128i*)out+3, tmp3);
		len -= 4*sizeof(__m128i);
		in  += 4*sizeof(__m128i);
		out += 4*sizeof(__m128i);
	}
	while (len > 0) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		tmp = Encrypt_Block(tmp, key, rounds);
		if (len < sizeof(__m128i)) {
			__m128i mask = _mkmask(len);
			mask = _mm_and_si128(mask, _mm_loadu_si128((__m128i*)in));
			tmp = _mm_xor_si128(tmp, mask);
		} else
			tmp = _mm_xor_si128(tmp, _mm_loadu_si128((__m128i*)in));
		_mm_storeu_si128((__m128i*)out, tmp);
		len -= sizeof(__m128i);
		in  += sizeof(__m128i);
		out += sizeof(__m128i);
	}
	_mm_storeu_si128((__m128i*)ctr, cblk);
}

void AESNI_CTR_crypt_old(const unsigned char* in, unsigned char* out,
		         unsigned char* ctr,
		         ssize_t len, const unsigned char* key, int rounds)
{
	__m128i ONE = _mm_set_epi32(0, 1, 0, 0);
	__m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8); 
	__m128i cblk = _mm_loadu_si128((__m128i*)ctr);
	/* TODO: We could process 4 blocks at once here as well */
	while (len >= sizeof(__m128i)) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		tmp = Encrypt_Block(tmp, key, rounds);
		tmp = _mm_xor_si128(tmp, _mm_loadu_si128((__m128i*)in));
		_mm_storeu_si128((__m128i*)out, tmp);
		len -= sizeof(__m128i);
		in  += sizeof(__m128i);
		out += sizeof(__m128i);
	}
	if (len) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		tmp = Encrypt_Block(tmp, key, rounds);
		__m128i mask = _mkmask(len);
		mask = _mm_and_si128(mask, _mm_loadu_si128((__m128i*)in));
		tmp = _mm_xor_si128(tmp, mask);
		_mm_storeu_si128((__m128i*)out, tmp);
	}
	_mm_storeu_si128((__m128i*)ctr, cblk);
}

