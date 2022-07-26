/** aesni.c
 * Implementation of AES en/decryption
 * using intel's AES-NI instruction set.
 * From
 * https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf
 * adapted by
 * Kurt Garloff <kurt@garloff.de>, 7/2014
 */

#include "aes.h"
#include "aesni.h"
#include "secmem.h"
#include <string.h>

#include "archdep.h"

#if defined(__x86_64__) || defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)
#include <wmmintrin.h>
#if defined(__AVX2__) && !defined(NO_AVX2)
#include <immintrin.h>
static int probe_aes_ni()
{
	return !have_aesni || !have_avx2;
}
#else	/* AVX2 */
#include <smmintrin.h>
static int probe_aes_ni()
{
	return !have_aesni;
}
#endif	/* AVX2 */
#endif	/* x86 */

/* Unaligned 128bit integer type, missing from gcc < 5 emmintrin.h */
typedef long long __m128i_u __attribute__ ((__vector_size__ (16), __may_alias__, __aligned__ (1)));

#define MMCLEAR(xmmreg) xmmreg = _mm_setzero_si128()
#define MM256CLEAR(xmmreg) xmmreg = _mm256_setzero_si256()

#define SIZE128 (ssize_t)sizeof(__m128i)
#define SIZE256 (ssize_t)sizeof(__m256i)

#define MMCLEAR3					\
	asm volatile("	pxor %%xmm2, %%xmm2	\n"	\
		"	pxor %%xmm1, %%xmm1	\n"	\
		"	pxor %%xmm0, %%xmm0	\n"	\
		: : : "xmm2", "xmm1", "xmm0")

#define MMCLEAR4					\
	asm volatile("	pxor %%xmm3, %%xmm3	\n"	\
		"	pxor %%xmm2, %%xmm2	\n"	\
		"	pxor %%xmm1, %%xmm1	\n"	\
		"	pxor %%xmm0, %%xmm0	\n"	\
		: : : "xmm3", "xmm2", "xmm1", "xmm0")

#define MMCLEAR5					\
	asm volatile("	pxor %%xmm4, %%xmm4	\n"	\
		"	pxor %%xmm3, %%xmm3	\n"	\
		"	pxor %%xmm2, %%xmm2	\n"	\
		"	pxor %%xmm1, %%xmm1	\n"	\
		"	pxor %%xmm0, %%xmm0	\n"	\
		: : : "xmm4", "xmm3", "xmm2", "xmm1", "xmm0")


#define MMCLEARALL_MAN					\
	asm volatile("	pxor %%xmm7, %%xmm7	\n"	\
		"	pxor %%xmm6, %%xmm6	\n"	\
		"	pxor %%xmm5, %%xmm5	\n"	\
		"	pxor %%xmm4, %%xmm4	\n"	\
		"	pxor %%xmm3, %%xmm3	\n"	\
		"	pxor %%xmm2, %%xmm2	\n"	\
		"	pxor %%xmm1, %%xmm1	\n"	\
		"	pxor %%xmm0, %%xmm0	\n"	\
		: : : "xmm7", "xmm6", "xmm5", "xmm4", "xmm3", "xmm2", "xmm1", "xmm0")

#if defined(__x86_64__)
#define MMCLEARALL_MAN2					\
	asm volatile("	pxor %%xmm15, %%xmm15	\n"	\
		"	pxor %%xmm14, %%xmm14	\n"	\
		"	pxor %%xmm13, %%xmm13	\n"	\
		"	pxor %%xmm12, %%xmm12	\n"	\
		"	pxor %%xmm11, %%xmm11	\n"	\
		"	pxor %%xmm10, %%xmm10	\n"	\
		"	pxor %%xmm9, %%xmm9	\n"	\
		"	pxor %%xmm8, %%xmm8	\n"	\
		: : : "xmm15", "xmm14", "xmm13", "xmm12", "xmm11", "xmm10", "xmm9", "xmm8");
#else
#define MMCLEARALL_MAN2 do {} while(0)
#endif

#if defined(__AVX2__) && !defined(NO_AVX2)
#define MMCLEARALL _mm256_zeroall()
#define MM256CLEAR5						\
	asm volatile("	vpxor %%ymm4, %%ymm4, %%ymm4	\n"	\
		"	vpxor %%ymm3, %%ymm3, %%ymm3	\n"	\
		"	vpxor %%ymm2, %%ymm2, %%ymm2	\n"	\
		"	vpxor %%ymm1, %%ymm1, %%ymm1	\n"	\
		"	vpxor %%ymm0, %%ymm0, %%ymm0	\n"	\
		: : : "ymm4", "ymm3", "ymm2", "ymm1", "ymm0")
#else
#define MMCLEARALL do { MMCLEARALL_MAN; MMCLEARALL_MAN2; } while(0)
#endif


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

static
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
	MMCLEAR(temp2);
	MMCLEAR(temp1);
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
	MMCLEAR(temp4);
} 

static
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
	MMCLEAR(temp3);
	MMCLEAR(temp2);
	MMCLEAR(temp1);
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
}

static
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
	MMCLEAR(temp3);
	MMCLEAR(temp2);
	MMCLEAR(temp1);
} 

static
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

static
void AESNI_128_DKey_Expansion_r(const unsigned char *userkey,
				unsigned char *dkey,
				unsigned int rounds)
{
	AESNI_128_EKey_Expansion_r(userkey, (unsigned char*)crypto->xkeys, rounds);
	AESNI_EKey_DKey((unsigned char*)crypto->xkeys, dkey, rounds);
}

static
void AESNI_192_DKey_Expansion_r(const unsigned char *userkey,
				unsigned char *dkey,
				unsigned int rounds)
{
	AESNI_192_EKey_Expansion_r(userkey, (unsigned char*)crypto->xkeys, rounds);
	AESNI_EKey_DKey((unsigned char*)crypto->xkeys, dkey, rounds);
}

static
void AESNI_256_DKey_Expansion_r(const unsigned char *userkey,
				unsigned char *dkey,
				unsigned int rounds)
{
	AESNI_256_EKey_Expansion_r(userkey, (unsigned char*)crypto->xkeys, rounds);
	AESNI_EKey_DKey((unsigned char*)crypto->xkeys, dkey, rounds);
}

#ifdef DEBUG
#include <stdio.h>
void static _debug_print(const __m128i m, const char* msg)
{
	union { 
		unsigned char a[16];
		unsigned int b[4];
	} val;
	_mm_storeu_si128((__m128i*)&val, m);
	int i;
	printf("%s 0x", msg);
	for (i = 15; i >= 0; --i)
		printf("%02x ", val.a[i]);
	printf(" %08x %08x %08x %08x ", val.b[3], val.b[2], val.b[1], val.b[0]);
	for (i = 0; i < 16; ++i)
		printf(" %02x", val.a[i]);
	printf("\n");
}
#endif

typedef __m128i (crypt_blk_fn)(const __m128i in, const unsigned char *rkeys, unsigned int rounds);
typedef void (crypt_4blks_fn)(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
			      const unsigned char *rkeys, unsigned int rounds);
typedef void (crypt_8blks_fn)(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
			      __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
			      const unsigned char *rkeys, unsigned int rounds);

static inline
__m128i Encrypt_Block(const __m128i in, const unsigned char *ekey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)ekey;
	//register __m128i rk = _mm_loadu_si128(rkeys++);
	register __m128i tmp = _mm_xor_si128(in, *rkeys++);
	//rk =  _mm_loadu_si128(rkeys++);
	for (r = 1; r < rounds; ++r) {
		tmp = _mm_aesenc_si128(tmp, *rkeys++);
		//rk =  _mm_loadu_si128(rkeys++);
	}
	tmp = _mm_aesenclast_si128(tmp, *rkeys);
	//MMCLEAR(rk);
	return tmp;
}

static inline
__m128i Decrypt_Block(const __m128i in, const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey;
	//register __m128i rk = _mm_loadu_si128(rkeys++);
	register __m128i tmp = _mm_xor_si128(in, *rkeys++);
	//rk =  _mm_loadu_si128(rkeys++);
	for (r = 1; r < rounds; ++r) {
		tmp = _mm_aesdec_si128(tmp, *rkeys++);
		//rk =  _mm_loadu_si128(rkeys++);
	}
	tmp = _mm_aesdeclast_si128(tmp, *rkeys);
	//MMCLEAR(rk);
	return tmp;
}

#ifdef UNUSED
static inline
void Encrypt_4Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     const unsigned char *ekey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys++);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	rk = _mm_loadu_si128(rkeys++);
	for (r = 1; r < rounds; ++r) {
		*i0 = _mm_aesenc_si128(*i0, rk);
		*i1 = _mm_aesenc_si128(*i1, rk);
		*i2 = _mm_aesenc_si128(*i2, rk);
		*i3 = _mm_aesenc_si128(*i3, rk);
		rk = _mm_loadu_si128(rkeys++);
	}
	/* Last round ... */
	*i0 = _mm_aesenclast_si128(*i0, rk);
	*i1 = _mm_aesenclast_si128(*i1, rk);
	*i2 = _mm_aesenclast_si128(*i2, rk);
	*i3 = _mm_aesenclast_si128(*i3, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm5, %%xmm5\n" :::"xmm5");
}
#endif

static inline
void Decrypt_4Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys++);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	rk = _mm_loadu_si128(rkeys++);
	for (r = 1; r < rounds; ++r) {
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
		rk = _mm_loadu_si128(rkeys++);
	}
	/* Last round ... */
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	MMCLEAR(rk);
}

static inline
void Encrypt_8Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
		     const unsigned char *ekey, unsigned int rounds)
{
	int r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m128i rk /*asm("xmm0")*/ = _mm_loadu_si128(rkeys++);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	rk = _mm_loadu_si128(rkeys++);
	for (r = rounds-1; r > 0; --r) {
		*i0 = _mm_aesenc_si128(*i0, rk);
		*i1 = _mm_aesenc_si128(*i1, rk);
		*i2 = _mm_aesenc_si128(*i2, rk);
		*i3 = _mm_aesenc_si128(*i3, rk);
		*i4 = _mm_aesenc_si128(*i4, rk);
		*i5 = _mm_aesenc_si128(*i5, rk);
		*i6 = _mm_aesenc_si128(*i6, rk);
		*i7 = _mm_aesenc_si128(*i7, rk);
		rk = _mm_loadu_si128(rkeys++);
	}
	/* Last round ... */
	*i0 = _mm_aesenclast_si128(*i0, rk);
	*i1 = _mm_aesenclast_si128(*i1, rk);
	*i2 = _mm_aesenclast_si128(*i2, rk);
	*i3 = _mm_aesenclast_si128(*i3, rk);
	*i4 = _mm_aesenclast_si128(*i4, rk);
	*i5 = _mm_aesenclast_si128(*i5, rk);
	*i6 = _mm_aesenclast_si128(*i6, rk);
	*i7 = _mm_aesenclast_si128(*i7, rk);
	MMCLEAR(rk);
}

static inline
void Decrypt_8Blocks(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		     __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
		     const unsigned char *dkey, unsigned int rounds)
{
	int r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i rk /*asm("xmm0")*/ = _mm_loadu_si128(rkeys++);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	rk = _mm_loadu_si128(rkeys++);
	for (r = rounds-1; r >0; --r) {
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
		*i4 = _mm_aesdec_si128(*i4, rk);
		*i5 = _mm_aesdec_si128(*i5, rk);
		*i6 = _mm_aesdec_si128(*i6, rk);
		*i7 = _mm_aesdec_si128(*i7, rk);
		rk = _mm_loadu_si128(rkeys++);
	}
	/* Last round ... */
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	*i4 = _mm_aesdeclast_si128(*i4, rk);
	*i5 = _mm_aesdeclast_si128(*i5, rk);
	*i6 = _mm_aesdeclast_si128(*i6, rk);
	*i7 = _mm_aesdeclast_si128(*i7, rk);
	MMCLEAR(rk);
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
static inline
__m128i _mkpad(char ln)
{
	uchar by = 16 - (ln & 0x0f);
	return _mm_set_epi8(by, by, by, by, by, by, by, by,
			    by, by, by, by, by, by, by, by);
}

#if 0
static
void AESNI_ECB_Encrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, unsigned int rounds)
{
	while (len >= SIZE128) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		blk = Encrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	if (len) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		__m128i mask = _mkmask(len);
		__m128i pad = _mkpad(len);
		__m128i imask = _mm_set_epi64x(0xffffffffffffffffULL, 0xffffffffffffffffULL);
		imask = _mm_xor_si128(imask, mask);
		pad = _mm_and_si128(pad, imask);
		blk = _mm_and_si128(blk, mask);
		blk = _mm_or_si128(blk, pad);
		blk = Encrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
	}
}

static
void AESNI_ECB_Decrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, unsigned int rounds)
{
	while (len > 0) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		blk = Decrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
}
#endif


static inline
int  AESNI_ECB_Crypt_Tmpl(crypt_8blks_fn *crypt8, crypt_blk_fn *crypt, int enc,
			  const unsigned char* key, unsigned int rounds,
			  unsigned int pad,
			  const unsigned char* in, unsigned char* out,
			  ssize_t len, ssize_t *olen)
{
	*olen = len;
	while (len >= 8*SIZE128) {
		__m128i blk0 = _mm_loadu_si128((const __m128i*)in);
		__m128i blk1 = _mm_loadu_si128((const __m128i*)(in+SIZE128));
		__m128i blk2 = _mm_loadu_si128((const __m128i*)(in+2*SIZE128));
		__m128i blk3 = _mm_loadu_si128((const __m128i*)(in+3*SIZE128));
		__m128i blk4 = _mm_loadu_si128((const __m128i*)(in+4*SIZE128));
		__m128i blk5 = _mm_loadu_si128((const __m128i*)(in+5*SIZE128));
		__m128i blk6 = _mm_loadu_si128((const __m128i*)(in+6*SIZE128));
		__m128i blk7 = _mm_loadu_si128((const __m128i*)(in+7*SIZE128));
		crypt8(&blk0, &blk1, &blk2, &blk3, &blk4, &blk5, &blk6, &blk7, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk0);
		_mm_storeu_si128((__m128i*)(out+SIZE128), blk1);
		_mm_storeu_si128((__m128i*)(out+2*SIZE128), blk2);
		_mm_storeu_si128((__m128i*)(out+3*SIZE128), blk3);
		_mm_storeu_si128((__m128i*)(out+4*SIZE128), blk4);
		_mm_storeu_si128((__m128i*)(out+5*SIZE128), blk5);
		_mm_storeu_si128((__m128i*)(out+6*SIZE128), blk6);
		_mm_storeu_si128((__m128i*)(out+7*SIZE128), blk7);
		len -= 8*SIZE128;
		in  += 8*SIZE128;
		out += 8*SIZE128;
	}
	while (len > 0 || (enc && len == 0 && pad == PAD_ALWAYS)) {
		register __m128i blk;
		if (len)
		       	blk = _mm_loadu_si128((const __m128i*)in);
		else
			MMCLEAR(blk);
		if (enc && len < SIZE128) {
			__m128i mask = _mkmask(len);
			blk = _mm_and_si128(blk, mask);
			if (pad) {
				__m128i padv = _mkpad(len);
				__m128i imask = _mm_set_epi64x(0xffffffffffffffffULL, 0xffffffffffffffffULL);
				imask = _mm_xor_si128(imask, mask);
				padv = _mm_and_si128(padv, imask);
				blk = _mm_or_si128(blk, padv);
#ifdef DEBUG
				if (!len) {
					_debug_print(mask, "mask");
					_debug_print(imask, "imask");
					_debug_print(padv, "padv");
				}
#endif
			}
			*olen += 16-(len&15);
		}
		blk = crypt(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	MMCLEARALL;
	if (enc)
		return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;
	if (pad)
		return dec_fix_olen_pad(olen, pad, out);
	else
		return 0;
}

#if defined(__AVX2__) && !defined(NO_AVX2) && defined(__VAES__)
#ifdef __GNUC__
#define ALWAYS_INLINE __attribute__ ((__gnu_inline__, __always_inline__, __artificial__))
#else
#define ALWAYS_INLINE
#endif
/* Why is this intrinsic missing ??? */
static inline __m256i ALWAYS_INLINE
_mm256_broadcast_si128 (const __m128i *__X)
{
	register __m256i ret;
	asm volatile("	vbroadcasti128	(%1), %0"
			: "=x"(ret)
			: "r"(__X), "m"(*__X)
		    );
	return ret;
	//return (__m256i) __builtin_ia32_vbroadcasti128 (*(__v2di)__X);
}

typedef void (crypt_4x2blks_fn)(__m256i *i0, __m256i *i1, __m256i *i2, __m256i *i3,
			        const unsigned char *rkeys, unsigned int rounds);

static inline
void Encrypt_4x2Blocks(__m256i *i0, __m256i *i1, __m256i *i2, __m256i *i3,
		       const unsigned char *ekey, unsigned int rounds)
{
	int r;
	const __m128i *rkeys = (__m128i*)ekey;
	register __m256i rk = _mm256_broadcast_si128(rkeys++);
	*i0 = _mm256_xor_si256(*i0, rk);
	*i1 = _mm256_xor_si256(*i1, rk);
	*i2 = _mm256_xor_si256(*i2, rk);
	*i3 = _mm256_xor_si256(*i3, rk);
	rk = _mm256_broadcast_si128(rkeys++);
	for (r = rounds-1; r > 0; --r) {
		*i0 = _mm256_aesenc_epi128(*i0, rk);
		*i1 = _mm256_aesenc_epi128(*i1, rk);
		*i2 = _mm256_aesenc_epi128(*i2, rk);
		*i3 = _mm256_aesenc_epi128(*i3, rk);
		rk = _mm256_broadcast_si128(rkeys++);
	}
	/* Last round ... */
	*i0 = _mm256_aesenclast_epi128(*i0, rk);
	*i1 = _mm256_aesenclast_epi128(*i1, rk);
	*i2 = _mm256_aesenclast_epi128(*i2, rk);
	*i3 = _mm256_aesenclast_epi128(*i3, rk);
	MM256CLEAR(rk);
}

static inline
void Decrypt_4x2Blocks(__m256i *i0, __m256i *i1, __m256i *i2, __m256i *i3,
		       const unsigned char *dkey, unsigned int rounds)
{
	int r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m256i rk = _mm256_broadcast_si128(rkeys++);
	*i0 = _mm256_xor_si256(*i0, rk);
	*i1 = _mm256_xor_si256(*i1, rk);
	*i2 = _mm256_xor_si256(*i2, rk);
	*i3 = _mm256_xor_si256(*i3, rk);
	rk = _mm256_broadcast_si128(rkeys++);
	for (r = rounds-1; r > 0; --r) {
		*i0 = _mm256_aesdec_epi128(*i0, rk);
		*i1 = _mm256_aesdec_epi128(*i1, rk);
		*i2 = _mm256_aesdec_epi128(*i2, rk);
		*i3 = _mm256_aesdec_epi128(*i3, rk);
		rk = _mm256_broadcast_si128(rkeys++);
	}
	/* Last round ... */
	*i0 = _mm256_aesdeclast_epi128(*i0, rk);
	*i1 = _mm256_aesdeclast_epi128(*i1, rk);
	*i2 = _mm256_aesdeclast_epi128(*i2, rk);
	*i3 = _mm256_aesdeclast_epi128(*i3, rk);
	MM256CLEAR(rk);
}

static inline
int  AESNI_ECB_Crypt_Tmpl2(crypt_4x2blks_fn *crypt4x2, crypt_blk_fn *crypt, int enc,
			  const unsigned char* key, unsigned int rounds,
			  unsigned int pad,
			  const unsigned char* in, unsigned char* out,
			  ssize_t len, ssize_t *olen)
{
	*olen = len;
	__m256i blk0, blk1, blk2, blk3;
	while (len >= 4*SIZE256) {
		blk0 = _mm256_loadu_si256((const __m256i*)in);
		blk1 = _mm256_loadu_si256((const __m256i*)(in+SIZE256));
		blk2 = _mm256_loadu_si256((const __m256i*)(in+2*SIZE256));
		blk3 = _mm256_loadu_si256((const __m256i*)(in+3*SIZE256));
		crypt4x2(&blk0, &blk1, &blk2, &blk3, key, rounds);
		_mm256_storeu_si256((__m256i*)out, blk0);
		_mm256_storeu_si256((__m256i*)(out+SIZE256), blk1);
		_mm256_storeu_si256((__m256i*)(out+2*SIZE256), blk2);
		_mm256_storeu_si256((__m256i*)(out+3*SIZE256), blk3);
		len -= 4*SIZE256;
		in  += 4*SIZE256;
		out += 4*SIZE256;
	}
	MM256CLEAR(blk0); MM256CLEAR(blk1); MM256CLEAR(blk2); MM256CLEAR(blk3);
	__m128i blk;
	while (len > 0 || (enc && len == 0 && pad == PAD_ALWAYS)) {
		blk = _mm_loadu_si128((const __m128i*)in);
		if (enc && len < SIZE128) {
			__m128i mask = _mkmask(len);
			blk = _mm_and_si128(blk, mask);
			if (pad) {
				__m128i padv = _mkpad(len);
				__m128i imask = _mm_set_epi64x(0xffffffffffffffffULL, 0xffffffffffffffffULL);
				imask = _mm_xor_si128(imask, mask);
				padv = _mm_and_si128(padv, imask);
				blk = _mm_or_si128(blk, padv);
#ifdef DEBUG
				if (!len) {
					_debug_print(mask, "mask");
					_debug_print(imask, "imask");
					_debug_print(padv, "padv");
				}
#endif
			}
			*olen += 16-(len&15);
		}
		blk = crypt(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	MMCLEAR(blk);
	if (enc)
		return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;
	if (pad)
		return dec_fix_olen_pad(olen, pad, out);
	else
		return 0;
}

static
int  AESNI_ECB_Encrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen)
{
	if (have_vaes)
		return AESNI_ECB_Crypt_Tmpl2(Encrypt_4x2Blocks, Encrypt_Block, 1,
			     key, rounds, pad, in, out, len, olen);
	else
		return AESNI_ECB_Crypt_Tmpl(Encrypt_8Blocks, Encrypt_Block, 1,
			     key, rounds, pad, in, out, len, olen);
}

static
int  AESNI_ECB_Decrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen)
{
	if (have_vaes)
		return AESNI_ECB_Crypt_Tmpl2(Decrypt_4x2Blocks, Decrypt_Block, 0,
			     key, rounds, pad, in, out, len, olen);
	else
		return AESNI_ECB_Crypt_Tmpl(Decrypt_8Blocks, Decrypt_Block, 0,
			     key, rounds, pad, in, out, len, olen);
}
#else
static
int  AESNI_ECB_Encrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen)
{
	return AESNI_ECB_Crypt_Tmpl(Encrypt_8Blocks, Encrypt_Block, 1,
			     key, rounds, pad, in, out, len, olen);
}

static
int  AESNI_ECB_Decrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen)
{
	return AESNI_ECB_Crypt_Tmpl(Decrypt_8Blocks, Decrypt_Block, 0,
			     key, rounds, pad, in, out, len, olen);
}
#endif

#if 0
static
void AESNI_ECB_Decrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv,
			const unsigned char* in, unsigned char* out,
			ssize_t len) 
{
	while (len >= 4*SIZE128) {
		__m128i blk0 = _mm_loadu_si128((const __m128i*)in);
		__m128i blk1 = _mm_loadu_si128((const __m128i*)(in+SIZE128));
		__m128i blk2 = _mm_loadu_si128((const __m128i*)(in+2*SIZE128));
		__m128i blk3 = _mm_loadu_si128((const __m128i*)(in+3*SIZE128));
		Decrypt_4Blocks(&blk0, &blk1, &blk2, &blk3, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk0);
		_mm_storeu_si128((__m128i*)(out+SIZE128), blk1);
		_mm_storeu_si128((__m128i*)(out+2*SIZE128), blk2);
		_mm_storeu_si128((__m128i*)(out+3*SIZE128), blk3);
		len -= 4*SIZE128;
		in  += 4*SIZE128;
		out += 4*SIZE128;
	}
	while (len > 0) {
		register __m128i blk = _mm_loadu_si128((const __m128i*)in);
		blk = Decrypt_Block(blk, key, rounds);
		_mm_storeu_si128((__m128i*)out, blk);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
}
#endif

static inline
int AESNI_CBC_Encrypt_Tmpl(crypt_blk_fn *encrypt,
			const unsigned char* key, unsigned int rounds,
			unsigned char* iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen) 
{
	register __m128i ivb = _mm_loadu_si128((const __m128i*)iv);
	register __m128i dat;
	*olen = len;
	while (len >= SIZE128) {
		//dat = _mm_loadu_si128((const __m128i*)in);
		ivb = _mm_xor_si128(ivb, *(const __m128i*)in);
		ivb = encrypt(ivb, key, rounds);
		_mm_storeu_si128((__m128i*)out, ivb);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	//_mm_storeu_si128((__m128i*)iv, ivb);
	if (len || pad == PAD_ALWAYS) {
		//dat = _mm_loadu_si128((const __m128i*)in);
		__m128i mask = _mkmask(len);
		dat = _mm_and_si128(*(const __m128i*)in, mask);
		if (pad) {
			__m128i padv = _mkpad(len);
			__m128i imask = _mm_set_epi64x(0xffffffffffffffffULL, 0xffffffffffffffffULL);
			imask = _mm_xor_si128(imask, mask);
			padv = _mm_and_si128(padv, imask);
			dat = _mm_or_si128(dat, padv);
		}
		ivb = _mm_xor_si128(ivb, dat);
		ivb = encrypt(ivb, key, rounds);
		_mm_storeu_si128((__m128i*)out, ivb);
		*olen += 16-(*olen&15);
	}
	_mm_storeu_si128((__m128i*)iv, ivb);
	/* FIXME: Clear the right registers */
	MMCLEAR(dat); MMCLEAR(ivb);
	return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;
}

static
int AESNI_CBC_Encrypt(	const unsigned char* key, unsigned int rounds,
			unsigned char* iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen) 
{
	return AESNI_CBC_Encrypt_Tmpl(Encrypt_Block, key, rounds, iv, pad, in, out, len, olen);
}

static inline
int  AESNI_CBC_Decrypt_Tmpl(crypt_4blks_fn *decrypt4, crypt_blk_fn *decrypt,
			const unsigned char* key, unsigned int rounds,
			unsigned char* iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen)
{
	register __m128i ivb = _mm_loadu_si128((const __m128i*)iv);
	*olen = len;
	__m128i dat0, dat1, dat2, dat3, b0, b1, b2, b3;
	/* TODO: We could do 4 blocks in parallel for CBC decrypt (NOT: encrypt) */
	while (len >= 4*SIZE128) {
		dat0 = _mm_loadu_si128((const __m128i*)in);
		dat1 = _mm_loadu_si128((const __m128i*)in+1);
		dat2 = _mm_loadu_si128((const __m128i*)in+2);
		dat3 = _mm_loadu_si128((const __m128i*)in+3);
		b0 = dat0, b1= dat1, b2 = dat2, b3 = dat3;
		decrypt4(&dat0, &dat1, &dat2, &dat3, key, rounds);
		_mm_storeu_si128((__m128i*)out  , _mm_xor_si128(dat0, ivb));
		_mm_storeu_si128((__m128i*)out+1, _mm_xor_si128(dat1, b0));
		_mm_storeu_si128((__m128i*)out+2, _mm_xor_si128(dat2, b1));
		_mm_storeu_si128((__m128i*)out+3, _mm_xor_si128(dat3, b2));
		ivb = b3;
		len -= 4*SIZE128;
		in  += 4*SIZE128;
		out += 4*SIZE128;
	}
	//_mm_storeu_si128((__m128i*)iv, ivb);
	while (len > 0) {
		dat0 = _mm_loadu_si128((const __m128i*)in);
		b0 = dat0;
		dat0 = decrypt(dat0, key, rounds);
		_mm_storeu_si128((__m128i*)out, _mm_xor_si128(dat0, ivb));
		ivb = b0;
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	_mm_storeu_si128((__m128i*)iv, ivb);
	/* FIXME: Clear the right registers */
	MMCLEAR(b3); MMCLEAR(b2); MMCLEAR(b1); MMCLEAR(b0);
	MMCLEAR(dat3); MMCLEAR(dat2); MMCLEAR(dat1); MMCLEAR(dat0);
	MMCLEAR(ivb);
	if (pad)
		return dec_fix_olen_pad(olen, pad, out);
	else
		return 0;
}

static
int  AESNI_CBC_Decrypt( const unsigned char* key, unsigned int rounds,
			unsigned char* iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen)
{
	return AESNI_CBC_Decrypt_Tmpl(Decrypt_4Blocks, Decrypt_Block,
			key, rounds, iv, pad, in, out, len, olen);
}


#if 0
/* CTR is big-endian */
static
void AESNI_CTR_Prep_2(const unsigned char* iv, const unsigned char* nonce,
		      unsigned char* ctr, unsigned long long val)
{
	const __m128i VAL = _mm_set_epi64x(val, 0);
	const __m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	
	__m128i tmp = _mm_setzero_si128();
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

#endif

/* CTR is big-endian */
static
void AESNI_CTR_Prep(const unsigned char* iv, unsigned char* ctr, unsigned long long val)
{
	__m128i tmp = _mm_loadu_si128((__m128i*)iv);
	//MSK = _mm_set_epi32(0xffffffff, 0, 0xffffffff, 0xffffffff);
	const __m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	const __m128i VAL = _mm_set_epi64x(val, 0);
	tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
	//tmp = _mm_and_si128(tmp, MSK);
	tmp = _mm_add_epi64(tmp, VAL);
	tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
	_mm_storeu_si128((__m128i*)ctr, tmp);
#ifdef DEBUG_CBLK_SETUP
	static int c = 0;
	if (!c++) {
		_debug_print(tmp);
		const __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
		tmp = _mm_add_epi64(tmp, ONE);
		tmp = _mm_shuffle_epi8(tmp, BSWAP_EPI64);
		_debug_print(tmp);
	}
#endif
	//MMCLEAR(tmp);
}


static inline
int AESNI_CTR_Crypt_Tmpl(crypt_8blks_fn *crypt8, crypt_blk_fn *crypt,
			 const unsigned char* key, unsigned int rounds,
		 	 unsigned char* ctr,
		 	 const unsigned char* in, unsigned char* out,
			 ssize_t len)
{
	__m128i cblk = _mm_loadu_si128((__m128i*)ctr);
	const __m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	const __m128i ONE   = _mm_set_epi32(0, 1, 0, 0);
	cblk = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
	const __m128i TWO   = _mm_set_epi32(0, 2, 0, 0);
	const __m128i THREE = _mm_set_epi32(0, 3, 0, 0);
	const __m128i FOUR  = _mm_set_epi32(0, 4, 0, 0);
	const __m128i_u* inptr = (const __m128i_u*)in;
	__m128i_u* outptr = (__m128i_u*)out;
	while (len >= 8*SIZE128) {
#ifdef AESNI_PREFETCH
		__builtin_prefetch(outptr, 1, 3);
		__builtin_prefetch(outptr+4, 1, 3);
		__builtin_prefetch(inptr, 0, 1);
		__builtin_prefetch(inptr+4, 0, 1);
#endif
		/* Prepare CTR (IV) values */
		__m128i tmp0 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		__m128i tmp1 = _mm_add_epi64(cblk, ONE);
		__m128i tmp2 = _mm_add_epi64(cblk, TWO);
		__m128i tmp3 = _mm_add_epi64(cblk, THREE);
		cblk = _mm_add_epi64(cblk, FOUR);
		tmp1 = _mm_shuffle_epi8(tmp1, BSWAP_EPI64);
		tmp2 = _mm_shuffle_epi8(tmp2, BSWAP_EPI64);
		tmp3 = _mm_shuffle_epi8(tmp3, BSWAP_EPI64);
		__m128i tmp4 = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		__m128i tmp5 = _mm_add_epi64(cblk, ONE);
		__m128i tmp6 = _mm_add_epi64(cblk, TWO);
		__m128i tmp7 = _mm_add_epi64(cblk, THREE);
		tmp5 = _mm_shuffle_epi8(tmp5, BSWAP_EPI64);
		tmp6 = _mm_shuffle_epi8(tmp6, BSWAP_EPI64);
		tmp7 = _mm_shuffle_epi8(tmp7, BSWAP_EPI64);
		/* Encrypt 8 IVs */
		crypt8(&tmp0, &tmp1, &tmp2, &tmp3, &tmp4, &tmp5, &tmp6, &tmp7, key, rounds);
		len -= 8*SIZE128;
		cblk = _mm_add_epi64(cblk, FOUR);
		*outptr++ = _mm_xor_si128(tmp0, *inptr++);
		*outptr++ = _mm_xor_si128(tmp1, *inptr++);
		*outptr++ = _mm_xor_si128(tmp2, *inptr++);
		*outptr++ = _mm_xor_si128(tmp3, *inptr++);
		*outptr++ = _mm_xor_si128(tmp4, *inptr++);
		*outptr++ = _mm_xor_si128(tmp5, *inptr++);
		*outptr++ = _mm_xor_si128(tmp6, *inptr++);
		*outptr++ = _mm_xor_si128(tmp7, *inptr++);
	}
	while (len > 0) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		tmp = crypt(tmp, key, rounds);
		if (len < SIZE128) {
			uchar *obuf = crypto->blkbuf3;
			__m128i mask = _mkmask(len);
			mask = _mm_and_si128(mask, *inptr++);
			*(__m128i*)obuf = _mm_xor_si128(tmp, mask);
			memcpy(outptr, obuf, len);
		} else {
			*outptr++ = _mm_xor_si128(tmp, *inptr++);
		}
		/* FIXME: We had only increased CTR for complete blocks before. Why? */
		/*if (len >= SIZE128)*/
			cblk = _mm_add_epi64(cblk, ONE);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	/* Change back to initial byte order */
	register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
	_mm_storeu_si128((__m128i*)ctr, tmp);
	MMCLEARALL;
	return 0;
}

#if !defined(__AVX2__) || !defined(__VAES__) || defined(NO_AVX2)
static
int AESNI_CTR_Crypt(const unsigned char* key, unsigned int rounds,
		     unsigned char* ctr, unsigned int pad,
		     const unsigned char* in, unsigned char* out,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	return AESNI_CTR_Crypt_Tmpl(Encrypt_8Blocks, Encrypt_Block,
				    key, rounds, ctr, in, out, len);
}

#else

static inline
int AESNI_CTR_Crypt_Tmpl2(crypt_4x2blks_fn *crypt4, crypt_blk_fn *crypt,
			  const unsigned char* key, unsigned int rounds,
			  unsigned char* ctr,
			  const unsigned char* in, unsigned char* out,
			  ssize_t len)
{
	__m128i cblk128 = _mm_loadu_si128((__m128i*)ctr);
	__m256i cblk = _mm256_broadcastsi128_si256(cblk128);
	//__builtin_prefetch(key, 0, 3);
	const __m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	const __m256i BSWAP_BOTH = _mm256_broadcastsi128_si256(BSWAP_EPI64);
	const __m256i INIT = _mm256_set_epi32(0, 1, 0, 0, 0, 0, 0, 0);
	cblk = _mm256_shuffle_epi8(cblk, BSWAP_BOTH);
	cblk = _mm256_add_epi64(cblk, INIT);
	__m256i tmp0, tmp1, tmp2, tmp3;
	const __m256i_u* inptr = (const __m256i_u*)in;
	__m256i_u* outptr = (__m256i_u*)out;
	//__builtin_prefetch(in, 0, 3);
	while (len >= 4*SIZE256) {
		const __m256i TWO = _mm256_set_epi32(0, 2, 0, 0, 0, 2, 0, 0);
#ifdef AESNI_PREFETCH
		__builtin_prefetch(outptr, 1, 3);
		__builtin_prefetch(outptr+2, 1, 3);
		__builtin_prefetch(inptr, 0, 1);
		__builtin_prefetch(inptr+2, 0, 1);
#endif
		/* Prepare CTR (IV) values */
		tmp0 = _mm256_shuffle_epi8(cblk, BSWAP_BOTH);
		cblk = _mm256_add_epi64(cblk, TWO);
		tmp1 = _mm256_shuffle_epi8(cblk, BSWAP_BOTH);
		cblk = _mm256_add_epi64(cblk, TWO);
		tmp2 = _mm256_shuffle_epi8(cblk, BSWAP_BOTH);
		cblk = _mm256_add_epi64(cblk, TWO);
		tmp3 = _mm256_shuffle_epi8(cblk, BSWAP_BOTH);
		/* Encrypt 4 Double IVs */
		crypt4(&tmp0, &tmp1, &tmp2, &tmp3, key, rounds);
		len -= 4*SIZE256;
		cblk = _mm256_add_epi64(cblk, TWO);
		*outptr++ = _mm256_xor_si256(tmp0, *inptr++);
		*outptr++ = _mm256_xor_si256(tmp1, *inptr++);
		*outptr++ = _mm256_xor_si256(tmp2, *inptr++);
		*outptr++ = _mm256_xor_si256(tmp3, *inptr++);
	}
	cblk128 = _mm256_extracti128_si256(cblk, 0);
	MM256CLEAR(tmp0); MM256CLEAR(tmp1); MM256CLEAR(tmp2); MM256CLEAR(tmp3);
	MM256CLEAR(cblk);
	register __m128i tmp;
	const __m128i_u* inptr2 = (const __m128i_u*)inptr;
	__m128i_u* outptr2 = (__m128i_u*)outptr;
	while (len > 0) {
		tmp = _mm_shuffle_epi8(cblk128, BSWAP_EPI64);
		const __m128i ONE  = _mm_set_epi32(0, 1, 0, 0);
		tmp = crypt(tmp, key, rounds);
		if (len < SIZE128) {
			uchar *obuf = crypto->blkbuf3;
			__m128i mask = _mkmask(len);
			mask = _mm_and_si128(mask, *inptr2++);
			*(__m128i*)obuf = _mm_xor_si128(tmp, mask);
			memcpy(outptr2, obuf, len);
		} else {
			*outptr2++ = _mm_xor_si128(tmp, *inptr2++);
		}
		/* FIXME: We had only increased CTR for complete blocks before. Why? */
		/*if (len >= SIZE128)*/
		cblk128 = _mm_add_epi64(cblk128, ONE);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	/* Change back to initial byte order */
	cblk128 = _mm_shuffle_epi8(cblk128, BSWAP_EPI64);
	_mm_storeu_si128((__m128i*)ctr, cblk128);
	MMCLEAR(tmp); MMCLEAR(cblk128);
	return 0;
}

static
int AESNI_CTR_Crypt(const unsigned char* key, unsigned int rounds,
		     unsigned char* ctr, unsigned int pad,
		     const unsigned char* in, unsigned char* out,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	if (have_vaes)
		return AESNI_CTR_Crypt_Tmpl2(Encrypt_4x2Blocks, Encrypt_Block,
				     key, rounds, ctr, in, out, len);
	else
		return AESNI_CTR_Crypt_Tmpl(Encrypt_8Blocks, Encrypt_Block,
				     key, rounds, ctr, in, out, len);
}
#endif

#if 0
static
void AESNI_CTR_Crypt4(const unsigned char* in, unsigned char* out,
		     unsigned char* ctr,
		     ssize_t len, const unsigned char* key, unsigned int rounds)
{
	const __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
	const __m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	__m128i cblk = _mm_loadu_si128((__m128i*)ctr);
	while (len >= 4*SIZE128) {
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
		len -= 4*SIZE128;
		in  += 4*SIZE128;
		out += 4*SIZE128;
	}
	while (len > 0) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		tmp = Encrypt_Block(tmp, key, rounds);
		if (len < SIZE128) {
			__m128i mask = _mkmask(len);
			mask = _mm_and_si128(mask, _mm_loadu_si128((__m128i*)in));
			tmp = _mm_xor_si128(tmp, mask);
		} else {
			cblk = _mm_add_epi64(cblk, ONE);
			tmp = _mm_xor_si128(tmp, _mm_loadu_si128((__m128i*)in));
		}
		_mm_storeu_si128((__m128i*)out, tmp);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	_mm_storeu_si128((__m128i*)ctr, cblk);
}

static
void AESNI_CTR_Crypt_old(const unsigned char* in, unsigned char* out,
		         unsigned char* ctr,
		         ssize_t len, const unsigned char* key, unsigned int rounds)
{
	const __m128i ONE = _mm_set_epi32(0, 1, 0, 0);
	const __m128i BSWAP_EPI64 = _mm_setr_epi8(7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8);
	__m128i cblk = _mm_loadu_si128((__m128i*)ctr);
	/* TODO: We could process 4 blocks at once here as well */
	while (len >= SIZE128) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		cblk = _mm_add_epi64(cblk, ONE);
		tmp = Encrypt_Block(tmp, key, rounds);
		tmp = _mm_xor_si128(tmp, _mm_loadu_si128((__m128i*)in));
		_mm_storeu_si128((__m128i*)out, tmp);
		len -= SIZE128;
		in  += SIZE128;
		out += SIZE128;
	}
	if (len) {
		register __m128i tmp = _mm_shuffle_epi8(cblk, BSWAP_EPI64);
		//cblk = _mm_add_epi64(cblk, ONE);
		tmp = Encrypt_Block(tmp, key, rounds);
		__m128i mask = _mkmask(len);
		mask = _mm_and_si128(mask, _mm_loadu_si128((__m128i*)in));
		tmp = _mm_xor_si128(tmp, mask);
		_mm_storeu_si128((__m128i*)out, tmp);
	}
	_mm_storeu_si128((__m128i*)ctr, cblk);
}
#endif

#include "sha256.h"
#include <assert.h>
#include <string.h>

#define AESNI_Key_ExpansionX2(MODE, BITS)				\
static void AESNI_##BITS##_##MODE##Key_ExpansionX2_r(const uchar *usrkey, uchar* rkeys, unsigned int rounds)	\
{									\
	assert(0 == rounds%2);						\
	AESNI_##BITS##_##MODE##Key_Expansion_r(usrkey, rkeys, rounds/2);\
	/* Second half: Calc sha256 from usrkey and expand */		\
	hash_t hv;							\
	sha256_init(&hv);						\
	sha256_calc(usrkey, BITS/8, BITS/8, &hv);			\
	sha256_beout(crypto->userkey2, &hv);				\
	sha256_init(&hv);						\
	AESNI_##BITS##_##MODE##Key_Expansion_r(crypto->userkey2, rkeys+16+8*rounds, rounds/2);	\
	/*memset(crypto->userkey2, 0, 32);*/				\
	sha256_init(&hv);						\
	asm("":::"memory");						\
}

AESNI_Key_ExpansionX2(E, 128);
AESNI_Key_ExpansionX2(D, 128);
AESNI_Key_ExpansionX2(E, 192);
AESNI_Key_ExpansionX2(D, 192);
AESNI_Key_ExpansionX2(E, 256);
AESNI_Key_ExpansionX2(D, 256);

static inline
__m128i Encrypt_BlockX2(const __m128i in, const unsigned char *ekey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)ekey;
	//register __m128i rk = _mm_loadu_si128(rkeys++);
	register __m128i tmp = _mm_xor_si128(in, *rkeys++);
	//rk = _mm_loadu_si128(rkeys++);
	for (r = 1; r < rounds/2; ++r) {
		tmp = _mm_aesenc_si128(tmp, *rkeys++);
		//rk = _mm_loadu_si128(rkeys++);
	}
	tmp = _mm_aesenclast_si128(tmp, *rkeys++);
	//rk = _mm_loadu_si128(rkeys++);
	tmp = _mm_xor_si128(tmp, *rkeys++);
	//rk = _mm_loadu_si128(rkeys++);
	for (r = 1; r < rounds/2; ++r) {
		tmp = _mm_aesenc_si128(tmp, *rkeys++);
		//rk = _mm_loadu_si128(rkeys++);
	}
	tmp = _mm_aesenclast_si128(tmp, *rkeys);
	//MMCLEAR(rk);
	return tmp;
}

static inline
__m128i Decrypt_BlockX2(const __m128i in, const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey + rounds/2+1;
	//register __m128i rk = _mm_loadu_si128(rkeys++);
	register __m128i tmp = _mm_xor_si128(in, *rkeys++);
	//rk = _mm_loadu_si128(rkeys++);
	for (r = 1; r < rounds/2; ++r) {
		tmp = _mm_aesdec_si128(tmp, *rkeys++);
		//rk = _mm_loadu_si128(rkeys++);
	}
	tmp = _mm_aesdeclast_si128(tmp, *rkeys);
	rkeys = (__m128i*)dkey;
	//rk = _mm_loadu_si128(rkeys++);
	tmp = _mm_xor_si128(tmp, *rkeys++);
	//rk = _mm_loadu_si128(rkeys++);
	for (r = 1; r < rounds/2; ++r) {
		tmp = _mm_aesdec_si128(tmp, *rkeys++);
		//rk = _mm_loadu_si128(rkeys++);
	}
	tmp = _mm_aesdeclast_si128(tmp, *rkeys);
	//MMCLEAR(rk);
	return tmp;
}

/* TODO: VAES optimized versions */
static inline
void Encrypt_8BlocksX2(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		       __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
		       const unsigned char *ekey, unsigned int rounds)
{
	uint r;
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
	for (r = 1; r < rounds/2; ++r) {
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
	rk = _mm_loadu_si128(rkeys+r++);
	*i0 = _mm_aesenclast_si128(*i0, rk);
	*i1 = _mm_aesenclast_si128(*i1, rk);
	*i2 = _mm_aesenclast_si128(*i2, rk);
	*i3 = _mm_aesenclast_si128(*i3, rk);
	*i4 = _mm_aesenclast_si128(*i4, rk);
	*i5 = _mm_aesenclast_si128(*i5, rk);
	*i6 = _mm_aesenclast_si128(*i6, rk);
	*i7 = _mm_aesenclast_si128(*i7, rk);
	/* Second encryption ... */
	rk = _mm_loadu_si128(rkeys+r++);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (; r < rounds+1; ++r) {
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
	rk = _mm_loadu_si128(rkeys+r++);
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
void Decrypt_8BlocksX2(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		       __m128i *i4, __m128i *i5, __m128i *i6, __m128i *i7,
		       const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys+rounds/2+1);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (r = rounds/2+2; r < rounds+1; ++r) {
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
	rk = _mm_loadu_si128(rkeys+r);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	*i4 = _mm_aesdeclast_si128(*i4, rk);
	*i5 = _mm_aesdeclast_si128(*i5, rk);
	*i6 = _mm_aesdeclast_si128(*i6, rk);
	*i7 = _mm_aesdeclast_si128(*i7, rk);
	/* First key */
	rk = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	*i4 = _mm_xor_si128(*i4, rk);
	*i5 = _mm_xor_si128(*i5, rk);
	*i6 = _mm_xor_si128(*i6, rk);
	*i7 = _mm_xor_si128(*i7, rk);
	for (r = 1; r < rounds/2; ++r) {
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
	rk = _mm_loadu_si128(rkeys+r);
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

/* TODO: 256bit VAES version */

static inline
void Decrypt_4BlocksX2(__m128i *i0, __m128i *i1, __m128i *i2, __m128i *i3,
		       const unsigned char *dkey, unsigned int rounds)
{
	uint r;
	const __m128i *rkeys = (__m128i*)dkey;
	register __m128i rk asm("xmm0") = _mm_loadu_si128(rkeys+rounds/2+1);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	for (r = rounds/2+2; r < rounds+1; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+r);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	/* First key */
	rk = _mm_loadu_si128(rkeys);
	*i0 = _mm_xor_si128(*i0, rk);
	*i1 = _mm_xor_si128(*i1, rk);
	*i2 = _mm_xor_si128(*i2, rk);
	*i3 = _mm_xor_si128(*i3, rk);
	for (r = 1; r < rounds/2; ++r) {
		rk = _mm_loadu_si128(rkeys+r);
		*i0 = _mm_aesdec_si128(*i0, rk);
		*i1 = _mm_aesdec_si128(*i1, rk);
		*i2 = _mm_aesdec_si128(*i2, rk);
		*i3 = _mm_aesdec_si128(*i3, rk);
	}
	/* Last round ... */
	rk = _mm_loadu_si128(rkeys+r);
	*i0 = _mm_aesdeclast_si128(*i0, rk);
	*i1 = _mm_aesdeclast_si128(*i1, rk);
	*i2 = _mm_aesdeclast_si128(*i2, rk);
	*i3 = _mm_aesdeclast_si128(*i3, rk);
	MMCLEAR(rk);
	//asm volatile("pxor %%xmm0, %%xmm0\n" :::"xmm0");
}

static
int  AESNI_ECB_EncryptX2(const uchar* rkeys, unsigned int rounds,
			 uchar *iv, uint pad, const uchar *in, uchar *out, 
			 ssize_t len, ssize_t *olen)
{
	return AESNI_ECB_Crypt_Tmpl(Encrypt_8BlocksX2, Encrypt_BlockX2, 1,
				    rkeys, rounds, pad, in, out, len, olen);
}

static
int  AESNI_ECB_DecryptX2(const uchar* rkeys, unsigned int rounds,
			 uchar *iv, uint pad, const uchar *in, uchar *out, 
			 ssize_t len, ssize_t *olen)
{
	return AESNI_ECB_Crypt_Tmpl(Decrypt_8BlocksX2, Decrypt_BlockX2, 0,
				    rkeys, rounds, pad, in, out, len, olen);
}

static
int  AESNI_CBC_EncryptX2(const uchar* rkeys, unsigned int rounds,
			 uchar *iv, uint pad, const uchar *in, uchar *out, 
			 ssize_t len, ssize_t *olen)
{
	return AESNI_CBC_Encrypt_Tmpl(Encrypt_BlockX2, rkeys, rounds, 
				iv, pad, in, out, len, olen);
}

static
int  AESNI_CBC_DecryptX2(const uchar* rkeys, unsigned int rounds,
			 uchar *iv, uint pad, const uchar *in, uchar *out, 
			 ssize_t len, ssize_t *olen)
{
	return AESNI_CBC_Decrypt_Tmpl(Decrypt_4BlocksX2, Decrypt_BlockX2, rkeys, rounds, 
				iv, pad, in, out, len, olen);
}
/* TODO: Handtuned asm x2 version */
static
int  AESNI_CTR_CryptX2(const uchar* rkeys, unsigned int rounds,
			uchar *iv, uint pad, const uchar *in, uchar *out, 
			ssize_t len, ssize_t *olen)
{
	*olen = len;
	return AESNI_CTR_Crypt_Tmpl(Encrypt_8BlocksX2, Encrypt_BlockX2,
				    rkeys, rounds, iv, in, out, len);
}

#if defined(__AVX2__) && !defined(NO_AVX2)
#define AESNI_METHODS VAESNI_Methods
#else
#define AESNI_METHODS SAESNI_Methods
#endif
static
stream_dsc_t aesni_stream_ctr = {  1, 1, STP_CTR, 1, AESNI_CTR_Prep };

ciph_desc_t AESNI_METHODS[] = {{"AES128-ECB"  , 128, 10, 16, 11*16, &aes_stream_ecb,
					AESNI_128_EKey_Expansion_r, AESNI_128_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES128-CBC"  , 128, 10, 16, 11*16, &aes_stream_cbc,
					AESNI_128_EKey_Expansion_r, AESNI_128_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES128-CTR"  , 128, 10, 16, 11*16, &aesni_stream_ctr,
					AESNI_128_EKey_Expansion_r, AESNI_128_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192-ECB"  , 192, 12, 16, 13*16, &aes_stream_ecb,
					AESNI_192_EKey_Expansion_r, AESNI_192_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192-CBC"  , 192, 12, 16, 13*16, &aes_stream_cbc,
					AESNI_192_EKey_Expansion_r, AESNI_192_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192-CTR"  , 192, 12, 16, 13*16, &aesni_stream_ctr,
					AESNI_192_EKey_Expansion_r, AESNI_192_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256-ECB"  , 256, 14, 16, 15*16, &aes_stream_ecb,
					AESNI_256_EKey_Expansion_r, AESNI_256_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256-CBC"  , 256, 14, 16, 15*16, &aes_stream_cbc,
					AESNI_256_EKey_Expansion_r, AESNI_256_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256-CTR"  , 256, 14, 16, 15*16, &aesni_stream_ctr,
					AESNI_256_EKey_Expansion_r, AESNI_256_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
				/* plus methods */
			       {"AES128+-ECB" , 128, 12, 16, 13*16, &aes_stream_ecb,
					AESNI_128_EKey_Expansion_r, AESNI_128_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES128+-CBC" , 128, 12, 16, 13*16, &aes_stream_cbc,
					AESNI_128_EKey_Expansion_r, AESNI_128_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES128+-CTR" , 128, 12, 16, 13*16, &aesni_stream_ctr,
					AESNI_128_EKey_Expansion_r, AESNI_128_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192+-ECB" , 192, 15, 16, 16*16, &aes_stream_ecb,
					AESNI_192_EKey_Expansion_r, AESNI_192_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192+-CBC" , 192, 15, 16, 16*16, &aes_stream_cbc,
					AESNI_192_EKey_Expansion_r, AESNI_192_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES192+-CTR" , 192, 15, 16, 16*16, &aesni_stream_ctr,
					AESNI_192_EKey_Expansion_r, AESNI_192_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256+-ECB" , 256, 18, 16, 19*16, &aes_stream_ecb,
					AESNI_256_EKey_Expansion_r, AESNI_256_DKey_Expansion_r,
					AESNI_ECB_Encrypt, AESNI_ECB_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256+-CBC" , 256, 18, 16, 19*16, &aes_stream_cbc,
					AESNI_256_EKey_Expansion_r, AESNI_256_DKey_Expansion_r,
					AESNI_CBC_Encrypt, AESNI_CBC_Decrypt, AES_Gen_Release, probe_aes_ni},
			       {"AES256+-CTR" , 256, 18, 16, 19*16, &aesni_stream_ctr,
					AESNI_256_EKey_Expansion_r, AESNI_256_EKey_Expansion_r,
					AESNI_CTR_Crypt, AESNI_CTR_Crypt, AES_Gen_Release, probe_aes_ni},
				/* x2 methods */
			       {"AES128x2-ECB", 128, 20, 16, 22*16, &aes_stream_ecb,
					AESNI_128_EKey_ExpansionX2_r, AESNI_128_DKey_ExpansionX2_r,
					AESNI_ECB_EncryptX2, AESNI_ECB_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES128x2-CBC", 128, 20, 16, 22*16, &aes_stream_cbc,
					AESNI_128_EKey_ExpansionX2_r, AESNI_128_DKey_ExpansionX2_r,
					AESNI_CBC_EncryptX2, AESNI_CBC_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES128x2-CTR", 128, 20, 16, 22*16, &aesni_stream_ctr,
					AESNI_128_EKey_ExpansionX2_r, AESNI_128_EKey_ExpansionX2_r,
					AESNI_CTR_CryptX2, AESNI_CTR_CryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES192x2-ECB", 192, 24, 16, 26*16, &aes_stream_ecb,
					AESNI_192_EKey_ExpansionX2_r, AESNI_192_DKey_ExpansionX2_r,
					AESNI_ECB_EncryptX2, AESNI_ECB_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES192x2-CBC", 192, 24, 16, 26*16, &aes_stream_cbc,
					AESNI_192_EKey_ExpansionX2_r, AESNI_192_DKey_ExpansionX2_r,
					AESNI_CBC_EncryptX2, AESNI_CBC_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES192x2-CTR", 192, 24, 16, 26*16, &aesni_stream_ctr,
					AESNI_192_EKey_ExpansionX2_r, AESNI_192_EKey_ExpansionX2_r,
					AESNI_CTR_CryptX2, AESNI_CTR_CryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES256x2-ECB", 256, 28, 16, 30*16, &aes_stream_ecb,
					AESNI_256_EKey_ExpansionX2_r, AESNI_256_DKey_ExpansionX2_r,
					AESNI_ECB_EncryptX2, AESNI_ECB_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES256x2-CBC", 256, 28, 16, 30*16, &aes_stream_cbc,
					AESNI_256_EKey_ExpansionX2_r, AESNI_256_DKey_ExpansionX2_r,
					AESNI_CBC_EncryptX2, AESNI_CBC_DecryptX2, AES_Gen_Release, probe_aes_ni},
			       {"AES256x2-CTR", 256, 28, 16, 30*16, &aesni_stream_ctr,
					AESNI_256_EKey_ExpansionX2_r, AESNI_256_EKey_ExpansionX2_r,
					AESNI_CTR_CryptX2, AESNI_CTR_CryptX2, AES_Gen_Release, probe_aes_ni},
			       {NULL, /* ... */}
};


