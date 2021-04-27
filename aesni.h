/** \file aesni.h
 *
 * declarations for AESNI functions
 */

#ifndef _AESNI_H
#define _AESNI_H

#include <sys/types.h>

#define AES_128_ROUNDS 10
#define AES_192_ROUNDS 12
#define AES_256_ROUNDS 14

#if 0
/* aesni.c */
static
void AESNI_EKey_DKey(const unsigned char* ekey, 
			   unsigned char* dkey,
			   int rounds);

static
void AESNI_128_EKey_Expansion_r(const unsigned char *userkey,
			  	      unsigned char *rkeys,
				      unsigned int rounds);
static
void AESNI_128_DKey_Expansion_r(const unsigned char *userkey,
			 	      unsigned char *rkeys,
				      unsigned int rounds);
static
void AESNI_192_EKey_Expansion_r(const unsigned char *userkey,
			  	      unsigned char *rkeys,
				      unsigned int rounds);
static
void AESNI_192_DKey_Expansion_r(const unsigned char *userkey,
			 	      unsigned char *rkeys,
				      unsigned int rounds);
static
void AESNI_256_EKey_Expansion_r(const unsigned char *userkey,
			  	      unsigned char *rkeys,
				      unsigned int rounds);
static
void AESNI_256_DKey_Expansion_r(const unsigned char *userkey,
			 	      unsigned char *rkeys,
				      unsigned int rounds);

static
void AESNI_128_EKey_ExpansionX2_r(const unsigned char *userkey,
			  	        unsigned char *rkeys,
				        unsigned int rounds);
static
void AESNI_128_DKey_ExpansionX2_r(const unsigned char *userkey,
			 	        unsigned char *rkeys,
				        unsigned int rounds);
static
void AESNI_192_EKey_ExpansionX2_r(const unsigned char *userkey,
			  	        unsigned char *rkeys,
				        unsigned int rounds);
static
void AESNI_192_DKey_ExpansionX2_r(const unsigned char *userkey,
			 	        unsigned char *rkeys,
				        unsigned int rounds);
static
void AESNI_256_EKey_ExpansionX2_r(const unsigned char *userkey,
			  	        unsigned char *rkeys,
				        unsigned int rounds);
static
void AESNI_256_DKey_ExpansionX2_r(const unsigned char *userkey,
			 	        unsigned char *rkeys,
				        unsigned int rounds);

/* With std no of rounds */
#define AESNI_128_EKey_Expansion(uk, rk) AESNI_128_EKey_Expansion_r(uk, rk, AES_128_ROUNDS)
#define AESNI_128_DKey_Expansion(uk, rk) AESNI_128_DKey_Expansion_r(uk, rk, AES_128_ROUNDS)
#define AESNI_192_EKey_Expansion(uk, rk) AESNI_192_EKey_Expansion_r(uk, rk, AES_192_ROUNDS)
#define AESNI_192_DKey_Expansion(uk, rk) AESNI_192_DKey_Expansion_r(uk, rk, AES_192_ROUNDS)
#define AESNI_256_EKey_Expansion(uk, rk) AESNI_256_EKey_Expansion_r(uk, rk, AES_256_ROUNDS)
#define AESNI_256_DKey_Expansion(uk, rk) AESNI_256_DKey_Expansion_r(uk, rk, AES_256_ROUNDS)

/* ECB, one 16byte block at a time */
static
void AESNI_ECB_Encrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, unsigned int rounds);
static
void AESNI_ECB_Decrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, unsigned int rounds);
/* ECB, 8 16byte blocks at a time */
static
int  AESNI_ECB_Encrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv /* unused */, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen);
static
int  AESNI_ECB_Decrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv /* unused */, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen);
/* CBC */
static
int  AESNI_CBC_Encrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen);
static
int  AESNI_CBC_Decrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen);
/* CTR */
static
void AESNI_CTR_Prep_2(const unsigned char* iv, const unsigned char* nonce,
		      unsigned char* ctr, unsigned long long val);
static
void AESNI_CTR_Prep(const unsigned char* iv, unsigned char* ctr, unsigned long long val);
static
int  AESNI_CTR_Crypt(const unsigned char* key, unsigned int rounds,
			unsigned char *ctr, unsigned int pad /* unused */,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen /* unneeded */);
static
void AESNI_CTR_Crypt_old(const unsigned char* in, unsigned char* out,
		     unsigned char* ctr,
		     ssize_t len, const unsigned char* key, unsigned int rounds);

/* Double encrpytion */
/* ECB */
static
int  AESNI_ECB_EncryptX2(const unsigned char* key, unsigned int rounds,
			unsigned char *iv /* unused */, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen);
static
int  AESNI_ECB_DecryptX2(const unsigned char* key, unsigned int rounds,
			unsigned char *iv /* unused */, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen);
/* CBC */
static
int  AESNI_CBC_EncryptX2(const unsigned char* key, unsigned int rounds,
			unsigned char *iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen);
static
int  AESNI_CBC_DecryptX2(const unsigned char* key, unsigned int rounds,
			unsigned char *iv, unsigned int pad,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen);
/* CTR */
static
int  AESNI_CTR_CryptX2(const unsigned char* key, unsigned int rounds,
			unsigned char *ctr, unsigned int pad /* unused */,
			const unsigned char* in, unsigned char* out,
			ssize_t len, ssize_t *olen /* unneeded */);
#endif

extern ciph_desc_t SAESNI_Methods[];
#ifndef NO_AVX2
extern ciph_desc_t VAESNI_Methods[];
#endif

#endif
