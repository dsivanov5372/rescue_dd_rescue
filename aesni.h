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

/* aesni.c */
void AESNI_EKey_DKey(const unsigned char* ekey, 
			   unsigned char* dkey,
			   int rounds);

void AESNI_128_EKey_Expansion_r(const unsigned char *userkey,
			  	      unsigned char *rkeys,
				      unsigned int rounds);
void AESNI_128_DKey_Expansion_r(const unsigned char *userkey,
			 	      unsigned char *rkeys,
				      unsigned int rounds);
void AESNI_192_EKey_Expansion_r(const unsigned char *userkey,
			  	      unsigned char *rkeys,
				      unsigned int rounds);
void AESNI_192_DKey_Expansion_r(const unsigned char *userkey,
			 	      unsigned char *rkeys,
				      unsigned int rounds);
void AESNI_256_EKey_Expansion_r(const unsigned char *userkey,
			  	      unsigned char *rkeys,
				      unsigned int rounds);
void AESNI_256_DKey_Expansion_r(const unsigned char *userkey,
			 	      unsigned char *rkeys,
				      unsigned int rounds);

void AESNI_128_EKey_ExpansionX2_r(const unsigned char *userkey,
			  	        unsigned char *rkeys,
				        unsigned int rounds);
void AESNI_128_DKey_ExpansionX2_r(const unsigned char *userkey,
			 	        unsigned char *rkeys,
				        unsigned int rounds);
void AESNI_192_EKey_ExpansionX2_r(const unsigned char *userkey,
			  	        unsigned char *rkeys,
				        unsigned int rounds);
void AESNI_192_DKey_ExpansionX2_r(const unsigned char *userkey,
			 	        unsigned char *rkeys,
				        unsigned int rounds);
void AESNI_256_EKey_ExpansionX2_r(const unsigned char *userkey,
			  	        unsigned char *rkeys,
				        unsigned int rounds);
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
void AESNI_ECB_Encrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, unsigned int rounds);
void AESNI_ECB_Decrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, unsigned int rounds);
/* ECB, 8 16byte blocks at a time */
void AESNI_ECB_Encrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv,	/* unused */
			const unsigned char* in, unsigned char* out,
			ssize_t len);
void AESNI_ECB_Decrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv,	/* unused */
			const unsigned char* in, unsigned char* out,
			ssize_t len);
/* CBC */
void AESNI_CBC_Encrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv,
			const unsigned char* in, unsigned char* out,
			ssize_t len);
void AESNI_CBC_Decrypt(const unsigned char* key, unsigned int rounds,
			unsigned char *iv,
			const unsigned char* in, unsigned char* out,
			ssize_t len);
/* CTR */
void AESNI_CTR_Prep_2(const unsigned char* iv, const unsigned char* nonce,
		      unsigned char* ctr, unsigned long long val);
void AESNI_CTR_Prep(const unsigned char* iv, unsigned char* ctr, unsigned long long val);
void AESNI_CTR_Crypt(const unsigned char* key, unsigned int rounds,
			unsigned char *ctr,
			const unsigned char* in, unsigned char* out,
			ssize_t len);
void AESNI_CTR_Crypt_old(const unsigned char* in, unsigned char* out,
		     unsigned char* ctr,
		     ssize_t len, const unsigned char* key, unsigned int rounds);

/* Double encrpytion */
/* ECB */
void AESNI_ECB_EncryptX2(const unsigned char* key, unsigned int rounds,
			unsigned char *iv,	/* unused */
			const unsigned char* in, unsigned char* out,
			ssize_t len);
void AESNI_ECB_DecryptX2(const unsigned char* key, unsigned int rounds,
			unsigned char *iv,	/* unused */
			const unsigned char* in, unsigned char* out,
			ssize_t len);
/* CBC */
void AESNI_CBC_EncryptX2(const unsigned char* key, unsigned int rounds,
			unsigned char *iv,
			const unsigned char* in, unsigned char* out,
			ssize_t len);
void AESNI_CBC_DecryptX2(const unsigned char* key, unsigned int rounds,
			unsigned char *iv,
			const unsigned char* in, unsigned char* out,
			ssize_t len);
/* CTR */
void AESNI_CTR_CryptX2(const unsigned char* key, unsigned int rounds,
			unsigned char *ctr,
			const unsigned char* in, unsigned char* out,
			ssize_t len);

extern aes_desc_t AESNI_Methods[];

#endif