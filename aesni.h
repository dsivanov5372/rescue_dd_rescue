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

/* With std no of rounds */
#define AESNI_128_EKey_Expansion(uk, rk) AESNI_128_EKey_Expansion_r(uk, rk, AES_128_ROUNDS)
#define AESNI_128_DKey_Expansion(uk, rk) AESNI_128_DKey_Expansion_r(uk, rk, AES_128_ROUNDS)
#define AESNI_192_EKey_Expansion(uk, rk) AESNI_192_EKey_Expansion_r(uk, rk, AES_192_ROUNDS)
#define AESNI_192_DKey_Expansion(uk, rk) AESNI_192_DKey_Expansion_r(uk, rk, AES_192_ROUNDS)
#define AESNI_256_EKey_Expansion(uk, rk) AESNI_256_EKey_Expansion_r(uk, rk, AES_256_ROUNDS)
#define AESNI_256_DKey_Expansion(uk, rk) AESNI_256_DKey_Expansion_r(uk, rk, AES_256_ROUNDS)

/* ECB, one 16byte block at a time */
void AESNI_ECB_encrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, int rounds);
void AESNI_ECB_decrypt_old(const unsigned char* in, unsigned char* out,
			   ssize_t len, const unsigned char* key, int rounds);
/* ECB, 4 16byte blocks at a time */
void AESNI_ECB_encrypt(const unsigned char* in, unsigned char* out,
		       ssize_t len, const unsigned char* key, int rounds);
void AESNI_ECB_decrypt(const unsigned char* in, unsigned char* out,
		       ssize_t len, const unsigned char* key, int rounds);
/* CBC */
void AESNI_CBC_encrypt(const unsigned char* in, unsigned char* out,
		       const unsigned char* iv,
		       ssize_t len, const unsigned char* key, int rounds);
void AESNI_CBC_decrypt(const unsigned char* in, unsigned char* out,
		       const unsigned char* iv,
		       ssize_t len, const unsigned char* key, int rounds);
/* CTR */
void AESNI_CTR_prep_2(const unsigned char* iv, const unsigned char* nonce,
		      unsigned char* ctr, unsigned long long val);
void AESNI_CTR_prep(const unsigned char* iv, unsigned char* ctr, unsigned long long val);
void AESNI_CTR_crypt(const unsigned char* in, unsigned char* out,
		     unsigned char* ctr,
		     ssize_t len, const unsigned char* key, int rounds);

void AESNI_CTR_crypt_old(const unsigned char* in, unsigned char* out,
		     unsigned char* ctr,
		     ssize_t len, const unsigned char* key, int rounds);

#endif
