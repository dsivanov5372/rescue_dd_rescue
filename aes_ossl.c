#include <openssl/evp.h>
#include <assert.h>
#include "aes.h"

void AES_OSSLEVP_128_EKey_Expand(const unsigned char *userkey,
			  	 unsigned char *ctx,
				 unsigned int rounds)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_init(evpctx);
	assert(rounds == AES_128_ROUNDS);
	EVP_EncryptInit(evpctx, EVP_aes_128_ecb(), userkey, NULL);
	EVP_CIPHER_CTX_set_padding(evpctx, 0);
}

void AES_OSSLEVP_128_DKey_Expand(const unsigned char *userkey,
			  	 unsigned char *ctx,
				 unsigned int rounds)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_init(evpctx);
	assert(rounds == AES_128_ROUNDS);
	EVP_DecryptInit(evpctx, EVP_aes_128_ecb(), userkey, NULL);
	EVP_CIPHER_CTX_set_padding(evpctx, 0);
}

void AES_OSSLEVP_128_Encrypt(const unsigned char* ctx, unsigned int rounds,
			     unsigned char* iv,
			     const unsigned char* in, unsigned char* out,
			     ssize_t len)
{
	int olen;
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_EncryptUpdate(evpctx, out, &olen, in, len); 
	/*; EVP_EncryptFinal(evpcctx, out+olen, &flen)*/
}


