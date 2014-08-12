#include <openssl/evp.h>
#include <assert.h>
#include "aes.h"
#include "aes_ossl.h"
#include <string.h>

#include <netinet/in.h>

void AES_OSSL_128_EKey_Expand(const unsigned char *userkey,
			  	 unsigned char *ctx,
				 unsigned int rounds)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_init(evpctx);
	assert(rounds == AES_128_ROUNDS);
	EVP_EncryptInit(evpctx, EVP_aes_128_ecb(), userkey, NULL);
	EVP_CIPHER_CTX_set_padding(evpctx, 0);
}

void AES_OSSL_128_DKey_Expand(const unsigned char *userkey,
			  	 unsigned char *ctx,
				 unsigned int rounds)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_init(evpctx);
	assert(rounds == AES_128_ROUNDS);
	EVP_DecryptInit(evpctx, EVP_aes_128_ecb(), userkey, NULL);
	EVP_CIPHER_CTX_set_padding(evpctx, 0);
}

void AES_OSSL_128_ECB_Encrypt(const unsigned char* ctx, unsigned int rounds,
			         unsigned char* iv,
			         const unsigned char* in, unsigned char* out,
			         ssize_t len)
{
	int olen;
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_EncryptUpdate(evpctx, out, &olen, in, len); 
	/*; EVP_EncryptFinal(evpcctx, out+olen, &flen)*/
}

void AES_OSSL_128_ECB_Decrypt(const unsigned char* ctx, unsigned int rounds,
			         unsigned char* iv,
			         const unsigned char* in, unsigned char* out,
			         ssize_t len)
{
	int olen;
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_DecryptUpdate(evpctx, out, &olen, in, len); 
	/*; EVP_DecryptFinal(evpcctx, out+olen, &flen)*/
}

void AES_OSSL_128_CBC_Encrypt(const unsigned char* ctx, unsigned int rounds,
			         unsigned char* iv,
			         const unsigned char* in, unsigned char* out,
			         ssize_t len)
{
	int olen;
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);
	evpctx->cipher = EVP_aes_128_cbc();
	EVP_EncryptUpdate(evpctx, out, &olen, in, len); 
	/*; EVP_EncryptFinal(evpcctx, out+olen, &flen)*/
}

void AES_OSSL_128_CBC_Decrypt(const unsigned char* ctx, unsigned int rounds,
			         unsigned char* iv,
			         const unsigned char* in, unsigned char* out,
			         ssize_t len)
{
	int olen;
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);
	evpctx->cipher = EVP_aes_128_cbc();
	EVP_DecryptUpdate(evpctx, out, &olen, in, len); 
	/*; EVP_DecryptFinal(evpcctx, out+olen, &flen)*/
}


void AES_OSSL_128_CTR_Crypt(const unsigned char* ctx, unsigned int rounds,
			         unsigned char* iv,
			         const unsigned char* in, unsigned char* out,
			         ssize_t len)
{
	int olen;
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);
	/* Only works for 32bit ctr values */
	evpctx->num = ntohl(*(int*)(iv+12));
	evpctx->cipher = EVP_aes_128_ctr();
	EVP_EncryptUpdate(evpctx, out, &olen, in, len); 
	/*; EVP_EncryptFinal(evpcctx, out+olen, &flen)*/
}

#define EVP_CTX_SZ sizeof(EVP_CIPHER_CTX)

aes_desc_t AES_OSSL_Methods[] = {{"AES128-ECB"  , 128, 10, EVP_CTX_SZ, AES_OSSL_128_EKey_Expand, AES_OSSL_128_DKey_Expand,
							NULL, AES_OSSL_128_ECB_Encrypt, AES_OSSL_128_ECB_Decrypt},
			      {"AES128-CBC"  , 128, 10, EVP_CTX_SZ, AES_OSSL_128_EKey_Expand, AES_OSSL_128_DKey_Expand,
							NULL, AES_OSSL_128_CBC_Encrypt, AES_OSSL_128_CBC_Decrypt},
			      {"AES128-CTR"  , 128, 10, EVP_CTX_SZ, AES_OSSL_128_EKey_Expand, AES_OSSL_128_EKey_Expand,
						AES_Gen_CTR_Prep, AES_OSSL_128_CTR_Crypt, AES_OSSL_128_CTR_Crypt},
			      {NULL, /* ... */}
};
