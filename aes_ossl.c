#include <openssl/evp.h>
#include <assert.h>
#include "aes.h"
#include "aes_ossl.h"
#include <string.h>

#include <netinet/in.h>

void AES_OSSL_Bits_EKey_Expand(const EVP_CIPHER *cipher, const unsigned char* userkey, unsigned char *ctx)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_init(evpctx);
	EVP_EncryptInit_ex(evpctx, cipher, NULL, userkey, NULL);
	EVP_CIPHER_CTX_set_padding(evpctx, 0);
}
void AES_OSSL_Bits_DKey_Expand(const EVP_CIPHER *cipher, const unsigned char* userkey, unsigned char *ctx)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_init(evpctx);
	EVP_DecryptInit_ex(evpctx, cipher, NULL, userkey, NULL);
	EVP_CIPHER_CTX_set_padding(evpctx, 0);
}

#define AES_OSSL_KEY_EX(BITS, ROUNDS, CHAIN)	\
void AES_OSSL_##BITS##_EKey_Expand_##CHAIN (const unsigned char *userkey, unsigned char *ctx, unsigned int rounds)	\
{							\
	assert(rounds == ROUNDS);			\
	AES_OSSL_Bits_EKey_Expand(EVP_aes_##BITS##_##CHAIN (), userkey, ctx);	\
};							\
void AES_OSSL_##BITS##_DKey_Expand_##CHAIN (const unsigned char *userkey, unsigned char *ctx, unsigned int rounds)	\
{							\
	assert(rounds == ROUNDS);			\
	AES_OSSL_Bits_DKey_Expand(EVP_aes_##BITS##_##CHAIN (), userkey, ctx);	\
}

#define AES_OSSL_CRYPT(BITCHAIN, IV)	\
void AES_OSSL_##BITCHAIN##_Encrypt(const unsigned char* ctx, unsigned int rounds,	\
			        unsigned char* iv, const unsigned char* in, 		\
				unsigned char* out, ssize_t len)			\
{								\
	int olen;						\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;		\
	if (IV) {						\
		memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);		\
	}							\
	EVP_EncryptUpdate(evpctx, out, &olen, in, len);		\
};								\
void AES_OSSL_##BITCHAIN##_Decrypt(const unsigned char* ctx, unsigned int rounds,	\
			        unsigned char* iv, const unsigned char* in, 		\
				unsigned char* out, ssize_t len)			\
{								\
	int olen;						\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;		\
	if (IV) {						\
		memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);		\
	}							\
	EVP_DecryptUpdate(evpctx, out, &olen, in, len);		\
}

void AES_OSSL_Release(unsigned char *ctx, unsigned int rounds)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_cleanup(evpctx);
	free(ctx);
}

AES_OSSL_KEY_EX(128, AES_128_ROUNDS, ecb);
AES_OSSL_KEY_EX(128, AES_128_ROUNDS, cbc);
AES_OSSL_KEY_EX(128, AES_128_ROUNDS, ctr);

AES_OSSL_CRYPT(128_ECB, 0);
AES_OSSL_CRYPT(128_CBC, 1);
AES_OSSL_CRYPT(128_CTR, 1);

AES_OSSL_KEY_EX(192, AES_192_ROUNDS, ecb);
AES_OSSL_KEY_EX(192, AES_192_ROUNDS, cbc);
AES_OSSL_KEY_EX(192, AES_192_ROUNDS, ctr);

AES_OSSL_CRYPT(192_ECB, 0);
AES_OSSL_CRYPT(192_CBC, 1);
AES_OSSL_CRYPT(192_CTR, 1);

AES_OSSL_KEY_EX(256, AES_256_ROUNDS, ecb);
AES_OSSL_KEY_EX(256, AES_256_ROUNDS, cbc);
AES_OSSL_KEY_EX(256, AES_256_ROUNDS, ctr);

AES_OSSL_CRYPT(256_ECB, 0);
AES_OSSL_CRYPT(256_CBC, 1);
AES_OSSL_CRYPT(256_CTR, 1);

#define EVP_CTX_SZ sizeof(EVP_CIPHER_CTX)

aes_desc_t AES_OSSL_Methods[] = {{"AES128-ECB"  , 128, 10, EVP_CTX_SZ, AES_OSSL_128_EKey_Expand_ecb, AES_OSSL_128_DKey_Expand_ecb,
							NULL, AES_OSSL_128_ECB_Encrypt, AES_OSSL_128_ECB_Decrypt, AES_OSSL_Release},
				{"AES128-CBC"  , 128, 10, EVP_CTX_SZ, AES_OSSL_128_EKey_Expand_cbc, AES_OSSL_128_DKey_Expand_cbc,
							NULL, AES_OSSL_128_CBC_Encrypt, AES_OSSL_128_CBC_Decrypt, AES_OSSL_Release},
				{"AES128-CTR"  , 128, 10, EVP_CTX_SZ, AES_OSSL_128_EKey_Expand_ctr, AES_OSSL_128_EKey_Expand_ctr,
						AES_Gen_CTR_Prep, AES_OSSL_128_CTR_Encrypt, AES_OSSL_128_CTR_Encrypt, AES_OSSL_Release},
				{"AES192-ECB"  , 192, 12, EVP_CTX_SZ, AES_OSSL_192_EKey_Expand_ecb, AES_OSSL_192_DKey_Expand_ecb,
							NULL, AES_OSSL_192_ECB_Encrypt, AES_OSSL_192_ECB_Decrypt, AES_OSSL_Release},
				{"AES192-CBC"  , 192, 12, EVP_CTX_SZ, AES_OSSL_192_EKey_Expand_cbc, AES_OSSL_192_DKey_Expand_cbc,
							NULL, AES_OSSL_192_CBC_Encrypt, AES_OSSL_192_CBC_Decrypt, AES_OSSL_Release},
				{"AES192-CTR"  , 192, 12, EVP_CTX_SZ, AES_OSSL_192_EKey_Expand_ctr, AES_OSSL_192_EKey_Expand_ctr,
						AES_Gen_CTR_Prep, AES_OSSL_192_CTR_Encrypt, AES_OSSL_192_CTR_Encrypt, AES_OSSL_Release},
				{"AES256-ECB"  , 256, 14, EVP_CTX_SZ, AES_OSSL_256_EKey_Expand_ecb, AES_OSSL_256_DKey_Expand_ecb,
							NULL, AES_OSSL_256_ECB_Encrypt, AES_OSSL_256_ECB_Decrypt, AES_OSSL_Release},
				{"AES256-CBC"  , 256, 14, EVP_CTX_SZ, AES_OSSL_256_EKey_Expand_cbc, AES_OSSL_256_DKey_Expand_cbc,
							NULL, AES_OSSL_256_CBC_Encrypt, AES_OSSL_256_CBC_Decrypt, AES_OSSL_Release},
				{"AES256-CTR"  , 256, 14, EVP_CTX_SZ, AES_OSSL_256_EKey_Expand_ctr, AES_OSSL_256_EKey_Expand_ctr,
						AES_Gen_CTR_Prep, AES_OSSL_256_CTR_Encrypt, AES_OSSL_256_CTR_Encrypt, AES_OSSL_Release},
				{NULL, /* ... */}
};
