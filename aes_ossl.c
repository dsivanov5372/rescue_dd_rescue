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
	//EVP_CIPHER_CTX_set_padding(evpctx, 0);
}
void AES_OSSL_Bits_DKey_Expand(const EVP_CIPHER *cipher, const unsigned char* userkey, unsigned char *ctx)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_init(evpctx);
	EVP_DecryptInit_ex(evpctx, cipher, NULL, userkey, NULL);
	EVP_CIPHER_CTX_set_padding(evpctx, 0);
}

#define CHECK_ERR(x)		\
	if (!x)			\
		fprintf(stderr, "Error returned by %s !\n", #x)
#define CHECK_ERR2(FN,OUT,OL,EL)		\
	oerr = FN (evpctx, OUT+OL, &EL);	\
	if (!oerr)				\
		fprintf(stderr, "%s(%p+%i, &%i) returned %i\n",	\
			#FN, OUT, OL, EL, oerr)

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
	int olen, elen, oerr;					\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;		\
	if (IV) {						\
		memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);		\
	}							\
	CHECK_ERR(EVP_EncryptUpdate(evpctx, out, &olen, in, len));			\
	CHECK_ERR2(EVP_EncryptFinal, out, olen, elen);		\
	if (olen+elen < len)					\
		fprintf(stderr, "Short encryption %i+%i < %zi\n",\
			olen, elen, len);			\
};								\
void AES_OSSL_##BITCHAIN##_Decrypt(const unsigned char* ctx, unsigned int rounds,	\
			        unsigned char* iv, const unsigned char* in, 		\
				unsigned char* out, ssize_t len)			\
{								\
	int olen, elen, oerr;					\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;		\
	if (IV) {						\
		memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);		\
	}							\
	CHECK_ERR(EVP_DecryptUpdate(evpctx, out, &olen, in, len));			\
	CHECK_ERR2(EVP_DecryptFinal, out, olen, elen);		\
	if (olen+elen < len)					\
		fprintf(stderr, "Short decryption %i+%i < %zi\n",\
			olen, elen, len);			\
}

void AES_OSSL_Release(unsigned char *ctx, unsigned int rounds)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_cleanup(evpctx);
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

/* Double encryption 
 * This only works in a straightforward way for ECB ...
 * For the others we need to break up the loop:
 * ECB: AES2(AES1(p)) == AESx2(p)
 * CBC: AES2(IV2^AES1(IV1^p)) != AESx2(IV^p)
 * CTR: AES2(CTR)^AES1(CTR)^p != AES2(AES1(CTR))^p == AESx2(CTR)^p
 * */

#include "sha256.h"

void AES_OSSL_Bits_EKey_ExpandX2(const EVP_CIPHER *cipher, const unsigned char* userkey, unsigned char *ctx, unsigned int bits)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_init(evpctx);
	EVP_EncryptInit_ex(evpctx, cipher, NULL, userkey, NULL);
	//EVP_CIPHER_CTX_set_padding(evpctx, 0);
	hash_t hv;
	sha256_init(&hv);
	sha256_calc(userkey, bits/8, bits/8, &hv);
	uchar usrkey2[32];
	sha256_beout(usrkey2, &hv);
	sha256_init(&hv);
	EVP_CIPHER_CTX_init(evpctx+1);
	EVP_EncryptInit_ex(evpctx+1, cipher, NULL, usrkey2, NULL);
	//EVP_CIPHER_CTX_set_padding(evpctx+1, 0);
	memset(usrkey2, 0, 32);
	asm("":::"memory");
}
void AES_OSSL_Bits_DKey_ExpandX2(const EVP_CIPHER *cipher, const unsigned char* userkey, unsigned char *ctx, unsigned int bits)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_init(evpctx);
	EVP_DecryptInit_ex(evpctx, cipher, NULL, userkey, NULL);
	//EVP_CIPHER_CTX_set_padding(evpctx, 0);
	hash_t hv;
	sha256_init(&hv);
	sha256_calc(userkey, bits/8, bits/8, &hv);
	uchar usrkey2[32];
	sha256_beout(usrkey2, &hv);
	sha256_init(&hv);
	EVP_CIPHER_CTX_init(evpctx+1);
	EVP_DecryptInit_ex(evpctx+1, cipher, NULL, usrkey2, NULL);
	//EVP_CIPHER_CTX_set_padding(evpctx+1, 0);
	memset(usrkey2, 0, 32);
	asm("":::"memory");
}


#define AES_OSSL_KEY_EX2(BITS, ROUNDS, CHAIN)	\
void AES_OSSL_##BITS##_EKey_ExpandX2_##CHAIN (const unsigned char *userkey, unsigned char *ctx, unsigned int rounds)	\
{							\
	assert(rounds == 2*ROUNDS);			\
	AES_OSSL_Bits_EKey_ExpandX2(EVP_aes_##BITS##_##CHAIN (), userkey, ctx, BITS);	\
};							\
void AES_OSSL_##BITS##_DKey_ExpandX2_##CHAIN (const unsigned char *userkey, unsigned char *ctx, unsigned int rounds)	\
{							\
	assert(rounds == 2*ROUNDS);			\
	AES_OSSL_Bits_DKey_ExpandX2(EVP_aes_##BITS##_##CHAIN (), userkey, ctx, BITS);	\
}

#define AES_OSSL_CRYPT2(BITCHAIN, IV)	\
void AES_OSSL_##BITCHAIN##_EncryptX2(const unsigned char* ctx, unsigned int rounds,	\
			        unsigned char* iv, const unsigned char* in, 		\
				unsigned char* out, ssize_t len)			\
{								\
	int olen, elen;						\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;		\
	if (IV) {						\
		memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);		\
		memcpy((evpctx+1)->oiv, iv, 16); memcpy((evpctx+1)->iv, iv, 16);	\
	}							\
	EVP_EncryptUpdate(evpctx, out, &olen, in, len);		\
	EVP_EncryptFinal(evpctx, out+olen, &elen);		\
	EVP_EncryptUpdate(evpctx+1, out, &olen, out, olen+elen);\
	EVP_EncryptFinal(evpctx+1, out+olen, &elen);		\
};								\
void AES_OSSL_##BITCHAIN##_DecryptX2(const unsigned char* ctx, unsigned int rounds,	\
			        unsigned char* iv, const unsigned char* in, 		\
				unsigned char* out, ssize_t len)			\
{								\
	int olen, elen;						\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;		\
	if (IV) {						\
		memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);		\
		memcpy((evpctx+1)->oiv, iv, 16); memcpy((evpctx+1)->iv, iv, 16);	\
	}							\
	EVP_DecryptUpdate(evpctx+1, out, &olen, in, len);	\
	EVP_DecryptFinal(evpctx+1, out+olen, &elen);		\
	EVP_DecryptUpdate(evpctx, out, &olen, out, olen+elen);	\
	EVP_DecryptFinal(evpctx, out+olen, &elen);		\
}

void AES_OSSL_ReleaseX2(unsigned char *ctx, unsigned int rounds)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_cleanup(evpctx);
	EVP_CIPHER_CTX_cleanup(evpctx+1);
}

AES_OSSL_KEY_EX2(128, AES_128_ROUNDS, ecb);
//AES_OSSL_KEY_EX2(128, AES_128_ROUNDS, cbc);
//AES_OSSL_KEY_EX2(128, AES_128_ROUNDS, ctr);

AES_OSSL_CRYPT2(128_ECB, 0);
//AES_OSSL_CRYPT2(128_CBC, 1);
//AES_OSSL_CRYPT2(128_CTR, 1);

AES_OSSL_KEY_EX2(192, AES_192_ROUNDS, ecb);
//AES_OSSL_KEY_EX2(192, AES_192_ROUNDS, cbc);
//AES_OSSL_KEY_EX2(192, AES_192_ROUNDS, ctr);

AES_OSSL_CRYPT2(192_ECB, 0);
//AES_OSSL_CRYPT2(192_CBC, 1);
//AES_OSSL_CRYPT2(192_CTR, 1);

AES_OSSL_KEY_EX2(256, AES_256_ROUNDS, ecb);
//AES_OSSL_KEY_EX2(256, AES_256_ROUNDS, cbc);
//AES_OSSL_KEY_EX2(256, AES_256_ROUNDS, ctr);

AES_OSSL_CRYPT2(256_ECB, 0);
//AES_OSSL_CRYPT2(256_CBC, 1);
//AES_OSSL_CRYPT2(256_CTR, 1);

void AES_OSSL_Blk_EncryptX2(const unsigned char *ctx, unsigned int rounds,
			    const unsigned char *in, unsigned char *out)			
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	int olen;
	uchar blk[16];
	EVP_EncryptUpdate(evpctx, blk, &olen, in, 16);
	EVP_EncryptUpdate(evpctx+1, out, &olen, blk, olen);
	memset(blk, 0, 16);
	asm("":::"memory");
}
void AES_OSSL_Blk_DecryptX2(const unsigned char *ctx, unsigned int rounds,
			    const unsigned char *in, unsigned char *out)			
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	int olen;
	uchar blk[16];
	EVP_DecryptUpdate(evpctx+1, blk, &olen, in, 16);
	EVP_DecryptUpdate(evpctx, out, &olen, blk, olen);
	memset(blk, 0, 16);
	asm("":::"memory");
}


#define AES_OSSL_DECL_CBC_X2(BITS)							\
void AES_OSSL_##BITS##_CBC_EncryptX2(const unsigned char *ctx, unsigned int rounds,	\
				     unsigned char *iv, const unsigned char* in,	\
				     unsigned char *out, ssize_t len)			\
{											\
	AES_Gen_CBC_Enc(AES_OSSL_Blk_EncryptX2, ctx, rounds, iv, in, out, len);		\
};											\
void AES_OSSL_##BITS##_CBC_DecryptX2(const unsigned char *ctx, unsigned int rounds,	\
				     unsigned char *iv, const unsigned char* in,	\
				     unsigned char *out, ssize_t len)			\
{											\
	AES_Gen_CBC_Dec(AES_OSSL_Blk_DecryptX2, ctx, rounds, iv, in, out, len);		\
}

AES_OSSL_DECL_CBC_X2(128);
AES_OSSL_DECL_CBC_X2(192);
AES_OSSL_DECL_CBC_X2(256);


#define AES_OSSL_DECL_CTR_X2(BITS)							\
void AES_OSSL_##BITS##_CTR_CryptX2(const unsigned char *ctx, unsigned int rounds,	\
				     unsigned char *iv, const unsigned char* in,	\
				     unsigned char *out, ssize_t len)			\
{											\
	AES_Gen_CTR_Crypt(AES_OSSL_Blk_EncryptX2, ctx, rounds, iv, in, out, len);	\
}

AES_OSSL_DECL_CTR_X2(128);
AES_OSSL_DECL_CTR_X2(192);
AES_OSSL_DECL_CTR_X2(256);


#define EVP_CTX_SZ sizeof(EVP_CIPHER_CTX)
#define EVP_CTX_SZX2 2*sizeof(EVP_CIPHER_CTX)

aes_desc_t AES_OSSL_Methods[] = {
				{"AES128-ECB"  , 128, 10, EVP_CTX_SZ, AES_OSSL_128_EKey_Expand_ecb, AES_OSSL_128_DKey_Expand_ecb,
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
				/* TODO */
				{"AES128x2-ECB"  , 128, 20, EVP_CTX_SZX2, AES_OSSL_128_EKey_ExpandX2_ecb, AES_OSSL_128_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_128_ECB_EncryptX2, AES_OSSL_128_ECB_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES128x2-CBC"  , 128, 20, EVP_CTX_SZX2, AES_OSSL_128_EKey_ExpandX2_ecb, AES_OSSL_128_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_128_CBC_EncryptX2, AES_OSSL_128_CBC_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES128x2-CTR"  , 128, 20, EVP_CTX_SZX2, AES_OSSL_128_EKey_ExpandX2_ecb, AES_OSSL_128_EKey_ExpandX2_ecb,
						AES_Gen_CTR_Prep, AES_OSSL_128_CTR_CryptX2, AES_OSSL_128_CTR_CryptX2, AES_OSSL_ReleaseX2},
				{"AES192x2-ECB"  , 192, 24, EVP_CTX_SZX2, AES_OSSL_192_EKey_ExpandX2_ecb, AES_OSSL_192_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_192_ECB_EncryptX2, AES_OSSL_192_ECB_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES192x2-CBC"  , 192, 24, EVP_CTX_SZX2, AES_OSSL_192_EKey_ExpandX2_ecb, AES_OSSL_192_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_192_CBC_EncryptX2, AES_OSSL_192_CBC_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES192x2-CTR"  , 192, 24, EVP_CTX_SZX2, AES_OSSL_192_EKey_ExpandX2_ecb, AES_OSSL_192_EKey_ExpandX2_ecb,
						AES_Gen_CTR_Prep, AES_OSSL_192_CTR_CryptX2, AES_OSSL_192_CTR_CryptX2, AES_OSSL_ReleaseX2},
				{"AES256x2-ECB"  , 256, 28, EVP_CTX_SZX2, AES_OSSL_256_EKey_ExpandX2_ecb, AES_OSSL_256_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_256_ECB_EncryptX2, AES_OSSL_256_ECB_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES256x2-CBC"  , 256, 28, EVP_CTX_SZX2, AES_OSSL_256_EKey_ExpandX2_ecb, AES_OSSL_256_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_256_CBC_EncryptX2, AES_OSSL_256_CBC_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES256x2-CTR"  , 256, 28, EVP_CTX_SZX2, AES_OSSL_256_EKey_ExpandX2_ecb, AES_OSSL_256_EKey_ExpandX2_ecb,
						AES_Gen_CTR_Prep, AES_OSSL_256_CTR_CryptX2, AES_OSSL_256_CTR_CryptX2, AES_OSSL_ReleaseX2},
				{NULL, /* ... */}
};
