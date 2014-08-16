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
}
void AES_OSSL_Bits_DKey_Expand(const EVP_CIPHER *cipher, const unsigned char* userkey, unsigned char *ctx)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_init(evpctx);
	EVP_DecryptInit_ex(evpctx, cipher, NULL, userkey, NULL);
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

#define AES_OSSL_CRYPT(BITCHAIN, IV, DOPAD)	\
int AES_OSSL_##BITCHAIN##_Encrypt(const unsigned char* ctx, unsigned int rounds,	\
			        unsigned char* iv, unsigned int pad, 			\
				const unsigned char* in, unsigned char* out, 		\
				ssize_t len, ssize_t *flen)				\
{								\
	int olen, elen, oerr;					\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;		\
	EVP_CIPHER_CTX_set_padding(evpctx, DOPAD? pad: 0);	\
	if (IV) {						\
		memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);		\
	}							\
       	if (DOPAD && !pad && (len&15)) {			\
		CHECK_ERR(EVP_EncryptUpdate(evpctx, out, &olen, in, len-(len&15)));	\
		uchar ibf[16];					\
		memcpy(ibf, in+olen, len&15);			\
		memset(ibf+(len&15), 0, 16-(len&15));		\
		CHECK_ERR(EVP_EncryptUpdate(evpctx, out+olen, &elen, ibf, 16));		\
		memset(ibf, 0, len&15);				\
		asm("":::"memory");				\
	} else {									\
		CHECK_ERR(EVP_EncryptUpdate(evpctx, out, &olen, in, len));		\
		CHECK_ERR2(EVP_EncryptFinal, out, olen, elen);				\
	}							\
	*flen = olen+elen;					\
	if (DOPAD && pad == PAD_ASNEEDED && !(len&15))		\
		*flen -= 16;					\
	if (olen+elen < len)					\
		fprintf(stderr, "Encryption length mismatch %i+%i != %zi\n",		\
			olen, elen, len);			\
	return (DOPAD && (pad == PAD_ALWAYS || (len&15)))? 16-(len&15): 0;	\
};								\
int  AES_OSSL_##BITCHAIN##_Decrypt(const unsigned char* ctx, unsigned int rounds,	\
			        unsigned char* iv, unsigned int pad,			\
				const unsigned char* in, unsigned char* out,		\
	       			ssize_t len, ssize_t *flen)				\
{								\
	int olen, elen = 0, oerr;				\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;		\
	EVP_CIPHER_CTX_set_padding(evpctx, DOPAD?pad:0);	\
	if (IV) {						\
		memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);		\
	}							\
	if (DOPAD && pad == PAD_ALWAYS)	{			\
		CHECK_ERR(EVP_DecryptUpdate(evpctx, out, &olen, in, len+16-(len&0x0f)));\
	} else {						\
		CHECK_ERR(EVP_DecryptUpdate(evpctx, out, &olen, in, (len&15)? len+16-(len&0x0f): len));\
	}							\
	CHECK_ERR2(EVP_DecryptFinal, out, olen, elen);		\
	if (DOPAD && pad) {					\
		*flen = olen + elen;				\
		if (olen+elen != len)				\
			fprintf(stderr, "Decryption length mismatch %i+%i != %zi\n",\
				olen, elen, len);		\
	} else							\
		*flen = len;					\
	return oerr - 1;					\
}

void AES_OSSL_Release(unsigned char *ctx, unsigned int rounds)
{
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;
	EVP_CIPHER_CTX_cleanup(evpctx);
}

AES_OSSL_KEY_EX(128, AES_128_ROUNDS, ecb);
AES_OSSL_KEY_EX(128, AES_128_ROUNDS, cbc);
AES_OSSL_KEY_EX(128, AES_128_ROUNDS, ctr);

AES_OSSL_CRYPT(128_ECB, 0, 1);
AES_OSSL_CRYPT(128_CBC, 1, 1);
AES_OSSL_CRYPT(128_CTR, 1, 0);

AES_OSSL_KEY_EX(192, AES_192_ROUNDS, ecb);
AES_OSSL_KEY_EX(192, AES_192_ROUNDS, cbc);
AES_OSSL_KEY_EX(192, AES_192_ROUNDS, ctr);

AES_OSSL_CRYPT(192_ECB, 0, 1);
AES_OSSL_CRYPT(192_CBC, 1, 1);
AES_OSSL_CRYPT(192_CTR, 1, 0);

AES_OSSL_KEY_EX(256, AES_256_ROUNDS, ecb);
AES_OSSL_KEY_EX(256, AES_256_ROUNDS, cbc);
AES_OSSL_KEY_EX(256, AES_256_ROUNDS, ctr);

AES_OSSL_CRYPT(256_ECB, 0, 1);
AES_OSSL_CRYPT(256_CBC, 1, 1);
AES_OSSL_CRYPT(256_CTR, 1, 0);

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
int  AES_OSSL_##BITCHAIN##_EncryptX2(const unsigned char* ctx, unsigned int rounds,	\
			        unsigned char* iv, unsigned int pad,			\
				const unsigned char* in, unsigned char* out,		\
	       			ssize_t len, ssize_t *flen)				\
{								\
	int olen, elen;						\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;		\
	EVP_CIPHER_CTX_set_padding(evpctx, pad);		\
	EVP_CIPHER_CTX_set_padding(evpctx+1, pad);		\
	if (IV) {						\
		memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);		\
		memcpy((evpctx+1)->oiv, iv, 16); memcpy((evpctx+1)->iv, iv, 16);	\
	}							\
       	if (!pad && (len&15)) {					\
		EVP_EncryptUpdate(evpctx, out, &olen, in, len-(len&15));		\
		uchar ibf[16];					\
		memcpy(ibf, in+olen, len&15);			\
		memset(ibf+(len&15), 0, 16-(len&15));		\
		EVP_EncryptUpdate(evpctx, out+olen, &elen, ibf, 16);			\
		memset(ibf, 0, len&15);				\
		asm("":::"memory");				\
	} else {						\
		EVP_EncryptUpdate(evpctx, out, &olen, in, len);	\
		EVP_EncryptFinal(evpctx, out+olen, &elen);	\
	}							\
	EVP_EncryptUpdate(evpctx+1, out, &olen, out, olen+elen);\
	EVP_EncryptFinal(evpctx+1, out+olen, &elen);		\
	*flen = olen+elen;					\
	if (pad == PAD_ASNEEDED && !(len&15))			\
		*flen -= 16;					\
	return (pad == PAD_ALWAYS || (len&15))? 16-(len&15): 0;	\
};								\
int  AES_OSSL_##BITCHAIN##_DecryptX2(const unsigned char* ctx, unsigned int rounds,	\
			        unsigned char* iv, unsigned int pad,			\
				const unsigned char* in, unsigned char* out,		\
	       			ssize_t len, ssize_t *flen)				\
{								\
	int olen, elen;						\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;		\
	EVP_CIPHER_CTX_set_padding(evpctx+1, pad);		\
	EVP_CIPHER_CTX_set_padding(evpctx, pad);		\
	if (IV) {						\
		memcpy((evpctx+1)->oiv, iv, 16); memcpy((evpctx+1)->iv, iv, 16);	\
		memcpy(evpctx->oiv, iv, 16); memcpy(evpctx->iv, iv, 16);		\
	}							\
	if (pad == PAD_ALWAYS)	{				\
		CHECK_ERR(EVP_DecryptUpdate(evpctx+1, out, &olen, in, len+16-(len&0x0f)));\
	} else {						\
		CHECK_ERR(EVP_DecryptUpdate(evpctx+1, out, &olen, in, (len&15)? len+16-(len&0x0f): len));\
	}							\
	EVP_DecryptFinal(evpctx+1, out+olen, &elen);		\
	EVP_DecryptUpdate(evpctx, out, &olen, out, olen+elen);	\
	int oerr = EVP_DecryptFinal(evpctx, out+olen, &elen);	\
	if (pad)						\
		*flen = olen+elen;				\
	else							\
		*flen = len;					\
	return oerr - 1;					\
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
int  AES_OSSL_##BITS##_CBC_EncryptX2(const unsigned char *ctx, unsigned int rounds,	\
				     unsigned char *iv, unsigned int pad,		\
				     const unsigned char* in, unsigned char *out,	\
	       			     ssize_t len, ssize_t *olen)			\
{											\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;					\
	EVP_CIPHER_CTX_set_padding(evpctx, 0);						\
	EVP_CIPHER_CTX_set_padding(evpctx+1, 0);					\
	return AES_Gen_CBC_Enc(AES_OSSL_Blk_EncryptX2, ctx, rounds, iv, pad, in, out, len, olen);	\
};											\
int  AES_OSSL_##BITS##_CBC_DecryptX2(const unsigned char *ctx, unsigned int rounds,	\
				     unsigned char *iv, unsigned int pad,		\
				     const unsigned char* in, unsigned char *out,	\
	       			     ssize_t len, ssize_t *olen)			\
{											\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;					\
	EVP_CIPHER_CTX_set_padding(evpctx+1, 0);					\
	EVP_CIPHER_CTX_set_padding(evpctx, 0);						\
	return AES_Gen_CBC_Dec(AES_OSSL_Blk_DecryptX2, ctx, rounds, iv, pad, in, out, len, olen);	\
}

AES_OSSL_DECL_CBC_X2(128);
AES_OSSL_DECL_CBC_X2(192);
AES_OSSL_DECL_CBC_X2(256);


#define AES_OSSL_DECL_CTR_X2(BITS)							\
int  AES_OSSL_##BITS##_CTR_CryptX2(const unsigned char *ctx, unsigned int rounds,	\
				     unsigned char *iv, unsigned int pad,		\
				     const unsigned char* in, unsigned char *out,	\
	       			     ssize_t len, ssize_t *olen)			\
{											\
	*olen = len;									\
	EVP_CIPHER_CTX *evpctx = (EVP_CIPHER_CTX*)ctx;					\
	EVP_CIPHER_CTX_set_padding(evpctx, 0);						\
	EVP_CIPHER_CTX_set_padding(evpctx+1, 0);					\
	return AES_Gen_CTR_Crypt(AES_OSSL_Blk_EncryptX2, ctx, rounds, iv, in, out, len);\
}

AES_OSSL_DECL_CTR_X2(128);
AES_OSSL_DECL_CTR_X2(192);
AES_OSSL_DECL_CTR_X2(256);


#define EVP_CTX_SZ sizeof(EVP_CIPHER_CTX)
#define EVP_CTX_SZX2 2*sizeof(EVP_CIPHER_CTX)

aes_desc_t AES_OSSL_Methods[] = {
				{"AES128-ECB"  , 128, 10, 16, EVP_CTX_SZ, AES_OSSL_128_EKey_Expand_ecb, AES_OSSL_128_DKey_Expand_ecb,
							NULL, AES_OSSL_128_ECB_Encrypt, AES_OSSL_128_ECB_Decrypt, AES_OSSL_Release},
				{"AES128-CBC"  , 128, 10, 16, EVP_CTX_SZ, AES_OSSL_128_EKey_Expand_cbc, AES_OSSL_128_DKey_Expand_cbc,
							NULL, AES_OSSL_128_CBC_Encrypt, AES_OSSL_128_CBC_Decrypt, AES_OSSL_Release},
				{"AES128-CTR"  , 128, 10,  1, EVP_CTX_SZ, AES_OSSL_128_EKey_Expand_ctr, AES_OSSL_128_EKey_Expand_ctr,
						AES_Gen_CTR_Prep, AES_OSSL_128_CTR_Encrypt, AES_OSSL_128_CTR_Encrypt, AES_OSSL_Release},
				{"AES192-ECB"  , 192, 12, 16, EVP_CTX_SZ, AES_OSSL_192_EKey_Expand_ecb, AES_OSSL_192_DKey_Expand_ecb,
							NULL, AES_OSSL_192_ECB_Encrypt, AES_OSSL_192_ECB_Decrypt, AES_OSSL_Release},
				{"AES192-CBC"  , 192, 12, 16, EVP_CTX_SZ, AES_OSSL_192_EKey_Expand_cbc, AES_OSSL_192_DKey_Expand_cbc,
							NULL, AES_OSSL_192_CBC_Encrypt, AES_OSSL_192_CBC_Decrypt, AES_OSSL_Release},
				{"AES192-CTR"  , 192, 12,  1, EVP_CTX_SZ, AES_OSSL_192_EKey_Expand_ctr, AES_OSSL_192_EKey_Expand_ctr,
						AES_Gen_CTR_Prep, AES_OSSL_192_CTR_Encrypt, AES_OSSL_192_CTR_Encrypt, AES_OSSL_Release},
				{"AES256-ECB"  , 256, 14, 16, EVP_CTX_SZ, AES_OSSL_256_EKey_Expand_ecb, AES_OSSL_256_DKey_Expand_ecb,
							NULL, AES_OSSL_256_ECB_Encrypt, AES_OSSL_256_ECB_Decrypt, AES_OSSL_Release},
				{"AES256-CBC"  , 256, 14, 16, EVP_CTX_SZ, AES_OSSL_256_EKey_Expand_cbc, AES_OSSL_256_DKey_Expand_cbc,
							NULL, AES_OSSL_256_CBC_Encrypt, AES_OSSL_256_CBC_Decrypt, AES_OSSL_Release},
				{"AES256-CTR"  , 256, 14,  1, EVP_CTX_SZ, AES_OSSL_256_EKey_Expand_ctr, AES_OSSL_256_EKey_Expand_ctr,
						AES_Gen_CTR_Prep, AES_OSSL_256_CTR_Encrypt, AES_OSSL_256_CTR_Encrypt, AES_OSSL_Release},
				/* TODO */
				{"AES128x2-ECB", 128, 20, 16, EVP_CTX_SZX2, AES_OSSL_128_EKey_ExpandX2_ecb, AES_OSSL_128_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_128_ECB_EncryptX2, AES_OSSL_128_ECB_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES128x2-CBC", 128, 20, 16, EVP_CTX_SZX2, AES_OSSL_128_EKey_ExpandX2_ecb, AES_OSSL_128_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_128_CBC_EncryptX2, AES_OSSL_128_CBC_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES128x2-CTR", 128, 20,  1, EVP_CTX_SZX2, AES_OSSL_128_EKey_ExpandX2_ecb, AES_OSSL_128_EKey_ExpandX2_ecb,
						AES_Gen_CTR_Prep, AES_OSSL_128_CTR_CryptX2, AES_OSSL_128_CTR_CryptX2, AES_OSSL_ReleaseX2},
				{"AES192x2-ECB", 192, 24, 16, EVP_CTX_SZX2, AES_OSSL_192_EKey_ExpandX2_ecb, AES_OSSL_192_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_192_ECB_EncryptX2, AES_OSSL_192_ECB_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES192x2-CBC", 192, 24, 16, EVP_CTX_SZX2, AES_OSSL_192_EKey_ExpandX2_ecb, AES_OSSL_192_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_192_CBC_EncryptX2, AES_OSSL_192_CBC_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES192x2-CTR", 192, 24,  1, EVP_CTX_SZX2, AES_OSSL_192_EKey_ExpandX2_ecb, AES_OSSL_192_EKey_ExpandX2_ecb,
						AES_Gen_CTR_Prep, AES_OSSL_192_CTR_CryptX2, AES_OSSL_192_CTR_CryptX2, AES_OSSL_ReleaseX2},
				{"AES256x2-ECB", 256, 28, 16, EVP_CTX_SZX2, AES_OSSL_256_EKey_ExpandX2_ecb, AES_OSSL_256_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_256_ECB_EncryptX2, AES_OSSL_256_ECB_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES256x2-CBC", 256, 28, 16, EVP_CTX_SZX2, AES_OSSL_256_EKey_ExpandX2_ecb, AES_OSSL_256_DKey_ExpandX2_ecb,
							NULL, AES_OSSL_256_CBC_EncryptX2, AES_OSSL_256_CBC_DecryptX2, AES_OSSL_ReleaseX2},
				{"AES256x2-CTR", 256, 28,  1, EVP_CTX_SZX2, AES_OSSL_256_EKey_ExpandX2_ecb, AES_OSSL_256_EKey_ExpandX2_ecb,
						AES_Gen_CTR_Prep, AES_OSSL_256_CTR_CryptX2, AES_OSSL_256_CTR_CryptX2, AES_OSSL_ReleaseX2},
				{NULL, /* ... */}
};
