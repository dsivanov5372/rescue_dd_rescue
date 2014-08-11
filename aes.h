/** aes.h
 *
 * Abstract types for the AES family
 */

#ifndef _AES_H
#define _AES_H

#include <sys/types.h>

#define AES_128_ROUNDS 10
#define AES_192_ROUNDS 12
#define AES_256_ROUNDS 14

#if 0
typedef struct _aes_rkeys {
	unsigned int rounds;
	unsigned char *rkeys;	/* 16*rounds+1 */
}
#endif


typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;

/* Both Enc and Dec */
typedef void (AES_Key_Setup_fn)(const uchar* usrkey, uchar* rkeys, uint rounds); 
typedef void (AES_Crypt_Blk_fn)(const uchar* rkeys, uint rounds, 
				const uchar* input, uchar* output);
typedef void (AES_Crypt_ECB_fn)(const uchar* rkeys, uint rounds,
				const uchar* input, uchar* output,
				ssize_t len);
typedef void (AES_Crypt_CBC_fn)(const uchar* rkeys, uint rounds,
				      uchar iv[16],
				const uchar* input, uchar* output,
				ssize_t len);
typedef void (AES_Crypt_CTR_Prep_fn)(const uchar nonce[16], uchar ctr[16], uint ival);
typedef void (AES_Crypt_CTR_fn)(const uchar* rkeys, uint rounds,
				      uchar ctr[16],
				const uchar* input, uchar* output,
				ssize_t len);


typedef struct _aes_coll_desc {
	const char* name;
	uint keylen;	/* bits */
	uint rounds;
	uint ctx_size;	/* Size for all round keys (and potentially addtl context in bytes) */
	/* blocksize is always 16 as is rkey size */
	AES_Key_Setup_fn *enc_key_setup, *dec_key_setup;
	AES_Crypt_Blk_fn *enc_block, *dec_block;
	AES_Crypt_ECB_fn *enc_ecb, *dec_ecb;
	AES_Crypt_CBC_fn *enc_cbc, *dec_cbc;
	AES_Crypt_CTR_Prep_fn *ctr_prep;
	AES_Crypt_CTR_fn *crypt_ctr;
} aes_coll_desc_t;

typedef struct _aes_desc {
	const char *name;
	uint keylen;	/* bits */
	uint rounds;	/* bits */
	uint ctx_size;	/* Size for all round keys (and potentially addtl context in bytes) */
	AES_Key_Setup_fn *enc_key_setup, *dec_key_setup;
	AES_Crypt_CTR_Prep_fn *iv_prep;
	AES_Crypt_CBC_fn *encrypt, *decrypt;
} aes_desc_t;


/* Generic functions */
void AES_Gen_ECB_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     const uchar *input, uchar *output,
		     ssize_t len);
void AES_Gen_ECB_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     const uchar *input, uchar *output,
		     ssize_t len);
void AES_Gen_CBC_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar iv[16],
		     const uchar *input, uchar *output,
		     ssize_t len);
void AES_Gen_CBC_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar iv[16],
		     const uchar *input, uchar *output,
		     ssize_t len);
void AES_Gen_CTR_Prep(const uchar nonce[16], uchar ctr[16], uint ival);
void AES_Gen_CTR_Crypt(AES_Crypt_Blk_fn *cryptfn,
			const uchar *rkeys, uint rounds,
			uchar ctr[16],
			const uchar *input, uchar *output,
			ssize_t len);

#endif
