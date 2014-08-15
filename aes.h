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

#define PAD_ZERO 0
#define PAD_ALWAYS 1
#define PAD_ASNEEDED 2

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;

/* Both Enc and Dec */
typedef void (AES_Key_Setup_fn)(const uchar* usrkey, uchar* rkeys, uint rounds); 
typedef void (AES_Crypt_IV_Prep_fn)(const uchar nonce[16], uchar ctr[16], unsigned long long ival);
typedef void (AES_Crypt_Blk_fn)(const uchar* rkeys, uint rounds, 
				const uchar* input, uchar* output);
typedef int  (AES_Crypt_IV_fn) (const uchar* rkeys, uint rounds,
				      uchar *iv /* [16] */, uint pad,
				const uchar* input, uchar* output,
				ssize_t len, ssize_t *olen);
typedef void (AES_Key_Release_fn)(uchar* rkeys, uint rounds);


typedef struct _aes_desc {
	const char *name;
	uint keylen;	/* bits */
	uint rounds;
	uint blksize;	/* bytes */
	uint ctx_size;	/* Size for all round keys (and potentially addtl context in bytes) */
	AES_Key_Setup_fn *enc_key_setup, *dec_key_setup;
	AES_Crypt_IV_Prep_fn *iv_prep;
	AES_Crypt_IV_fn *encrypt, *decrypt;
	AES_Key_Release_fn *release;
} aes_desc_t;


/* Generic functions */
int  AES_Gen_ECB_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /* uchar *iv unused ,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
int  AES_Gen_ECB_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /* char *iv unused ,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
int  AES_Gen_CBC_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
int  AES_Gen_CBC_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen);
int  AES_Gen_CTR_Crypt(AES_Crypt_Blk_fn *cryptfn,
			const uchar *rkeys, uint rounds,
			uchar *ctr, /* uint pad unused ,*/
			const uchar *input, uchar *output,
			ssize_t len/*, ssize_t *olen unused */);
void AES_Gen_CTR_Prep(const uchar nonce[16], uchar ctr[16], unsigned long long ival);
void AES_Gen_Release(uchar *rkeys, uint rounds);
int  dec_fix_olen_pad(ssize_t *olen, uint pad, const uchar *output);
#endif
