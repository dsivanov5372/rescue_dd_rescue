#ifndef _AES_C_H
#define _AES_C_H

#include "aes.h"
#include <stdio.h>

/* aes.c */
#if 0
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

int rijndaelKeySetupEnc(u32 rk[/*4*(Nr + 1)*/], const u8 cipherKey[], int keyBits, int rounds);
int rijndaelKeySetupDec(u32 rk[/*4*(Nr + 1)*/], const u8 cipherKey[], int keyBits, int rounds);
void rijndaelEncrypt(const u32 rk[/*4*(Nr + 1)*/], int Nr, const u8 pt[16], u8 ct[16]);
void rijndaelDecrypt(const u32 rk[/*4*(Nr + 1)*/], int Nr, const u8 ct[16], u8 pt[16]);

void rijndaelKeySetupEncPF();
void rijndaelKeySetupDecPF();
void rijndaelEncryptPF();
void rijndaelDecryptPF();

void aes_c_encrypt_ecb(const unsigned char *plainText, unsigned char *cipherText, 
			ssize_t len, const u32 *ekey, int rounds);
void aes_c_decrypt_ecb(const unsigned char *cipherText, unsigned char *plainText,
			ssize_t len, const u32 *dkey, int rounds);
void aes_c_encrypt_cbc(const unsigned char *plainText, unsigned char *cipherText, const unsigned char* iv, 
			ssize_t len, const u32 *ekey, int rounds);
void aes_c_decrypt_cbc(const unsigned char *cipherText, unsigned char *plainText, const unsigned char* iv, 
			ssize_t len, const u32 *ekey, int rounds);
void aes_c_crypt_ctr(const unsigned char* plainText, unsigned char *cipherText, const unsigned char *iv,
		     unsigned int *ctr, size_t len, const u32 *ekey, int rounds);
#endif

#define DECL_KEYSETUP(MODE, BITS)	\
void AES_C_KeySetup_##BITS##_##MODE(const uchar *usrkey, uchar *rkeys, uint rounds)
DECL_KEYSETUP(Enc, 128);
DECL_KEYSETUP(Dec, 128);
DECL_KEYSETUP(Enc, 192);
DECL_KEYSETUP(Dec, 192);
DECL_KEYSETUP(Enc, 256);
DECL_KEYSETUP(Dec, 256);
#undef DECL_KEYSETUP

void AES_C_Encrypt_Blk(const uchar* rkeys, uint rounds, const uchar in[16], uchar out[16]);
void AES_C_Decrypt_Blk(const uchar* rkeys, uint rounds, const uchar in[16], uchar out[16]);
void AES_C_ECB_Encrypt(const uchar* rkeys, uint rounds, uchar *iv,  const uchar *in, uchar *out, ssize_t len);
void AES_C_ECB_Decrypt(const uchar* rkeys, uint rounds, uchar *iv,  const uchar *in, uchar *out, ssize_t len);
void AES_C_CBC_Encrypt(const uchar* rkeys, uint rounds, uchar *iv,  const uchar *in, uchar *out, ssize_t len);
void AES_C_CBC_Decrypt(const uchar* rkeys, uint rounds, uchar *iv,  const uchar *in, uchar *out, ssize_t len);
void AES_C_CTR_Crypt  (const uchar* rkeys, uint rounds, uchar *ctr, const uchar *in, uchar *out, ssize_t len);


#endif
