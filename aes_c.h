#ifndef _AES_H
#define _AES_H

#include <stdio.h>

/* aes.c */
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
