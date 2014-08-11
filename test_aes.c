#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include "secmem.h"
#include "aes.h"

sec_fields *crypto;

void _printblk(unsigned char* blk, ssize_t ln)
{
	int i;
	for (i = 0; i < ln; ++i)
		printf("%02x ", blk[i]);
	printf("\n");
}

#define printblk(blk, ln)		\
	if (dbg)			\
		_printblk(blk, ln);	\
	else				\
		printf("\n")


void fillrand(unsigned char* bf, ssize_t ln)
{
	while(ln > 0) {
		*(int*)bf = rand();
		bf+= 4;
		ln -=4;
	}
}

void fillval(unsigned char* bf, ssize_t ln, unsigned int val)
{
	while(ln > 0) {
		*(int*)bf = val;
		bf+= 4;
		ln -=4;
	}
}

#ifdef HAVE_AESNI
#include "aesni.h"
#endif

#include "aes_c.h"
#include "aes_ossl.h"

/* Defaults */

#define REP 5000000
#define LN 288
#ifndef SHIFT
# define SHIFT 5
#endif

/* TIMING */
#define BENCH(routine, rep)		\
	fflush(stdout);			\
	gettimeofday(&t1, NULL);	\
	for (i = 0; i < rep; ++i) {	\
		routine; }		\
	gettimeofday(&t2, NULL);	\
	tdiff = t2.tv_sec-t1.tv_sec + 0.000001*(t2.tv_usec-t1.tv_usec);	\
	printf("(%6.3fGB/s) ", (double)rep*LN/(1e9*tdiff))


void setup_iv(aes_desc_t *alg, uchar iv[16])
{
	if (alg->iv_prep)
		alg->iv_prep((const uchar*)"Halleluja 12345", iv, 1);
	else
		memcpy(iv, "Halleluja 12345", 16);
}

aes_desc_t *findalg(aes_desc_t* list, const char* nm)
{
	aes_desc_t* alg = list;
	while (alg) {
		if (!strcmp(alg->name, nm))
			return alg;
		alg += 1;
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	int rep = REP;
	unsigned char in[LN], in2[LN], out[LN], vfy[LN], out2[LN];
	unsigned char *key = (unsigned char*)"Test Key_123 is long enough even for AES-256";
        struct timeval t1, t2;
	double tdiff; int i;
	int dbg = 0;
	char* testalg;
	crypto = secmem_init();
	if (argc > 1 && !strcmp("-d", argv[1])) {
		dbg = 1; --argc; ++argv;
	}
	if (argc > 1)
		testalg = argv[1];
	else
		testalg = "AES128-CTR";
	if (argc > 2)
		rep = atol(argv[2]);
	if (argc > 3)
		srand(atol(argv[3]));
	else
		srand(time(NULL));
	if (argc > 4)
		fillval(in, LN, atol(argv[4]));
	else
		fillrand(in, LN);


	printf("AES tests/benchmark\n");
	uchar iv[16];
	aes_desc_t *alg = NULL;

#ifdef HAVE_AESNI
	printf("AESNI:\n");
	alg = findalg(AESNI_Methods, testalg);
	if (alg) {
		printf("%s (%i, %i, %i)\n", alg->name, alg->keylen, alg->rounds, alg->ctx_size);
		printf("Key setup: ");
		uchar *rkeys = (uchar*)malloc(alg->ctx_size);
		BENCH(alg->enc_key_setup(key, rkeys, alg->rounds), rep);
		printf("\nEncrypt  : ");
		BENCH(setup_iv(alg, iv); alg->encrypt(rkeys, alg->rounds, iv, in, out, LN), rep/2);
		printf("\nKey setup: ");
		BENCH(alg->dec_key_setup(key, rkeys, alg->rounds), rep);
		printf("\nDecrypt  : ");
		BENCH(setup_iv(alg, iv); alg->decrypt(rkeys, alg->rounds, iv, out, vfy, LN), rep/2);
		if (memcmp(vfy, in, LN))
			abort();
		free(rkeys);
	}
#endif
	printf("\nAES_C:\n");
	alg = findalg(AES_C_Methods, testalg);
	if (alg) {
		printf("%s (%i, %i, %i)\n", alg->name, alg->keylen, alg->rounds, alg->ctx_size);
		printf("Key setup: ");
		uchar *rkeys = (uchar*)malloc(alg->ctx_size);
		BENCH(alg->enc_key_setup(key, rkeys, alg->rounds), rep);
		printf("\nEncrypt  : ");
		BENCH(setup_iv(alg, iv); alg->encrypt(rkeys, alg->rounds, iv, in, out2, LN), rep/2);
#ifdef HAVE_AESNI
		if (memcmp(out, out2, LN))
			abort();
#endif
		printf("\nKey setup: ");
		BENCH(alg->dec_key_setup(key, rkeys, alg->rounds), rep);
		printf("\nDecrypt  : ");
		BENCH(setup_iv(alg, iv); alg->decrypt(rkeys, alg->rounds, iv, out2, vfy, LN), rep/2);
		if (memcmp(vfy, in, LN))
			abort();
		free(rkeys);
	}

	printf("\nOpenSSL ");
	//OPENSSL_init();
	alg = findalg(AES_OSSL_Methods, testalg);
	if (alg) {
		printf("%s (%i, %i, %i)\n", alg->name, alg->keylen, alg->rounds, alg->ctx_size);
		printf("Key setup: ");
		uchar *rkeys = (uchar*)malloc(alg->ctx_size);
		BENCH(alg->enc_key_setup(key, rkeys, alg->rounds), rep);
		printf("\nEncrypt  : ");
		BENCH(setup_iv(alg, iv); alg->encrypt(rkeys, alg->rounds, iv, in, out, LN), rep/2);
		if (memcmp(out, out2, LN))
			abort();
		printf("\nKey setup: ");
		BENCH(alg->dec_key_setup(key, rkeys, alg->rounds), rep);
		printf("\nDecrypt  : ");
		BENCH(setup_iv(alg, iv); alg->decrypt(rkeys, alg->rounds, iv, out, vfy, LN), rep/2);
		if (memcmp(vfy, in, LN))
			abort();
		free(rkeys);
	}

#if 0
	BENCH(AES_set_encrypt_key(key, 128, &aesenc), rep);
	printf("\nCipher: ");
	BENCH(AES_encrypt_ecb(in, out2, LN, &aesenc), rep/2);
	printblk(out2, LN);
#ifdef HAVE_AESNI
	if (memcmp(out, out2, LN))
		return 2;
#endif

	BENCH(AES_set_decrypt_key(key, 128, &aesdec), rep);
	printf("\nDeciph: ");
	BENCH(AES_decrypt_ecb(out2, vfy, LN, &aesdec), rep/2);
	printblk(vfy, LN);

	if (memcmp(in, vfy, LN))
		return 3;
	
	/* TODO: Use OpenSSL EVP interface to enable accelerated versions */
	printf("SSL EVP ");
	//OpenSSL_add_all_algorithms();
	EVP_CIPHER_CTX_init(&evpcctx);
	BENCH(EVP_EncryptInit_ex(&evpcctx, EVP_aes_128_ecb(), NULL, key, NULL), rep);
	EVP_CIPHER_CTX_set_padding(&evpcctx, 0);
	printf("\nCipher: ");
	int olen = LN; //int flen = 0;
	BENCH(EVP_EncryptUpdate(&evpcctx, out, &olen, in, LN) /*; EVP_EncryptFinal(&evpctx, out+olen, &flen)*/, rep/2);
	printblk(out, LN);
	if (memcmp(out, out2, LN))
		return 2;
	//EVP_CIPHER_CTX_cleanup(&evpctx);
	//EVP_CIPHER_CTX_init(&evpctx);
	BENCH(EVP_DecryptInit_ex(&evpdctx, EVP_aes_128_ecb(), NULL, key, NULL), rep);
	printf("\nDeciph: ");
	//olen = LN; flen = 0;
#if 0
	EVP_CIPHER_CTX ctx2 = evpctx;
	EVP_DecryptUpdate(&evpctx, vfy, &olen, out, LN);
	/*
	if (memcmp(&ctx2, &evpctx, sizeof(ctx2)))
		abort();
	 */
	if (memcmp(out, out2, LN))
		abort();
#endif
	BENCH(evpdctx.final_used = 0; EVP_DecryptUpdate(&evpdctx, vfy, &olen, out, LN)/*; EVP_DecryptFinal(&evpctx, vfy+olen, &flen)*/, rep/2);
	printblk(vfy, LN);
	if (memcmp(in, vfy, LN))
		return 3;

	/* AES (C) */

	u32 erk[19*4], drk[19*4];
	printf("AES (C) ");
	rijndaelKeySetupEncPF();
	BENCH(rijndaelKeySetupEnc(erk, key, 128, 10), rep);
	printf("\nCipher: ");
	rijndaelEncryptPF();
	BENCH(aes_c_encrypt_ecb( in, out, LN, erk, 10), rep/2);
	printblk(out, LN);
	if (memcmp(out, out2, LN))
		return 4;

	rijndaelKeySetupDecPF();
	BENCH(rijndaelKeySetupDec(drk, key, 128, 10), rep);
	printf("\nDeciph: ");
	rijndaelDecryptPF();
	BENCH(aes_c_decrypt_ecb(out, vfy, LN, drk, 10), rep/2);
	printblk(vfy, LN);

	if (memcmp(in, vfy, LN))
		return 5;

	/* In real code, we would call the prefetch again after being done
	 * AND overwrite the key and roundkeys in memory */

	printf("==> CBC\n");
	const unsigned char* iv  = (const unsigned char*)"This is the IV vector ...";
	unsigned char iv2[16];
#ifdef HAVE_AESNI
	printf("AESNI");
	printf("\nCipher: ");
	BENCH(AESNI_CBC_encrypt( in, out, iv, LN, ekeys, 10), rep/2);
	printblk(out, LN);
	printf("Deciph: ");
	BENCH(AESNI_CBC_decrypt(out, vfy, iv, LN, dkeys, 10), rep/2);
	printblk(vfy, LN);
	
	if (memcmp(in, vfy, LN))
		return 7;

#endif
	printf("OpenSSL");
	printf("\nCipher: ");
	BENCH(memcpy(iv2, iv, 16); AES_cbc_encrypt(in, out2, LN, &aesenc, iv2, AES_ENCRYPT), rep/2);
	printblk(out2, LN);
#ifdef HAVE_AESNI
	if (memcmp(out, out2, LN))
		return 8;
#endif
	printf("Deciph: ");
	BENCH(memcpy(iv2, iv, 16); AES_cbc_encrypt(out2, vfy, LN, &aesdec, iv2, AES_DECRYPT), rep/2);
	printblk(vfy, LN);
	if (memcmp(in, vfy, LN))
		return 9;

	printf("SSL EVP");
	EVP_EncryptInit_ex(&evpcctx, EVP_aes_128_cbc(), NULL, key, iv);
	printf("\nCipher: ");
	BENCH(memcpy(evpcctx.iv, evpcctx.oiv, 16); EVP_EncryptUpdate(&evpcctx, out, &olen, in, LN) /*; EVP_EncryptFinal(&evpctx, out+olen, &flen)*/, rep/2);
	printblk(out, LN);
	if (memcmp(out, out2, LN))
		return 8;
	EVP_DecryptInit_ex(&evpdctx, EVP_aes_128_cbc(), NULL, key, iv);
	printf("Deciph: ");
	BENCH(evpdctx.final_used = 0; memcpy(evpdctx.iv, evpdctx.oiv, 16); EVP_DecryptUpdate(&evpdctx, vfy, &olen, out, LN)/*; EVP_DecryptFinal(&evpctx, vfy+olen, &flen)*/, rep/2);
	printblk(vfy, LN);
	if (memcmp(in, vfy, LN))
		return 9;

	printf("AES (C) ");
	printf("\nCipher: ");
	rijndaelEncryptPF();
	BENCH(aes_c_encrypt_cbc( in, out, iv, LN, erk, 10), rep/2);
	printblk(out, LN);
	if (memcmp(out, out2, LN))
		return 10;
	printf("Deciph: ");
	rijndaelDecryptPF();
	BENCH(aes_c_decrypt_cbc(out, vfy, iv, LN, drk, 10), rep/2);
	printblk(vfy, LN);
	
	if (memcmp(in, vfy, LN))
		return 11;


	printf("==> CTR\n");
#ifdef HAVE_AESNI
	printf("AESNI");
	unsigned char cblk[16];
	printf("\nCipOld: ");
	BENCH(AESNI_CTR_prep(iv, cblk, 0); AESNI_CTR_crypt_old( in, out, cblk, LN, ekeys, 10), rep/2);
	printf("\nCipher: ");
	BENCH(AESNI_CTR_prep(iv, cblk, 0); AESNI_CTR_crypt( in, out, cblk, LN, ekeys, 10), rep/2);
	//BENCH(AESNI_CTR_prep_2(iv+4, iv, cblk, 0); AESNI_CTR_crypt( in, out, cblk, LN, ekeys, 10), rep/2);
	printblk(out, LN);
	printf("Deciph: ");
	BENCH(AESNI_CTR_prep(iv, cblk, 0); AESNI_CTR_crypt(out, vfy, cblk, LN, ekeys, 10), rep/2);
	printblk(vfy, LN);
	
	if (memcmp(in, vfy, LN))
		return 12;

#endif
	unsigned char ecntbf[16];
	memset(ecntbf, 0, 16);
	printf("OpenSSL");
	printf("\nCipher: ");
	unsigned int start = 0;
	BENCH(start = 0; memcpy(iv2, iv, 12); memset(iv2+12, 0, 4); AES_ctr128_encrypt(in, out2, LN, &aesenc, iv2, ecntbf, &start), rep/2);
	printblk(out2, LN);
#if defined(HAVE_AESNI) && !defined(SKIP_CTR_CMP)
	if (memcmp(out, out2, LN))
		return 13;
#endif
	printf("Deciph: ");
	BENCH(start = 0; memcpy(iv2, iv, 12); memset(iv2+12, 0, 4); AES_ctr128_encrypt(in, out2, LN, &aesenc, iv2, ecntbf, &start), rep/2);
	printblk(vfy, LN);
	if (memcmp(in, vfy, LN))
		return 14;

	printf("SSL EVP");
	start = 0;
	memcpy(iv2, iv, 12); memset(iv2+12, 0, 4);
	EVP_EncryptInit_ex(&evpcctx, EVP_aes_128_ctr(), NULL, key, iv2);
	printf("\nCipher: ");
	olen = LN; //int flen = 0;
	BENCH(memset(evpcctx.iv+12, 0, 4); EVP_EncryptUpdate(&evpcctx, out, &olen, in, LN) /*; EVP_EncryptFinal(&evpctx, out+olen, &flen)*/, rep/2);
	printblk(out, LN);
	if (memcmp(out, out2, LN))
		return 13;
	EVP_DecryptInit_ex(&evpdctx, EVP_aes_128_ctr(), NULL, key, iv2);
	printf("Deciph: ");
	BENCH(evpdctx.final_used = 0; memset(evpdctx.iv+12, 0, 4); EVP_DecryptUpdate(&evpdctx, vfy, &olen, out, LN)/*; EVP_DecryptFinal(&evpctx, vfy+olen, &flen)*/, rep/2);
	printblk(vfy, LN);
	if (memcmp(in, vfy, LN))
		return 14;

	printf("AES (C) ");
	printf("\nCihper: ");
	unsigned int ctr = 0;
	BENCH(ctr = 0; aes_c_crypt_ctr(in, out, iv, &ctr, LN, erk, 10), rep/2);
	printblk(out2, LN);
	if (memcmp(out, out2, LN))
		return 15;
	printf("Deciph: ");
	BENCH(ctr = 0; aes_c_crypt_ctr(vfy, out, iv, &ctr, LN, erk, 10), rep/2);
	printblk(vfy, LN);
	if (memcmp(in, vfy, LN))
		return 16;

	/* Extended round variants */
	printf("==> ECB (128/12)\n");
#ifdef HAVE_AESNI
	printf("AESNI : ");
	BENCH(AESNI_128_EKey_Expansion_r(key, ekeys, 12), rep);
	printblk(in, LN);
	printf("Cipher: ");
	BENCH(AESNI_ECB_encrypt( in, out, LN, ekeys, 12), rep/2);
	printblk(out, LN);
	BENCH(AESNI_128_DKey_Expansion_r(key, dkeys, 12), rep);
	printf("\nDeciph: ");
	BENCH(AESNI_ECB_decrypt(out, vfy, LN, dkeys, 12), rep/2);
	printblk(vfy, LN);
	
	if (memcmp(in, vfy, LN))
		return 17;
#endif

	printf("AES (C) ");
	rijndaelKeySetupEncPF();
	BENCH(rijndaelKeySetupEnc(erk, key, 128, 12), rep);
	printf("\nCipher: ");
	rijndaelEncryptPF();
	BENCH(aes_c_encrypt_ecb( in, out2, LN, erk, 12), rep/2);
	printblk(out, LN);
#if defined(HAVE_AESNI) && !defined(SKIP_AES12812_CMP)
	if (memcmp(out, out2, LN))
		return 18;
#endif

	rijndaelKeySetupDecPF();
	BENCH(rijndaelKeySetupDec(drk, key, 128, 12), rep);
	printf("\nDeciph: ");
	rijndaelDecryptPF();
	BENCH(aes_c_decrypt_ecb(out2, vfy, LN, drk, 12), rep/2);
	printblk(vfy, LN);

	if (memcmp(in, vfy, LN))
		return 19;

	/* AES-192 */
	printf("==> ECB 192\n");
#ifdef HAVE_AESNI
	printf("AESNI : ");
	BENCH(AESNI_192_EKey_Expansion_r(key, ekeys, 12), rep);
	printblk(in, LN);
	printf("Cipher: ");
	BENCH(AESNI_ECB_encrypt( in, out, LN, ekeys, 12), rep/2);
	printblk(out, LN);
	BENCH(AESNI_192_DKey_Expansion_r(key, dkeys, 12), rep);
	printf("\nDeciph: ");
	BENCH(AESNI_ECB_decrypt(out, vfy, LN, dkeys, 12), rep/2);
	printblk(vfy, LN);
	
	if (memcmp(in, vfy, LN))
		return 20;
#endif

	printf("AES (C) ");
	rijndaelKeySetupEncPF();
	BENCH(rijndaelKeySetupEnc(erk, key, 192, 12), rep);
	printf("\nCipher: ");
	rijndaelEncryptPF();
	BENCH(aes_c_encrypt_ecb( in, out2, LN, erk, 12), rep/2);
	printblk(out, LN);
#if defined(HAVE_AESNI)
	if (memcmp(out, out2, LN))
		return 21;
#endif

	rijndaelKeySetupDecPF();
	BENCH(rijndaelKeySetupDec(drk, key, 192, 12), rep);
	printf("\nDeciph: ");
	rijndaelDecryptPF();
	BENCH(aes_c_decrypt_ecb(out2, vfy, LN, drk, 12), rep/2);
	printblk(vfy, LN);

	if (memcmp(in, vfy, LN))
		return 22;

	/* AES-192 */
	printf("==> ECB 192(15)\n");
#ifdef HAVE_AESNI
	printf("AESNI : ");
	BENCH(AESNI_192_EKey_Expansion_r(key, ekeys, 15), rep);
	printblk(in, LN);
	printf("Cipher: ");
	BENCH(AESNI_ECB_encrypt( in, out, LN, ekeys, 15), rep/2);
	printblk(out, LN);
	BENCH(AESNI_192_DKey_Expansion_r(key, dkeys, 15), rep);
	printf("\nDeciph: ");
	BENCH(AESNI_ECB_decrypt(out, vfy, LN, dkeys, 15), rep/2);
	printblk(vfy, LN);
	
	if (memcmp(in, vfy, LN))
		return 23;
#endif

	printf("AES (C) ");
	rijndaelKeySetupEncPF();
	BENCH(rijndaelKeySetupEnc(erk, key, 192, 15), rep);
	printf("\nCipher: ");
	rijndaelEncryptPF();
	BENCH(aes_c_encrypt_ecb( in, out2, LN, erk, 15), rep/2);
	printblk(out, LN);
#if defined(HAVE_AESNI) && !defined(SKIP_AES19215_CMP)
	if (memcmp(out, out2, LN))
		return 24;
#endif

	rijndaelKeySetupDecPF();
	BENCH(rijndaelKeySetupDec(drk, key, 192, 15), rep);
	printf("\nDeciph: ");
	rijndaelDecryptPF();
	BENCH(aes_c_decrypt_ecb(out2, vfy, LN, drk, 15), rep/2);
	printblk(vfy, LN);
#if !defined(SKIP_AES19215_CMP)
	if (memcmp(in, vfy, LN))
		return 25;
#endif

	/* AES-256 */
	printf("==> ECB 256\n");
#ifdef HAVE_AESNI
	printf("AESNI : ");
	BENCH(AESNI_256_EKey_Expansion_r(key, ekeys, 14), rep);
	printblk(in, LN);
	printf("Cipher: ");
	BENCH(AESNI_ECB_encrypt( in, out, LN, ekeys, 14), rep/2);
	printblk(out, LN);
	BENCH(AESNI_256_DKey_Expansion_r(key, dkeys, 14), rep);
	printf("\nDeciph: ");
	BENCH(AESNI_ECB_decrypt(out, vfy, LN, dkeys, 14), rep/2);
	printblk(vfy, LN);
	
	if (memcmp(in, vfy, LN))
		return 26;
#endif

	printf("AES (C) ");
	rijndaelKeySetupEncPF();
	BENCH(rijndaelKeySetupEnc(erk, key, 256, 14), rep);
	printf("\nCipher: ");
	rijndaelEncryptPF();
	BENCH(aes_c_encrypt_ecb( in, out2, LN, erk, 14), rep/2);
	printblk(out, LN);
#if defined(HAVE_AESNI)
	if (memcmp(out, out2, LN))
		return 27;
#endif

	rijndaelKeySetupDecPF();
	BENCH(rijndaelKeySetupDec(drk, key, 256, 14), rep);
	printf("\nDeciph: ");
	rijndaelDecryptPF();
	BENCH(aes_c_decrypt_ecb(out2, vfy, LN, drk, 14), rep/2);
	printblk(vfy, LN);

	if (memcmp(in, vfy, LN))
		return 28;

	/* AES-192 */
	printf("==> ECB 256(18)\n");
#ifdef HAVE_AESNI
	printf("AESNI : ");
	BENCH(AESNI_256_EKey_Expansion_r(key, ekeys, 18), rep);
	printblk(in, LN);
	printf("Cipher: ");
	BENCH(AESNI_ECB_encrypt( in, out, LN, ekeys, 18), rep/2);
	printblk(out, LN);
	BENCH(AESNI_256_DKey_Expansion_r(key, dkeys, 18), rep);
	printf("\nDeciph: ");
	BENCH(AESNI_ECB_decrypt(out, vfy, LN, dkeys, 18), rep/2);
	printblk(vfy, LN);
	
	if (memcmp(in, vfy, LN))
		return 29;
#endif

	printf("AES (C) ");
	rijndaelKeySetupEncPF();
	BENCH(rijndaelKeySetupEnc(erk, key, 256, 18), rep);
	printf("\nCipher: ");
	rijndaelEncryptPF();
	BENCH(aes_c_encrypt_ecb( in, out2, LN, erk, 18), rep/2);
	printblk(out, LN);
#if defined(HAVE_AESNI)
	if (memcmp(out, out2, LN))
		return 30;
#endif

	rijndaelKeySetupDecPF();
	BENCH(rijndaelKeySetupDec(drk, key, 256, 18), rep);
	printf("\nDeciph: ");
	rijndaelDecryptPF();
	BENCH(aes_c_decrypt_ecb(out2, vfy, LN, drk, 18), rep/2);
	printblk(vfy, LN);

	if (memcmp(in, vfy, LN))
		return 31;

	EVP_CIPHER_CTX_cleanup(&evpcctx);
	EVP_CIPHER_CTX_cleanup(&evpdctx);
#endif
	secmem_release(crypto);
	return 0;
}

