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
#define BENCH(_routine, _rep, _ln)	\
	fflush(stdout);			\
	_routine;			\
	gettimeofday(&t1, NULL);	\
	for (i = 0; i < _rep; ++i) {	\
		_routine; 		\
		asm("":::"memory");	\
	}				\
	gettimeofday(&t2, NULL);	\
	tdiff = t2.tv_sec-t1.tv_sec + 0.000001*(t2.tv_usec-t1.tv_usec);	\
	printf("%6.3fs (%6.0fMB/s) ", tdiff, (double)(_rep)*(_ln)/(1e6*tdiff))


void setup_iv(aes_desc_t *alg, uchar iv[16])
{
	if (alg->iv_prep)
		alg->iv_prep((const uchar*)"Halleluja 12345", iv, 0);
	else
		memcpy(iv, "Halleluja 12345", 16);
}

aes_desc_t *findalg(aes_desc_t* list, const char* nm)
{
	aes_desc_t* alg = list;
	while (alg->name) {
		if (!strcmp(alg->name, nm))
			return alg;
		alg += 1;
	}
	return NULL;
}

int compare(uchar* p1, uchar* p2, size_t ln, const char* msg)
{
	uint i;
	for (i = 0; i < ln; ++i) 
		if (p1[i] != p2[i]) {
			printf("Miscompare (%s) @ %i: %02x <-> %02x",
				msg, i, p1[i], p2[i]);
			return 1;
		}
	return 0;
}


int main(int argc, char *argv[])
{
	int rep = REP;
	unsigned char in[LN], in2[LN], out[LN], vfy[LN], out2[LN];
	unsigned char *key = (unsigned char*)"Test Key_123 is long enough even for AES-256";
        struct timeval t1, t2;
	double tdiff; int i;
	int dbg = 0;
	int err = 0;
	int tested = 0;
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


	printf("AES tests/benchmark");
	uchar iv[16];
	aes_desc_t *alg = NULL;

#ifdef HAVE_AESNI
	alg = findalg(AESNI_Methods, testalg);
	if (alg) {
		++tested;
		printf("\nAESNI %s (%i, %i, %i)\n", alg->name, alg->keylen, alg->rounds, alg->ctx_size);
		printf("Key setup: ");
		/* TODO: Use secmem ... */
		uchar *rkeys = (uchar*)malloc(alg->ctx_size);
		BENCH(alg->enc_key_setup(key, rkeys, alg->rounds), rep, 16*(1+alg->rounds));
		printf("\nEncrypt  : ");
		BENCH(setup_iv(alg, iv); alg->encrypt(rkeys, alg->rounds, iv, in, out, LN), rep/2+1, LN);
		printf("\nKey setup: ");
		BENCH(alg->dec_key_setup(key, rkeys, alg->rounds), rep, 16*(1+alg->rounds));
		printf("\nDecrypt  : ");
		memset(vfy, 0, LN);
		BENCH(setup_iv(alg, iv); alg->decrypt(rkeys, alg->rounds, iv, out, vfy, LN), rep/2+1, LN);
		err += compare(vfy, in, LN, "AESNI plain");
		if (alg->release)
			alg->release(rkeys, alg->rounds);
		free(rkeys);
	}
#endif
	alg = findalg(AES_C_Methods, testalg);
	if (alg) {
		++tested;
		printf("\nAES_C %s (%i, %i, %i)\n", alg->name, alg->keylen, alg->rounds, alg->ctx_size);
		printf("Key setup: ");
		uchar *rkeys = (uchar*)malloc(alg->ctx_size);
		BENCH(alg->enc_key_setup(key, rkeys, alg->rounds), rep, 16*(1+alg->rounds));
		printf("\nEncrypt  : ");
		BENCH(setup_iv(alg, iv); alg->encrypt(rkeys, alg->rounds, iv, in, out2, LN), rep/2+1, LN);
#ifdef HAVE_AESNI
		err += compare(out, out2, LN, "AESNI vs AES_C");;
#endif
		printf("\nKey setup: ");
		BENCH(alg->dec_key_setup(key, rkeys, alg->rounds), rep, 16*(1+alg->rounds));
		printf("\nDecrypt  : ");
		memset(vfy, 0, LN);
		BENCH(setup_iv(alg, iv); alg->decrypt(rkeys, alg->rounds, iv, out2, vfy, LN), rep/2+1, LN);
		err += compare(vfy, in, LN, "AES_C plain");
		if (alg->release)
			alg->release(rkeys, alg->rounds);
		free(rkeys);
	}

	//OPENSSL_init();
	alg = findalg(AES_OSSL_Methods, testalg);
	if (alg) {
		++tested;
		printf("\nOpenSSL %s (%i, %i, %i)\n", alg->name, alg->keylen, alg->rounds, alg->ctx_size);
		printf("Key setup: ");
		uchar *rkeys = (uchar*)malloc(alg->ctx_size);
		BENCH(alg->enc_key_setup(key, rkeys, alg->rounds); alg->release(rkeys, alg->rounds), rep, 16*(1+alg->rounds));
		alg->enc_key_setup(key, rkeys, alg->rounds);
 		printf("\nEncrypt  : ");
		BENCH(setup_iv(alg, iv); alg->encrypt(rkeys, alg->rounds, iv, in, out, LN), rep/2+1, LN);
		err += compare(out2, out, LN, "AES_C vs OSSL");
		if (alg->release)
			alg->release(rkeys, alg->rounds);
		printf("\nKey setup: ");
		BENCH(alg->dec_key_setup(key, rkeys, alg->rounds); alg->release(rkeys, alg->rounds), rep, 16*(1+alg->rounds));
		alg->dec_key_setup(key, rkeys, alg->rounds);
		printf("\nDecrypt  : ");
		memset(vfy, 0, LN);
		BENCH(setup_iv(alg, iv); alg->decrypt(rkeys, alg->rounds, iv, out, vfy, LN), rep/2+1, LN);
		err += compare(vfy, in, LN, "OSSL plain");
		if (alg->release)
			alg->release(rkeys, alg->rounds);
		free(rkeys);
	}

	printf("\n");
	secmem_release(crypto);
	return tested? err: -1;
}

