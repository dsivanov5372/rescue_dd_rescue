#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <assert.h>
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
#define DEF_LN 288
#ifndef SHIFT
# define SHIFT 5
#endif

/* TIMING */
#define BENCH(_routine, _rep, _ln)	\
	fflush(stdout);			\
	/* _routine; */			\
	gettimeofday(&t1, NULL);	\
	for (i = 0; i < (_rep); ++i) {	\
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

int tested = 0;
/* Input to result cache */
uint last_ln = 0;
int last_epad, last_dpad;
/* Result cache contents */
uint last_eln, last_dln;
int last_eres, last_dres;
uchar last_ct[DEF_LN+16];

int test_alg(const char* prefix, aes_desc_t *alg, uchar *key, uchar *in, uint ln, int epad, int dpad, int rep)
{
	uchar ctxt[DEF_LN], vfy[DEF_LN];
	uchar iv[16];
        struct timeval t1, t2;
	double tdiff; 
	int i;
	int err = 0;
	int eerr = 0, derr = 0;
	ssize_t eln, dln;
	ssize_t exp_eln = alg->blksize <= 1? ln: ((epad == PAD_ALWAYS || (ln&15))? ln+16-(ln&15): ln);
	++tested;
	printf("\n* %s %s (%i, %i, %i) pad %i/%i", prefix, alg->name, alg->keylen, alg->rounds, alg->ctx_size, epad, dpad);
	printf("\nEKey setup: ");
	/* TODO: Use secmem ... */
	uchar *rkeys = (uchar*)malloc(alg->ctx_size);
	BENCH(alg->enc_key_setup(key, rkeys, alg->rounds); alg->release(rkeys, alg->rounds), rep, 16*(1+alg->rounds));
	alg->enc_key_setup(key, rkeys, alg->rounds);
	printf("\nEncrypt   : ");
	BENCH(setup_iv(alg, iv); eerr = alg->encrypt(rkeys, alg->rounds, iv, epad, in, ctxt, ln, &eln), rep/2+1, ln);
	printf("%zi->%zi: %i ", ln, eln, eerr);
	if (last_ln == ln && last_epad == epad) {
		err += compare(ctxt, last_ct, eln, "encr vs prev");
		assert(eln == exp_eln);
		// TODO: Compare elen against last
		// TODO: Compare retval
	}
	printf("\nDKey setup: ");
	BENCH(alg->dec_key_setup(key, rkeys, alg->rounds); alg->release(rkeys, alg->rounds), rep, 16*(1+alg->rounds));
	alg->dec_key_setup(key, rkeys, alg->rounds);
	printf("\nDecrypt   : ");
	memset(vfy, 0xff, DEF_LN);
	BENCH(setup_iv(alg, iv); derr = alg->decrypt(rkeys, alg->rounds, iv, dpad, ctxt, vfy, eln, &dln), rep/2+1, eln);
	printf("%zi->%zi: %i ", eln, dln, derr);
	ssize_t exp_dln = alg->blksize <= 1? eln: (dpad? ln: eln);
	// TODO: We should try with short ln as well? Seeing what dln is returned then ...	
	err += compare(vfy, in, ln, prefix);
	if (last_ln == ln && last_dpad == dpad) {
		assert(dln == exp_dln);
		// TODO: Compare dlen against last
		// TODO: Compare retval
	}
	/* TODO: Check for overwrite(CTR) and padding(Others) */
	//if (vfy[LN] != 0 /*SHIFT*/ && alg->blksize != 1)
	//	printf("\n Padding broken! %02x\n", vfy[LN]);
	/* Update cache */	
	last_ln = ln; last_epad = epad; last_dpad = dpad;
	memcpy(last_ct, ctxt, eln);
	last_eln = eln; last_dln = dln;
	last_eres = eerr; last_dres = derr;
	if (alg->release)
		alg->release(rkeys, alg->rounds);
	free(rkeys);
	return err;
}



int main(int argc, char *argv[])
{
	int rep = REP;
	unsigned int LN = DEF_LN;
	unsigned char in[DEF_LN+16];
	unsigned char *key = (unsigned char*)"Test Key_123 is long enough even for AES-256";
	//int dbg = 0;
	int err = 0;
	char* testalg;
	crypto = secmem_init();
	/*
	if (argc > 1 && !strcmp("-d", argv[1])) {
		dbg = 1; --argc; ++argv;
	}
	*/
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


	aes_desc_t *alg = NULL;
	printf("===> AES tests/benchmark (%i) <===", LN);

	//OPENSSL_init();
#ifdef HAVE_AESNI
	alg = findalg(AESNI_Methods, testalg);
	if (alg) 
		err += test_alg("AESNI", alg, key, in, LN, PAD_ZERO, PAD_ZERO, rep);
#endif
	alg = findalg(AES_C_Methods, testalg);
	if (alg) 
		err += test_alg("AES_C", alg, key, in, LN, PAD_ZERO, PAD_ZERO, rep);
	alg = findalg(AES_OSSL_Methods, testalg);
	if (alg)
		err += test_alg("OSSL ", alg, key, in, LN, PAD_ZERO, PAD_ZERO, rep);
	
	LN -= SHIFT;
	printf("\n===> AES tests/benchmark (%i) <===", LN);
#ifdef HAVE_AESNI
	alg = findalg(AESNI_Methods, testalg);
	if (alg) 
		err += test_alg("AESNI", alg, key, in, LN, PAD_ZERO, PAD_ZERO, rep);
#endif
	alg = findalg(AES_C_Methods, testalg);
	if (alg) 
		err += test_alg("AES_C", alg, key, in, LN, PAD_ZERO, PAD_ZERO, rep);
	alg = findalg(AES_OSSL_Methods, testalg);
	if (alg)
		err += test_alg("OSSL ", alg, key, in, LN, PAD_ZERO, PAD_ZERO, rep);

	/* TODO: Test with different padding values */

	printf("\n");
	secmem_release(crypto);
	return tested? err: -1;
}

