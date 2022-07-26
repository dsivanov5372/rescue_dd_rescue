#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "find_nonzero.h"
#include "archdep.h"
#include "secmem.h"
#include "aes.h"

//ARCH_DECLS
#if defined(__ANDROID_MIN_SDK_VERSION__) && __ANDROID_MIN_SDK_VERSION__ < 28
#warning Compile with -target linux-aarch64-android28 or -target linux-arm-android28
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <assert.h>

void usage()
{
	printf("Usage: test_aes [-s[-][N]] [-w] [ALG [REP [SEED [LEN [FILL]]]]]\n");
	exit(0);
}


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

#ifdef HAVE_AES_ARM64
#include "aes_arm64.h"
#endif

#include "aes_c.h"

#ifdef HAVE_OPENSSL_EVP_H
#include "aes_ossl.h"
#endif

/* Defaults */

#define REP 3000000
unsigned int DEF_LN = 432;
int shift = -1;
int warmup = 0;

/* TIMING */
#define BENCH(_routine, _rep, _ln)	\
	fflush(stdout);			\
	if (warmup) {			\
		_routine;		\
	}				\
	gettimeofday(&t1, NULL);	\
	for (i = 0; i < (_rep); ++i) {	\
		_routine; 		\
		LFENCE;			\
	}				\
	gettimeofday(&t2, NULL);	\
	tdiff = t2.tv_sec-t1.tv_sec + 0.000001*(t2.tv_usec-t1.tv_usec) + 0.00000001;	\
	printf("%6.3fs (%6.0fMB/s) ", tdiff, (double)(_rep)*(_ln)/(1e6*tdiff))


void setup_iv(stream_dsc_t *strm, uchar *iv /*[16]*/, uint ln)
{
	if (strm->iv_prep)
		strm->iv_prep((const uchar*)"Halleluja 12345", iv, 0);
	else
		memcpy(iv, "Halleluja 12345", ln);
}

int compare(uchar* p1, uchar* p2, size_t ln, const char* msg)
{
	uint i;
	uint *pp1 = (uint*)p1, *pp2 = (uint*)p2;
	for (i = 0; i < ln/sizeof(uint); ++i)
		if (pp1[i] != pp2[i]) {
			p1 = (uchar*)(pp1+i); p2 = (uchar*)(pp2+i);
			printf("Miscompare (%s) @ %i: %02x %02x %02x %02x <-> %02x %02x %02x %02x",
				msg, i*(uint)sizeof(uint), p1[0], p1[1], p1[2], p1[3], p2[0], p2[1], p2[2], p2[3]);
			return 1;
		}
	return 0;
}

int cmp_ln(ssize_t l1, ssize_t l2, const char* msg)
{
	if (l1 == l2)
		return 0;
	printf("Inconsistent length: %zi vs %zi (%s) ",
			l1, l2, msg);
	return 1;
}

int cmp_rv(int r1, int r2, const char* msg)
{
	if (r1 == r2)
		return 0;
	printf("Diff rval: %i vs %i (%s) ",
			r1, r2, msg);
	if ((r1 < 0 && r2 >= 0) || (r1 >= 0 && r2 < 0))
		return 1;
	else
		return 0;
}

int tested = 0;
/* Input to result cache */
uint last_ln = 0;
int last_epad, last_dpad;
/* Result cache contents */
uint last_eln, last_dln;
int last_eres, last_dres;
uchar *last_ct;
uchar do_shifted = 0;

#define BLKSZ (alg->blocksize)

#if !defined(HAVE_ALIGNED_ALLOC) || !defined(ALIGNED_ALLOC_WORKS)
void* ALIGNED_ALLOC(size_t align, size_t len)
{
#ifdef HAVE_POSIX_MEMALIGN
#warning Emulating aligned_alloc with posix_memalign
	void* ptr;
	int err = posix_memalign(&ptr, align, len);
	if (err)
		return 0;
	else
		return ptr;
#else
#warning Emulating aligned_alloc with plain alloc
	void *ptr = malloc(len+align);
	if (!ptr)
		return 0;
	else
		return ((unsigned long)ptr%align? ptr+align-(unsigned long)ptr%align: ptr);
#endif
}
#else
/* C11 requires size to be a multiple of alignment, which is enforced by Bionic */
#define ALIGNED_ALLOC(al,sz) aligned_alloc(al, (sz+al-1)-(sz+al-1)%al)
#endif

int test_alg(const char* prefix, ciph_desc_t *alg, uchar *key, uchar *in, ssize_t ln, int epad, int dpad, int rep)
{
	//uchar ctxt[DEF_LN+32], vfy[DEF_LN+2*32];	/* OpenSSL may need +2*16, sigh */
	//uchar iv[32];
	uchar *ctxt = ALIGNED_ALLOC(64, ln+32);
	uchar *vfy  = ALIGNED_ALLOC(64, ln+2*32);
	uchar *iv   = ALIGNED_ALLOC(64, 32);
        struct timeval t1, t2;
	double tdiff; 
	int i;
	int err = 0;
	int eerr = 0, derr = 0;
	unsigned long long ivhash, divhash;
	ssize_t eln, dln;
	ssize_t exp_eln = alg->stream->granul <= 1? ln: ((epad == PAD_ALWAYS || (ln&(BLKSZ-1)))? ln+BLKSZ-(ln&(BLKSZ-1)): ln);
	++tested;
	printf("* %s %s (%i, %i, %i) pad %i/%i", prefix, alg->name, alg->keylen, alg->rounds, alg->ctx_size, epad, dpad);
	printf("\nEKey setup: ");
	assert(ctxt); assert(vfy); assert(iv);
	uchar *rkeys = (uchar*)crypto->ekeys;	//malloc(alg->ctx_size);
	BENCH(alg->enc_key_setup(key, rkeys, alg->rounds); if (alg->release) alg->release(rkeys, alg->rounds), rep*2, 16*(1+alg->rounds));
	alg->enc_key_setup(key, rkeys, alg->rounds);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x ", rkeys[0], rkeys[16], rkeys[32], rkeys[64],
			rkeys[16*(alg->rounds-3)], rkeys[16*(alg->rounds-2)], rkeys[16*(alg->rounds-1)], rkeys[16*alg->rounds]);
	printf("\nEncrypt   : ");
	BENCH(setup_iv(alg->stream, iv, BLKSZ); eerr = alg->encrypt(rkeys, alg->rounds, iv, epad, in, ctxt, ln, &eln); if (alg->recycle) alg->recycle(rkeys), (rep+1)/2, ln);
	memcpy(&ivhash, iv, 4); memcpy((uchar*)(&ivhash)+4, iv+12, 4);
	printf("%zi->%zi: %i %016llx ", ln, eln, eerr, ivhash);
	if (eerr < 0)
		++err;
	err += cmp_ln(eln, exp_eln, "encr vs exp");
	if (last_ln == ln && last_epad == epad) {
		err += compare(ctxt, last_ct, eln, "encr vs prev");
		err += cmp_ln(eln, last_eln, "enc len");
		err += cmp_rv(eerr, last_eres, "enc retval");
	}
	if (alg->release)
		alg->release(rkeys, alg->rounds);
	//if (err) printf("%i ", err);
	printf("\nDKey setup: ");
	BENCH(alg->dec_key_setup(key, rkeys, alg->rounds); if (alg->release) alg->release(rkeys, alg->rounds), rep*2, 16*(1+alg->rounds));
	alg->dec_key_setup(key, rkeys, alg->rounds);
	printf("%02x%02x%02x%02x%02x%02x%02x%02x ", rkeys[0], rkeys[16], rkeys[32], rkeys[64],
			rkeys[16*(alg->rounds-3)], rkeys[16*(alg->rounds-2)], rkeys[16*(alg->rounds-1)], rkeys[16*alg->rounds]);
	printf("\nDecrypt   : ");
	memset(vfy, 0xff, DEF_LN+32);
	BENCH(setup_iv(alg->stream, iv, BLKSZ); derr = alg->decrypt(rkeys, alg->rounds, iv, dpad, ctxt, vfy, eln, &dln); if (alg->recycle) alg->recycle(rkeys), (rep+1)/2, eln);
	memcpy(&divhash, iv, 4); memcpy((uchar*)(&divhash)+4, iv+12, 4);
	printf("%zi->%zi: %i %016llx ", eln, dln, derr, divhash);
	if (derr < 0)
		++err;
	ssize_t exp_dln = alg->stream->granul <= 1? eln: (dpad? ln: eln);
	// TODO: We should try with shorter ln as well? Seeing what dln is returned then ...	
	err += compare(vfy, in, ln, prefix);
	err += cmp_ln(dln, exp_dln, "decr vs exp");
	if (last_ln == ln && last_dpad == dpad) {
		err += cmp_ln(dln, last_dln, "dec len");
		err += cmp_rv(derr, last_dres, "dec retval");
	}
	//if (err) printf("%i ", err);
	/* Check for overwrite(CTR) and padding(Others) */
	if (alg->stream->granul <= 1 && vfy[dln] != 0xff) {
		printf("overrun detected "); ++err;
	}
	if (alg->stream->granul > 1 && (ln&(BLKSZ-1))) {
		if (epad == PAD_ZERO && vfy[ln] != 0) {
			printf("no zero pad "); ++err;
		}
		if (epad != PAD_ZERO && vfy[ln] != BLKSZ-(ln&(BLKSZ-1))) {
			printf("no %i pad %02x ", BLKSZ-(int)(ln&(BLKSZ-1)), vfy[ln]);
			//++err;
		}
	}
	if (ivhash != divhash) {
		printf("iv miscompare "); ++err;
	}
	//if (err) printf("%i ", err);
	/* Update cache */	
	last_ln = ln; last_epad = epad; last_dpad = dpad;
	memcpy(last_ct, ctxt, eln);
	last_eln = eln; last_dln = dln;
	last_eres = eerr; last_dres = derr;
	printf("\n");
	if (0 && err)
		abort();
	if (alg->release)
		alg->release(rkeys, alg->rounds);
	//free(rkeys);
	free(iv); free(vfy); free(ctxt);
	return err;
}

int test_memcpy(uchar *in, ssize_t ln, int rep)
{
	uchar *ctxt = ALIGNED_ALLOC(64, ln+32);
        struct timeval t1, t2;
	double tdiff;
	int i;
	printf("\nMemcpy    : ");
	BENCH(memcpy(ctxt, in, ln), rep, ln);
	printf("\n");
	free(ctxt);
	return 0;
}

#if defined(HAVE_LIBCRYPTO) && !defined(NO_OSSL)
#define TEST_OSSL(LN, EPAD, DPAD)			\
	alg = findalg(AES_OSSL_Methods, testalg, 1);	\
	if (alg)					\
		ret += test_alg("OSSL ", alg, key, in, LN, EPAD, DPAD, rep)
#else
#define TEST_OSSL(LN, EPAD, DPAD) do {} while(0)
#endif

#ifdef HAVE_AESNI
#ifndef NO_AVX2
#define TEST_AESNI(LN, EPAD, DPAD)			\
	do {						\
	const char* label;				\
	if (have_avx2) {				\
		label = "VAES ";			\
		alg = findalg(VAESNI_Methods, testalg, 1);	\
	} else {					\
		label = "AESNI";			\
		alg = findalg(SAESNI_Methods, testalg, 1);	\
	}						\
	if (alg)					\
		ret += test_alg(label, alg, key, in, LN, EPAD, DPAD, rep);	\
	} while(0)
#else
#define TEST_AESNI(LN, EPAD, DPAD)			\
	alg = findalg(SAESNI_Methods, testalg, 1);	\
	if (alg)					\
		ret += test_alg("AESNI", alg, key, in, LN, EPAD, DPAD, rep)
#endif
#else
#define TEST_AESNI(LN, EPAD, DPAD) do {} while(0)
#endif

#ifdef HAVE_AES_ARM64
#define TEST_AES_ARM64(LN, EPAD, DPAD)			\
	alg = findalg(AES_ARM8_Methods, testalg, 1);	\
	if (alg)					\
		ret += test_alg("ARM64", alg, key, in, LN, EPAD, DPAD, rep)
#else
#define TEST_AES_ARM64(LN, EPAD, DPAD) do {} while(0)
#endif


#define TEST_ENGINES(LN, EPAD, DPAD)			\
	alg = findalg(AES_C_Methods, testalg, 1);	\
	if (alg) 					\
		ret += test_alg("AES_C", alg, key, in, LN, EPAD, DPAD, (rep+3)/4);	\
	TEST_OSSL(LN, EPAD, DPAD);			\
	TEST_AESNI(LN, EPAD, DPAD);			\
	TEST_AES_ARM64(LN, EPAD, DPAD);	

int ret = 0;
int main(int argc, char *argv[])
{
	int rep = REP;
	unsigned char *key = (unsigned char*)"Test Key_123 is long enough even for AES-256";
	//int dbg = 0;
	char* testalg;
	ARCH_DETECT;
#if defined(__i386__) || defined(__x86_64__)
	printf("CPU Features: SSE2 %i SSE4.2 %i AES %i RDRAND %i AVX2 %i VAES %i\n",
		have_sse2, have_sse42, have_aesni, have_rdrand, have_avx2, have_vaes);
#elif defined(__arm__) || defined(__aarch64__)
	//have_arm8crypto = 1;
	printf("CPU Features: AES Arm8 %i\n",
		have_arm8crypto);
#endif
	crypto = secmem_init();
	/*
	if (argc > 1 && !strcmp("-d", argv[1])) {
		dbg = 1; --argc; ++argv;
	}
	*/
	if (argc > 1 && !strcmp(argv[1], "-h"))
		usage();
	/* Repeat the run with a changed length */
	if (argc > 1 && !memcmp(argv[1], "-s", 2)) {
		do_shifted = 1;
		if (strlen(argv[1]) > 2)
			shift = atol(argv[1]+2);
		--argc; ++argv;
	}
	/* Do a warmup run */
	if (argc > 1 && !strcmp(argv[1], "-w")) {
		warmup = 1;
		--argc; ++argv;
	}
#if !defined(NO_AVX2) && (defined(__i386__) || defined(__x86_64__))
	/* Disable AVX override */
	if (argc > 1 && !strcmp(argv[1], "-2")) {
		have_avx2 = 0;
		--argc; ++argv;
	}
#endif
	/* Positional parameters following */
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
		DEF_LN = atol(argv[4]);

	unsigned char *in = ALIGNED_ALLOC(64, DEF_LN+16);
	last_ct = ALIGNED_ALLOC(64, DEF_LN+32);
	assert(in); assert(last_ct);
	if (argc > 5)
		fillval(in, DEF_LN, atol(argv[5]));
	else
		fillrand(in, DEF_LN);

	ciph_desc_t *alg = NULL;
	//OPENSSL_init();
	test_memcpy(in, DEF_LN, rep*4);
	printf("===> AES tests/benchmark (%i) PAD_ZERO <===\n", DEF_LN);
	TEST_ENGINES(DEF_LN, PAD_ZERO, PAD_ZERO);
	if (ret) {
		fprintf(stderr, " ************* %i inconsistencies found\n", ret);
		secmem_release(crypto);
		return ret;
	}
	if((long)DEF_LN+shift >= 0 && do_shifted) {
	printf("===> AES tests/benchmark (%i) PAD_ZERO <===\n", DEF_LN+shift);
	TEST_ENGINES(DEF_LN+shift, PAD_ZERO, PAD_ZERO);
	if (ret) {
		fprintf(stderr, " ************* %i inconsistencies found\n", ret);
		secmem_release(crypto);
		return ret;
	}
	}
	printf("\n===> AES tests/benchmark (%i) PAD_ALWAYS <===\n", DEF_LN);
	TEST_ENGINES(DEF_LN, PAD_ALWAYS, PAD_ALWAYS);
	if (ret) {
		fprintf(stderr, " ************* %i inconsistencies found\n", ret);
		secmem_release(crypto);
		return ret;
	}
	if((long)DEF_LN+shift >= 0 && do_shifted) {
	printf("===> AES tests/benchmark (%i) PAD_ALWAYS <===\n", DEF_LN+shift);
	TEST_ENGINES(DEF_LN+shift, PAD_ALWAYS, PAD_ALWAYS);
	if (ret) {
		fprintf(stderr, " ************* %i inconsistencies found\n", ret);
		secmem_release(crypto);
		return ret;
	}
	}
	printf("\n===> AES tests/benchmark (%i) PAD_ASNEEDED <===\n", DEF_LN);
	TEST_ENGINES(DEF_LN, PAD_ASNEEDED, PAD_ASNEEDED);
	if (ret) {
		fprintf(stderr, " ************* %i inconsistencies found\n", ret);
		secmem_release(crypto);
		return ret;
	}
	if((long)DEF_LN+shift >= 0 && do_shifted) {
	printf("===> AES tests/benchmark (%i) PAD_ASNEEDED <===\n", DEF_LN+shift);
	TEST_ENGINES(DEF_LN+shift, PAD_ASNEEDED, PAD_ASNEEDED);
	if (ret) {
		fprintf(stderr, " ************* PAD_ASNEEDED: %i inconsistencies found. (Ignore!) ************* \n", ret);
		ret = 0;
	}
	}

	printf("\n");
	if (!tested)
		fprintf(stderr, "No tests performed; invalid alg \"%s\".\n", testalg);
	secmem_release(crypto);
	free(last_ct); free(in);
	return (tested? ret: -1);
}

