/** secmem.h
 *
 * Declare functions and structures for secure storage 
 */

#ifndef _SECMEM_H
#define _SECMEM_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

typedef union _roundkey {
	unsigned char data[16];
	unsigned int data32[4];
} roundkey;

typedef struct _ciphblk {
	unsigned char data[32];
} ciphblk;

typedef struct _sec_fields {
	/* PRNG state */
	unsigned char prng_state[256];
	/* Up to 256 bit symmetric keys */
	unsigned char userkey1[32];
	unsigned char userkey2[32];
	/* @320: Enough for 38 rounds of en/decryption with 16byte roundkeys */
	roundkey ekeys[40];
	roundkey dkeys[40];
	roundkey xkeys[40];
	/* @2240: Hashing buffer */
	unsigned char hashbuf1[128];
	unsigned char hashbuf2[128];
	/* @2496: IVs */
	unsigned char nonce1[32];
	unsigned char nonce2[32];
	ciphblk iv1;	/* ctr */
	ciphblk iv2;
	/* @2624: Salt + Password for pbkdf2 ... */
	unsigned char salt[64];
	unsigned char passphr[128];
	/* @2816: char buffer, enough for 512bit hash/key in hex */
	char charbuf1[160];
	/* @2976: two blocks - intermediate result for x2 cypto */
	unsigned char blkbuf1[32];
	/* @3008: data buffer for incomplete blocks (libcrypt) */
	unsigned char databuf1[64];
	/* @3072: buffer up to 512 bytes */
	unsigned char databuf2[512];
	/* @3584: four blocks (64B) - incomplete input block */
	unsigned char blkbuf2[64];
	/* @3648: four blocks (64B) - output buffer */
	unsigned char blkbuf3[64];
	/* @3712: four blocks (64B) - x2 long buffer */
	unsigned char blkbuf4[64];
	/* @3776 canary */
	unsigned long long canary;
	
} sec_fields;

sec_fields* secmem_init();
void secmem_release(sec_fields*);

extern sec_fields *crypto;

//#if defined(__i386__) || defined(__x86_64__)
#ifdef HAVE_LFENCE
#define LFENCE asm("lfence":::"memory")
#else
#define LFENCE asm("":::"memory")
#endif
#define mem_clobber asm("":::"memory")

#endif
