/** secmem.h
 *
 * Declare functions and structures for secure storage 
 */

#ifndef _SECMEM_H
#define _SECMEM_H

typedef struct _roundkey {
	unsigned char data[16];
} roundkey;

typedef struct _ciphblk {
	unsigned char data[16];
} ciphblk;

typedef struct _sec_fields {
	/* PRNG state */
	unsigned char prng_state[256];
	/* Up to 256 bit symmetric keys */
	unsigned char userkey1[32];
	unsigned char userkey2[32];
	/* Enough for 38 rounds of en/decryption */
	roundkey ekeys[40];
	roundkey dkeys[40];
	roundkey xkeys[40];
	/* Hashing buffer */
	unsigned char hashbuf1[128];
	unsigned char hashbuf2[128];
	/* IVs */
	ciphblk iv1;
	ciphblk iv2;
} sec_fields;

sec_fields* secmem_init();
void secmem_release(sec_fields*);

extern sec_fields *crypto;

#endif
