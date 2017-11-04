/* openSSL key derivation: pbkdf_ossl.c
 * 
 * not recommended; weak and so fast that it can be easily
 * brute-forced. Provided for compatibility.
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 9/2015
 * License: GNU GPL v2 or v3 (at your option)
 */

#include "pbkdf_ossl.h"
#include "md5.h"
#include <stdlib.h>
#include <assert.h>
#include <endian.h>
#include <stdint.h>

#define MIN(a,b) ((a)<(b)? (a): (b))

#if __BYTE_ORDER == __BIG_ENDIAN
static inline void to_bytes(uint32_t val, uint8_t *bytes)
{
	bytes[0] = (uint8_t)val;
	bytes[1] = (uint8_t)(val >> 8);
	bytes[2] = (uint8_t)(val >> 16);
	bytes[3] = (uint8_t)(val >> 24);
}
static inline void memcpy_hash(uint8_t *buf, hash_t *hv, size_t hln)
{
	int i;
	assert(hln%sizeof(uint32_t) == 0);
	for (i=0; i<hln/sizeof(uint32_t); ++i)
		to_bytes(hv->sha256_h[i], buf+i*sizeof(uint32_t));
}
#else
static inline void memcpy_hash(uint8_t *buf, hash_t *hv, size_t hln)
{
	memcpy(buf, hv, hln);
}

#endif
#include <netinet/in.h>
static inline void memcpy_nhash(hashalg_t *hash, uint8_t *buf, hash_t *hv, size_t hln)
{
	if (hash->hashln == 16)
		return memcpy_hash(buf, hv, hln);
	int i;
	assert(hln%sizeof(uint32_t) == 0);
	for (i=0; i<hln/sizeof(uint32_t); ++i)
		*((uint32_t*)buf+i) = htonl(*((uint32_t*)hv+i));
}

#include <stdio.h>
int pbkdf_ossl(hashalg_t *hash, unsigned char* pwd,  int plen,
				unsigned char* salt, int slen,
	     unsigned int iter, unsigned char* key,  int klen,
				unsigned char* iv,   int ivlen)
{
	unsigned char* hbuf = malloc(hash->hashln+plen+slen);
	unsigned int off = 0;
	unsigned cnt = 0;
	assert(iter == 1);
	hash_t hv;
	while (off < klen+ivlen) {
		int hbln = plen+slen;
		/* Compose buffer to be hashed */
		if (!cnt) {
			memcpy(hbuf, pwd, plen);
			if (slen)
				memcpy(hbuf+plen, salt, slen);
		} else {
			hbln = plen+slen+hash->hashln;
			memcpy_hash(hbuf, &hv, hash->hashln);
			memcpy(hbuf+hash->hashln, pwd, plen);
			if (slen)
				memcpy(hbuf+hash->hashln+plen, salt, slen);
		}
		hash->hash_init(&hv);
		//for (int i = 0; i <= cnt; ++i)
		hash->hash_calc(hbuf, hbln, hbln, &hv);
		/* Fill in result */
		if (off+hash->hashln < klen)
			//hash->hash_beout(key+off, &hv);
			memcpy_nhash(hash, key+off, &hv, hash->hashln);
		else if (off >= klen) {
			//hash->hash_beout(iv+off-klen, &hv);
			//memcpy_nhash(hash, iv+off-klen, &hv, MIN(hash->hashln, ivlen+klen-off));
			if (ivlen+klen < off+hash->hashln) {
				//char buf[131];
				//fprintf(stderr, "%s\n", hash->hash_hexout(buf, &hv));
				memcpy_nhash(hash, iv+off-klen, &hv, ivlen+klen-off);
			} else
				memcpy_nhash(hash, iv+off-klen, &hv, hash->hashln);
		} else {
			//fprintf(stderr, "OUCH!\n");
			//hash->hash_beout(key+off, &hv);
			memcpy_nhash(hash, key+off, &hv, klen-off);
			//hash->hash_beout(iv-(klen-off), &hv);
			memcpy_nhash(hash, iv, (hash_t*)(((unsigned char*)&hv)+klen-off), MIN(hash->hashln-klen+off, ivlen));
		}
		off += hash->hashln;
		++cnt;
	}
	memset(hbuf, 0, hash->hashln+plen+slen);
	asm("":::"memory");
	free(hbuf);
	return 0;
}
