/* openSSL key derivation: pbddf_ossl.c
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

#define MIN(a,b) ((a)<(b)? (a): (b))

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
			hbln += hash->hashln;
			memcpy(hbuf, &hv, hash->hashln);
			memcpy(hbuf+hash->hashln, pwd, plen);
			if (slen)
				memcpy(hbuf+hash->hashln+plen, salt, slen);
		}
		hash->hash_init(&hv);
		//for (int i = 0; i <= cnt; ++i)
		hash->hash_calc(hbuf, hbln, hbln, &hv);
		/* Fill in result */
		if (off+hash->hashln < klen)		
			memcpy(key+off, &hv, hash->hashln);
		else if (off >= klen)
			memcpy(iv+off-klen, &hv, MIN(hash->hashln, ivlen+klen-off));
		else {
			memcpy(key+off, &hv, klen-off);
			memcpy(iv, (unsigned char*)&hv+klen-off, MIN(hash->hashln-klen+off, ivlen));
		}
		off += hash->hashln;
		++cnt;
	}
	memset(hbuf, 0, hash->hashln+plen+slen);
	asm("":::"memory");
	free(hbuf);
	return 0;
}
