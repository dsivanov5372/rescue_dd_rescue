/** aes.c
 * Generic AES routines buidling CBC and CTR by calling a lowlevel AES_Blk routine
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 8/2014
 * License: GPL v2 or v3
 */

#include "aes.h"

#include <string.h>

void xor16(uchar x1[16], const uchar x2[16])
{
	uint i;
	for (i = 0; i < 16; ++i)
		*(ulong*)(x1+i) ^= *(ulong*)(x2+i);
}


void AES_Gen_CBC_Enc(AES_Crypt_Blk_fn *cryptfn, xor_blk *xorfn,
		     const uchar* rkeys, uint rounds,
		     uchar iv[16],
		     const uchar *input, uchar *output,
		     ssize_t len)
{
	while (len >= 16) {
		xorfn(iv, input);
		cryptfn(rkeys, rounds, iv, iv);
		memcpy(output, iv, 16);
		len -= 16; input += 16; output += 16;
	}
	if (len) {
		int i;
		uchar in[16];
		for (i = 0; i < len; ++i) 
			in[i] = input[i];
		for (; i < 16; ++i)
			in[i] = 0;
		xorfn(iv, in);
		cryptfn(rkeys, rounds, iv, iv);
		memcpy(output, iv, 16);
	}
}


