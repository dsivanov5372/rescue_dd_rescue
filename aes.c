/** aes.c
 * Generic AES routines buidling CBC and CTR by calling a lowlevel AES_Blk routine
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 8/2014
 * License: GPL v2 or v3
 */

#include "aes.h"

#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>

void xor16(const uchar x1[16], const uchar x2[16], uchar xout[16])
{
	uint i;
	for (i = 0; i < 16; i+=sizeof(ulong))
		*(ulong*)(xout+i) = *(ulong*)(x1+i) ^ *(ulong*)(x2+i);
}

void fill_blk(const uchar *in, uchar bf[16], ssize_t len)
{
	uint i;
	for (i = 0; i < len; ++i)
		bf[i] = in[i];
	for (; i < 16; ++i)
		bf[i] = 0;
}

void AES_Gen_ECB_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar* iv,
		     const uchar *input, uchar *output,
		     ssize_t len)
{
	while (len >= 16) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (len) {
		uchar in[16];
		fill_blk(input, in, len);
		cryptfn(rkeys, rounds, in, output);
	}
}

void AES_Gen_ECB_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar* iv,
		     const uchar *input, uchar *output,
		     ssize_t len)
{
	while (len >= 16) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (len) {
		uchar out[16];
		cryptfn(rkeys, rounds, input, out);
		memcpy(output, out, len);
	}
}


void AES_Gen_CBC_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv,
		     const uchar *input, uchar *output,
		     ssize_t len)
{
	while (len >= 16) {
		xor16(iv, input, iv);
		cryptfn(rkeys, rounds, iv, iv);
		memcpy(output, iv, 16);
		len -= 16; input += 16; output += 16;
	}
	if (len) {
		uchar in[16];
		fill_blk(input, in, len);
		xor16(iv, in, iv);
		cryptfn(rkeys, rounds, iv, iv);
		memcpy(output, iv, 16);
	}
}

void AES_Gen_CBC_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv,
		     const uchar *input, uchar *output,
		     ssize_t len)
{
	uchar ebf[16];
	while (len >= 16) {
		cryptfn(rkeys, rounds, input, ebf);
		xor16(iv, ebf, output);
		memcpy(iv, input, 16);
		len -= 16; input += 16; output += 16;
	}
	if (len) {
		cryptfn(rkeys, rounds, input, ebf);
		int i;
		for (i = 0; i < len; ++i)
			output[i] = iv[i] ^ ebf[i];
		memcpy(iv, input, 16);
	}
}

/* Use 12 bits from nonce, initialize rest with counter */
void AES_Gen_CTR_Prep(const uchar nonce[16], uchar ctr[16], unsigned long long ival)
{
	memcpy(ctr, nonce, 12);
	unsigned int low = (unsigned int)ival;
	*(uint*)(ctr+12) = htonl(low);
	unsigned int high = (unsigned int)(ival>>32);
	*(uint*)(ctr+8) += htonl(high);
}

/* Consider counter to be 8 bytes ... this avoids wrap around after 4G blocks (64GB) */
static inline 
void be_inc(uchar ctr[8])
{
	int i = 8;
	do {
		++ctr[--i];
	} while (i && !ctr[i]);
}

void AES_Gen_CTR_Crypt(AES_Crypt_Blk_fn *cryptfn,
			const uchar *rkeys, uint rounds,
			uchar *ctr,
			const uchar *input, uchar *output,
			ssize_t len)
{
	uchar eblk[16];
	while (len >= 16) {
		cryptfn(rkeys, rounds, ctr, eblk);
		xor16(eblk, input, output);
		be_inc(ctr+8);	
		len -= 16;
		input += 16; output += 16;
	}
	if (len) {
		uchar in[16];
		fill_blk(input, in, len);
		cryptfn(rkeys, rounds, ctr, eblk);
		xor16(eblk, in, output);
		be_inc(ctr+8);	
	}
}

void AES_Gen_Release(uchar *rkeys, uint rounds)
{
	memset(rkeys, 0, 16*(rounds+1));
	asm("":::"memory");
	free(rkeys);
}

