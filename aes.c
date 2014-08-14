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

/* PKCS padding */
void fill_blk(const uchar *in, uchar bf[16], ssize_t len, uint pad)
{
	uint i;
	uchar by = pad? 16-(len&0x0f) : 0;
	for (i = 0; i < len; ++i)
		bf[i] = in[i];
	for (; i < 16; ++i)
		bf[i] = by;
}

void AES_Gen_ECB_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /*uchar *iv,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	while (len >= 16) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (len || pad == PAD_ALWAYS) {
		uchar in[16];
		fill_blk(input, in, len, pad);
		cryptfn(rkeys, rounds, in, output);
		*olen += (16-len&15);
	}
}

void AES_Gen_ECB_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     /*uchar* iv,*/ uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	while (len >= 16) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (len) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (pad) {
		uchar last = *(output-1);
		if (last > 0x10)
			fprintf(stderr, "Illegal padding! (%02x)\n", last);
		else {
			int i;
			for (i = 1; i < last; ++i) {
				if (*(output-1-i) != last) {
					fprintf(stderr, "Inconsistent padding! (%02x@-%i vs. %02x)\n",
						*(output-1-i), i, last);
					i = 0;
					break;
				}
				if (!i)
					return;
				if (last == 1 && pad != PAD_ALWAYS)
					fprintf(stderr, "Warn: 1/256 chance of misdetecting padding!\n");
				if (*olen & 0x0f)
					*olen += 16-(*olen&0x0f);
				*olen -= last;
		}
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
		cryptfn(rkeys, rounds, iv, output);
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
		//int i;
		//for (i = 0; i < len; ++i)
		//	output[i] = iv[i] ^ ebf[i];
		xor16(iv, ebf, output);
		//memcpy(iv, input, 16);
	}
}

/* Use 12 bits from nonce, initialize rest with counter */
void AES_Gen_CTR_Prep(const uchar nonce[16], uchar ctr[16], unsigned long long ival)
{
	memcpy(ctr, nonce, 12);
	unsigned int low  = (unsigned int)ival;
	*(uint*)(ctr+12)  = htonl(low);
	unsigned int high = (unsigned int)(ival>>32);
	*(uint*)(ctr+8)   = htonl(ntohl(*(uint*)(ctr+8)+high));
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
		//be_inc(ctr+8);	
	}
}

void AES_Gen_Release(uchar *rkeys, uint rounds)
{
	memset(rkeys, 0, 16*(rounds+1));
	asm("":::"memory");
}

