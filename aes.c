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
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	assert(iv == NULL);
	*olen = len;
	while (len >= 16) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (len || pad == PAD_ALWAYS) {
		uchar in[16];
		fill_blk(input, in, len, pad);
		cryptfn(rkeys, rounds, in, output);
		*olen += 16-(len&15);
	}
}

/** Decrypt padding:
 * We expect all blocks have been decoded fully and
 * the output pointer points to the first byte beyond
 * the output buffer (i.e. output[-1] is the last decoded byte).
 * *olen contains the input length -- which may not be a multiple
 * of the block size -- in the PAD_ZERO case, we'll leave it
 * untouched (and assume that caller knew the right length).
 * Otherwise we round olen up to the next multiple of the block
 * size and then look for padding bytes. With PAD_ALWAYS, there
 * MUST be padding (1 -- 16 bytes), with PAD_ASNEEDED there may
 * be padding (0 -- 15 bytes). Note that there is a risk for
 * misinterpretation with PAD_ASNEEDED (if the last byte of the
 * inupt happens to be a 0x01, or -- less likely -- the last two
 * bytes being 0x02 0x02 or ...).
 */
void dec_fix_olen_pad(ssize_t *olen, uint pad, const uchar *output)
{
	if (!pad)
		return;
	uchar last = output[-1];
	if (last > 0x10) {
		fprintf(stderr, "Illegal padding! (%02x)\n", last);
		return;
	}
	uint i;
	for (i = 1; i < last; ++i) {
		if (*(output-1-i) != last) {
			fprintf(stderr, "Inconsistent padding! (%02x@-%i vs. %02x)\n",
				*(output-1-i), i, last);
			i = 0;
			break;
		}
	}
	if (!i)
		return;
	if (pad != PAD_ALWAYS) {
		if (last == 1)
			fprintf(stderr, "Warn: 1/256 chance of misdetecting padding!\n");
		else if (last == 2)
			fprintf(stderr, "Warn: 1/65536 chance of misdetecting padding!\n");
		// ...
	}
	if (*olen & 0x0f)
		*olen += 16-(*olen&0x0f);
	*olen -= last;
}

void AES_Gen_ECB_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar* iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	assert(iv == NULL);
	*olen = len;
	while (len >= 16) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (len) {
		cryptfn(rkeys, rounds, input, output);
		len -= 16; input += 16; output += 16;
	}
	if (pad) 
		dec_fix_olen_pad(olen, pad, output);
}


void AES_Gen_CBC_Enc(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	*olen = len;
	while (len >= 16) {
		xor16(iv, input, iv);
		cryptfn(rkeys, rounds, iv, iv);
		memcpy(output, iv, 16);
		len -= 16; input += 16; output += 16;
	}
	if (len || pad == PAD_ALWAYS) {
		uchar in[16];
		fill_blk(input, in, len, pad);
		xor16(iv, in, iv);
		cryptfn(rkeys, rounds, iv, output);
		//memcpy(iv, output, 16);
		*olen += (16-len&15);
	}
}

void AES_Gen_CBC_Dec(AES_Crypt_Blk_fn *cryptfn,
		     const uchar* rkeys, uint rounds,
		     uchar *iv, uint pad,
		     const uchar *input, uchar *output,
		     ssize_t len, ssize_t *olen)
{
	uchar ebf[16];
	*olen = len;
	while (len >= 16) {
		cryptfn(rkeys, rounds, input, ebf);
		xor16(iv, ebf, output);
		memcpy(iv, input, 16);
		len -= 16; input += 16; output += 16;
	}
	if (len) {
		cryptfn(rkeys, rounds, input, ebf);
		xor16(iv, ebf, output);
		//memcpy(iv, input, 16);
		len -= 16; input += 16; output += 16;
	}
	if (pad)
		dec_fix_olen_pad(olen, pad, output);
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
			uchar *ctr, uint pad,
			const uchar *input, uchar *output,
			ssize_t len, ssize_t *olen)
{
	//assert(pad == 0);
	*olen = len;
	uchar eblk[16];
	while (len >= 16) {
		cryptfn(rkeys, rounds, ctr, eblk);
		be_inc(ctr+8);	
		xor16(eblk, input, output);
		len -= 16;
		input += 16; output += 16;
	}
	if (len) {
		uchar in[16];
		fill_blk(input, in, len, pad);
		cryptfn(rkeys, rounds, ctr, eblk);
		//be_inc(ctr+8);	
		xor16(eblk, in, output);
	}
}

void AES_Gen_Release(uchar *rkeys, uint rounds)
{
	memset(rkeys, 0, 16*(rounds+1));
	asm("":::"memory");
}

