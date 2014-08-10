/** aes.c
 * Generic AES routines buidling CBC and CTR by calling a lowlevel AES_Blk routine
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 8/2014
 * License: GPL v2 or v3
 */

#include "aes.h"
#ifdef __SSE4__
static inline
__m128i _mkmask(char ln)
{
	ln &= 0x0f;
	return (ln >= 8? 
			_mm_set_epi64x((1ULL<<(8*ln-64))-1, 0xffffffffffffffffULL):
			_mm_set_epi64x(0ULL, (1ULL<<(8*ln))-1)
		);

}
#endif


void AES_Gen_CBC_Enc(AES_Crypt_Blk_fn *cryptfn, xor_blk *xorfn,
		     const uchar* rkeys, uint rounds,
		     uchar iv[16],
		     const uchar *input, uchar *output,
		     ssize_t len)
{
	while (len >= 16) {
		xorfn(iv, input);
		cryptfn(rkeys, rounds, iv, iv);
		output = iv;
		len -= 16; input += 16; output += 16;
	}
	if (len) {
#ifdef __SSE4__
		register __m128i dat = _mm_loadu_si128((const __m128i*)input);
		__m128i mask = _mkmask(len);
		dat = _mm_and_si128(dat, mask);
		iv = _mm_xor_si128(iv, dat);
#else
		int i;
		uchar in[16];
		for (i = 0; i < len; ++i) {
			if (i < len)
				in[i] = input[i];
			else
				in[i] = 0;
		}
		xorfn(iv, in);
#endif
		cryptfn(rkeys, rounds, iv, iv);
		output = iv;
	}
}
		       
