/** rdrand.c
 * x86-64 implementation for rdrand (and aesni probing)
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 8/2014
 * License: GNU GPL v2 or v3
 */

#ifdef __RDRND__
#include <immintrin.h>
#include "archdep.h"
#define BSWAP32(x) ((x<<24) | ((x<<8)&0x00ff0000) | ((x>>8)&0x0000ff00) | (x>>24))

unsigned int rdrand32()
{
	unsigned int val = (unsigned long)&rdrand32;
	val = BSWAP32(val);
	_rdrand32_step(&val);
	return val;
}

#ifdef __x86_64__
unsigned long rdrand64()
{
	unsigned long long val = (unsigned long long)&rdrand64;
	val = (unsigned long)BSWAP32((unsigned int)val&0xffffffff)<<32 | BSWAP32((unsigned int)(val>>32));
	_rdrand64_step(&val);
	return val;
}
#else
#warning no rdrand64 on 32bit system
#endif

//#include <unistd.h>
volatile unsigned int _rdrand_res;
void probe_rdrand()
{
	_rdrand_res = rdrand32();
}

#ifdef __AES__
#include <wmmintrin.h>
volatile char _aes_probe_res[16];
void probe_aesni()
{
	__m128i x = _mm_setzero_si128();
	x = _mm_aeskeygenassist_si128(x, 0x01);
	_mm_storeu_si128((__m128i*)_aes_probe_res, x);
}
#else 
# warning compile rdrand with -maes
#endif


#else 
# warning compile rdrand with -mrdrnd
#endif


