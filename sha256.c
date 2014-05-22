/** sha256.c
 *
 * Algorithm translated to C from pseudocode at Wikipedia
 * by Kurt Garloff <kurt@garloff.de>
 * http://en.wikipedia.org/wiki/SHA256
 * Copyright: CC-BY-SA 3.0/GFDL
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <assert.h>

/*
Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 2^32 
Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63 
Note 3: The compression function uses 8 working variables, a through h 
Note 4: Big-endian convention is used when expressing the constants in this pseudocode, and when parsing message block data i
	from bytes to words, for example, the first word of the input message "abc" after padding is 0x61626380 
*/
typedef struct sha256_ctx {
	uint32_t h[8];
} sha256_ctx_t;

/*
 * Initialize hash values: (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19): 
 */
void init_sha256(sha256_ctx_t *ctx)
{
	ctx->h[0] = 0x6a09e667;
	ctx->h[1] = 0xbb67ae85;
	ctx->h[2] = 0x3c6ef372;
	ctx->h[3] = 0xa54ff53a;
	ctx->h[4] = 0x510e527f;
	ctx->h[5] = 0x9b05688c;
	ctx->h[6] = 0x1f83d9ab;
	ctx->h[7] = 0x5be0cd19;
}
			       
/* 
 * Initialize array of round constants: (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
 */
static const
uint32_t k[] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
		 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/*
 * Pre-processing: 
 * append the bit '1' to the message 
 * append k bits '0', where k is the minimum number >= 0 such that the resulting message length (modulo 512 in bits) is 448. 
 * append length of message (without the '1' bit or padding), in bits, as 64-bit big-endian integer 
 * (this will make the entire post-processed length a multiple of 512 bits)
 */

#define  LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define RIGHTROTATE(x, c) (((x) >> (c)) | ((x) << (32 - (c))))
/* 
 * Process the message in successive 512-bit chunks: 
 * break message into 512-bit chunks 
 * (The initial values in w[0..63] don't matter, so many implementations zero them here) 
 */
void sha256_64(const uint8_t* msg, sha256_ctx_t* ctx)
{
	int i;
 	/* for each chunk create a 64-entry message schedule array w[0..63] of 32-bit words */
	uint32_t w[64];
 	/* copy chunk into first 16 words w[0..15] of the message schedule array */
	memcpy(w, msg, 64/(sizeof(uint32_t)));
	/* Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array: */
	for (i = 16; i < 64;  ++i) {
		uint32_t s0 = RIGHTROTATE(w[i-15], 7) ^ RIGHTROTATE(w[i-15], 18) ^ (w[i-15] >> 3);
		uint32_t s1 = RIGHTROTATE(w[i-2], 17) ^ RIGHTROTATE(w[i-2] , 19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	/* Initialize working variables to current hash value:*/
	uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
	uint32_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h = ctx->h[7];
	/* Compression function main loop: */
	for (i = 0; i < 64; ++i) {
		uint32_t S1 = RIGHTROTATE(e, 6) ^ RIGHTROTATE(e, 11) ^ RIGHTROTATE(e, 25);
		uint32_t ch = (e & f) ^ ((!e) & g);
		uint32_t temp1 = h + S1 + ch + k[i] + w[i];
		uint32_t S0 = RIGHTROTATE(a, 2) ^ RIGHTROTATE(a, 13) ^ RIGHTROTATE(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = S0 + maj;

		h = g; g = f; f = e;
		e = d + temp1;
		d = c; c = b; b = a;
		a = temp1 + temp2;
	}
	/* Add the compressed chunk to the current hash value: */
	ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
	ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

static char _sha256_res[65];
char* sha256_out(sha256_ctx_t* ctx)
{
	/* Produce the final hash value (big-endian): */ 
	//digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
	int i;
	*_sha256_res = 0;
	for (i = 0; i < 8; ++i) {
		char res[9];
		sprintf(res, "%08x", htonl(ctx->h[i]));
		strcat(_sha256_res, res);
	}
	return _sha256_res;
}

/* We assume we have a few bytes behind ln  ... */
void sha256_calc(uint8_t *ptr, size_t chunk_ln, size_t final_len, sha256_ctx_t *ctx)
{
	if (final_len) {
		ptr[chunk_ln] = 0x80;
		int i;
		for (i = chunk_ln + 1; i % 64 != 56; ++i)
			ptr[i] = 0;
		*(uint32_t*)(ptr+i) = htonl(final_len << 3);
		*(uint32_t*)(ptr+i+4) = htonl(final_len >> 29);
		chunk_ln = i + 8;
	}
	assert(0 == chunk_ln % 64);
	uint32_t offset;
	for (offset = 0; offset < chunk_ln; offset += 64)
		sha256_64(ptr + offset, ctx);
}

