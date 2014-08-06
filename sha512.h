#ifndef _SHA512_H
#define _SHA512_H

#include "hash.h"

void sha512_init(hash_t *ctx);
void sha384_init(hash_t *ctx);
void sha512_128(const uint8_t* msg, hash_t* ctx);
void sha512_calc(const uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx);
char* sha512_hexout(char *buf, const hash_t* ctx);
char* sha384_hexout(char *buf, const hash_t* ctx);
unsigned char* sha512_beout(unsigned char *buf, const hash_t* ctx);
unsigned char* sha384_beout(unsigned char *buf, const hash_t* ctx);

#endif
