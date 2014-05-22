#ifndef _SHA512_H
#define _SHA512_H

#include "hash.h"

void sha512_init(hash_t *ctx);
void sha512_64(const uint8_t* msg, hash_t* ctx);
void sha512_calc(uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx);
char* sha512_out(char *buf, const hash_t* ctx);

#endif
