#ifndef _SHA256_H
#define _SHA256_H

#include "hash.h"

void sha256_init(hash_t *ctx);
void sha224_init(hash_t *ctx);
void sha256_64(const uint8_t* msg, hash_t* ctx);
void sha256_calc(uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx);
char* sha256_out(char *buf, const hash_t* ctx);
char* sha224_out(char *buf, const hash_t* ctx);

#endif
