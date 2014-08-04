#ifndef _SHA1_H
#define _SHA1_H

#include "hash.h"

void sha1_init(hash_t *ctx);
void sha1_64(const uint8_t* msg, hash_t* ctx);
void sha1_calc(uint8_t *ptr, size_t chunk_ln, size_t final_len, hash_t *ctx);
char* sha1_hexout(char *buf, const hash_t* ctx);
unsigned char* sha1_beout(unsigned char *buf, const hash_t* ctx);

#endif
