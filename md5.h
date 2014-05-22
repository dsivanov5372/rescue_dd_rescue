#ifndef _MD5_H
#define _MD5_H

#include <stdint.h>
#include <sys/types.h>
#include "hash.h"
#include <string.h>

#define MD5_BLKSZ 64

typedef struct _md5_ctx {
	uint32_t h[4];
} md5_ctx;

void md5_init(md5_ctx* ctx);
void md5_64(const uint8_t *ptr, md5_ctx* ctx);
void md5_calc(uint8_t *ptr, size_t chunk_ln, size_t final_ln, md5_ctx* ctx);
char* md5_out(char *buf, const md5_ctx* ctx);

static inline void gen_md5_init(hash_t *hash)
{
	md5_init((md5_ctx*)hash);
	memset((uint8_t*)hash + sizeof(md5_ctx), 0, sizeof(hash)-sizeof(md5_ctx));
}

static inline void gen_md5_64(const uint8_t *ptr, hash_t *hash)
{
	md5_64(ptr, (md5_ctx*)hash);
}

static inline void gen_md5_calc(uint8_t *ptr, size_t chunk_ln, size_t final_ln, hash_t *hash)
{
	md5_calc(ptr, chunk_ln, final_ln, (md5_ctx*)hash);
}

char* gen_md5_out(char* buf, const hash_t *hash)
{
	return md5_out(buf, (const md5_ctx*)hash); 
}

#endif

