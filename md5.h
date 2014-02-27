#ifndef _MD5_H
#define _MD5_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __GNUC__
#define ALIGNED(x) __attribute__((aligned(x)))
#else
#define ALIGNED(x)
#endif

typedef struct _md5_ctx {
	uint32_t h0, h1, h2, h3;
} md5_ctx ALIGNED(16);

void md5_init(md5_ctx* ctx);
void md5_calc(uint8_t *ptr, size_t chunk_ln, size_t final_len, md5_ctx* ctx);
void md5_result(md5_ctx *ctx, uint8_t* digest);

#endif

