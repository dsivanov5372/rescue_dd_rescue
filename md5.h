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
	uint32_t h[4];
} md5_ctx ALIGNED(16);

void md5_init(md5_ctx* ctx);
void md5_64(const uint8_t *ptr, md5_ctx* ctx);
void md5_calc(uint8_t *ptr, size_t chunk_ln, size_t final_len, md5_ctx* ctx);
char* md5_out(char *buf, const md5_ctx* ctx);

#endif

