/*
 * Simple MD5 implementation
 * Source: http://en.wikipedia.org/wiki/MD5
 * Copyright: CC-BY-SA 3.0 / GFDL
 *
 * Compile with: gcc -o md5 md5.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>
 
// Constants are the integer part of the sines of integers (in radians) * 2^32.
static const uint32_t k[64] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
// r specifies the per-round shift amounts
static const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
 
// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline void to_bytes(uint32_t val, uint8_t *bytes)
{
	*(uint32_t*)bytes = val;
}
static inline uint32_t to_int32(const uint8_t *bytes)
{
	return *(const uint32_t*)bytes;
}
#else
/* Store val into bytes in little endian fmt */
static inline void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}
 
/* Read val from little-endian array */
static inline uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
        | ((uint32_t) bytes[1] << 8)
        | ((uint32_t) bytes[2] << 16)
        | ((uint32_t) bytes[3] << 24);
}
#endif

typedef struct _md5_ctx {
	uint32_t h0, h1, h2, h3;
} md5_ctx __attribute__((aligned(16)));

void md5_64(uint8_t *ptr, md5_ctx* ctx)
{
	uint32_t _a, _b, _c, _d;
	unsigned int i;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t *w = (uint32_t*)ptr;
#ifdef HAVE___BUILTIN_PREFETCH
	__builtin_prefetch(ptr, 0, 3);
	//__builtin_prefetch(ptr+32, 0, 3);
#endif
#else
	uint32_t w[16];
        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(ptr + i*4);
#endif
 
        // Initialize hash value for this chunk:
        _a = ctx->h0; _b = ctx->h1; _c = ctx->h2; _d = ctx->h3;

        // Main loop:
        for(i = 0; i<64; i++) {
	    uint32_t temp, f, g;
            if (i < 16) {
                f = (_b & _c) | ((~_b) & _d);
                g = i;
            } else if (i < 32) {
                f = (_d & _b) | ((~_d) & _c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = _b ^ _c ^ _d;
                g = (3*i + 5) % 16;          
            } else {
                f = _c ^ (_b | (~_d));
                g = (7*i) % 16;
            }
 
	    temp = _d;
            _d = _c;
            _c = _b;
            _b = _b + LEFTROTATE((_a + f + k[i] + w[g]), r[i]);
            _a = temp;
        }
 
        // Add this chunk's hash to result so far:
        ctx->h0 += _a;
        ctx->h1 += _b;
        ctx->h2 += _c;
        ctx->h3 += _d;
}

void init_ctx(md5_ctx* ctx)
{
	ctx->h0 = 0x67452301; 
	ctx->h1 = 0xefcdab89; 
	ctx->h2 = 0x98badcfe; 
	ctx->h3 = 0x10325476;
}

/* We assume we have a few bytes behind ln  ... */
void calc_md5(uint8_t *ptr, size_t chunk_ln, size_t final_len, md5_ctx* ctx)
{
	if (final_len) {
		ptr[chunk_ln] = 0x80;
		int i;
		for (i = chunk_ln+1; i%64 != 56; ++i)
			ptr[i] = 0;
		to_bytes(final_len*8, ptr+i);
		to_bytes(final_len>>29, ptr+i+4);
		chunk_ln = i+8;
	} 
	if (chunk_ln % 64)
		abort();
	uint32_t offset;
	for (offset = 0; offset < chunk_ln; offset += 64) 
		md5_64(ptr+offset, ctx);
}

void md5_result(md5_ctx *ctx, uint8_t* digest)
{	
    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(ctx->h0, digest);
    to_bytes(ctx->h1, digest + 4);
    to_bytes(ctx->h2, digest + 8);
    to_bytes(ctx->h3, digest + 12);
}

#ifdef MD5_MAIN
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define BUFSIZE 16384
int main(int argc, char **argv) 
{
    int i;
    uint8_t result[16];
    md5_ctx ctx;
 
    if (argc < 2) {
        printf("usage: %s 'file'\n", argv[0]);
        return 1;
    }

    struct stat stbf;
    if (stat(argv[1], &stbf)) {
	fprintf(stderr, "md5: Can't stat %s: %s\n", argv[1], strerror(errno));
	exit(1);
    }
    size_t len = stbf.st_size;

    uint8_t *obf = malloc(BUFSIZE+128);
    uint8_t *bf = obf;
#if defined(HAVE___BUILTIN_PREFETCH) && !defined(NO_ALIGN)
    bf += 63;
    bf -= ((unsigned long)bf % 64);
#endif

    if (!bf) {
	fprintf(stderr, "md5: Failed to allocate buffer of size %i\n", BUFSIZE);
	exit(2);
    }

    int fd = 0;
    if (strcmp(argv[1], "-"))
	fd = open(argv[1], O_RDONLY);

    if (fd < 0) {
	fprintf(stderr, "md5: Failed to open %s for reading: %s\n",
		argv[1], strerror(errno));
	free(bf);
	exit(3);
    }

#ifdef BENCH
    for (i = 0; i < 10000; ++i) {
#endif
    init_ctx(&ctx);
    while (1) {
	ssize_t rd = read(fd, bf, BUFSIZE);
	if (rd == 0) {
		calc_md5(bf, 0, len, &ctx);
		break;
	}
	if (rd < 0) {
		fprintf(stderr, "md5: Error reading %s: %s\n",
			argv[1], strerror(errno));
		free(bf);
		exit(4);
	}
	if (rd < BUFSIZE) {
		calc_md5(bf, rd, len, &ctx);
		break;
	} else
		calc_md5(bf, BUFSIZE, 0, &ctx);
    }

    md5_result(&ctx, result);
#ifdef BENCH
    lseek(fd, 0, SEEK_SET);
    }
#endif
    if (fd)
	close(fd);
    free(obf);

    // display result
    for (i = 0; i < 16; i++)
        printf("%2.2x", result[i]);
    printf("  %s\n", argv[1]);
 
    return 0;
}
#endif