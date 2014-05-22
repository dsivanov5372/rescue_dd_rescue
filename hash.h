#ifndef _HASH_H
#define _HASH_H

#include <stdint.h>

#ifdef __GNUC__
#define ALIGNED(x) __attribute__((aligned(x)))
#else
#define ALIGNED(x)
#endif


typedef struct {
	union {
		uint32_t md5_h[4];
		uint32_t sha256_h[8];
		uint64_t sha512_h[8];
	};
} hash_t ALIGNED(32);

#endif
