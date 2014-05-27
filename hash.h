#ifndef _HASH_H
#define _HASH_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <sys/types.h>

#ifdef __GNUC__
#define ALIGNED(x) __attribute__((aligned(x)))
#else
#define ALIGNED(x)
#endif


typedef struct {
	union {
		uint32_t md5_h[4];
		uint32_t sha1_h[5];
		uint32_t sha256_h[8];
		uint64_t sha512_h[8];
		//uint64_t sha3_h[25];
	};
} hash_t ALIGNED(32);

#endif
