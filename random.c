/** Generate good random numbers ...
 * Get them from the OS if possible
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 10/2014
 * License: GPL v2 or v3
 */

#include "random.h"
#include <time.h>
#include <sys/time.h>

#if (defined(__x86_64__) || defined(__i386__)) && !defined(NO_RDRND)
unsigned int rdrand32();
#else
#define BSWAP32(x) ((x<<24) | ((x<<8)&0x00ff0000) | ((x>>8)&0x0000ff00) | (x>>24))
#endif

unsigned int random_getseedval32()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
#if (defined(__x86_64__) || defined(__i386__)) && !defined(NO_RDRND)
	unsigned int hwrnd = rdrand32();
#else
	unsigned int hwrnd = BSWAP32((unsigned int)(unsigned long)&frandom_getseedval);
#endif
	return (tv.tv_usec << 12) ^ tv.tv_sec ^ getpid() ^ hwrnd;
}

/* TODO: Functions to generate N bytes of good or really good random numbers */

