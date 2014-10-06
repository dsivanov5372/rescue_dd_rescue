/** Generate good random numbers ...
 * Get them from the OS if possible
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 10/2014
 * License: GPL v2 or v3
 */

#include "random.h"
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>

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
	unsigned int hwrnd = BSWAP32((unsigned int)(unsigned long)&random_getseedval32);
#endif
	return (tv.tv_usec << 12) ^ tv.tv_sec ^ getpid() ^ hwrnd;
}

/* Functions to generate N bytes of good or really good random numbers
 * Notes: -We use /dev/random or /dev/urandom which works on Linux, but not everywhere
 * 	(TODO: make more portable)
 * - We mix in the bytes from the libc rand() function, not because it really adds 
 *   entropy, but to make observation from the outside (think hypervisors ...) a bit
 *   harder.
 */
unsigned int random_bytes(unsigned char* buf, unsigned int ln, unsigned char nourand)
{
	const char* rdfnm = (nourand? "/dev/random": "/dev/urandom");
	srand(random_getseedval32());
	rand();
	int fd = open(rdfnm, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "FATAL: Can't open %s for random numbers\n", rdfnm);
		raise(SIGQUIT);
	}
	unsigned i;
	for (i = 0; i < (ln+3)/4; ++i) {
		unsigned int rnd;
		if (read(fd, &rnd, 4) != 4) {
			fprintf(stderr, "FATAL: Short read on %s\n", rdfnm);
			raise(SIGQUIT);
		}
		rnd ^= rand();
		if (4*i+3 < ln)
			((unsigned int*)buf)[i] = rnd;
		else
			memcpy(buf+4*i, &rnd, ln-4*i);
	}
	close(fd);
	return ln;
}

