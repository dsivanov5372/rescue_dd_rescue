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
#ifdef HAVE_LINUX_RANDOM_H
#include <linux/random.h>
#endif

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

#if defined(HAVE_GETENTROPY) && !defined(HAVE_GETRANDOM)
static int getrandom(void *buf, size_t buflen, unsigned int flags)
{
	/* Problem: We can't differentiate b/w urandom and random(GRND_RANDOM) */
	int err = getentropy(buf, buflen);
	if (err < 0)
		return err;
	else
		return buflen;
}
#define GRND_RANDOM 2
#define HAVE_GETRANDOM 2
#endif

#ifdef HAVE_GETRANDOM 
#define READ_RAND(fd, buf, ln, flg) getrandom(buf, ln, flg)
#define RAND_CLOSE(fd) do {} while(0)
#else
#define READ_RAND(fd, buf, ln, flg) read(fd, buf, ln)
#define RAND_CLOSE(fd) close(fd)
#endif

/* Functions to generate N bytes of good or really good random numbers
 * Notes: 
 * - We use getrandom() and getentropy() if available, otherwise fall back to
 *   	/dev/random or /dev/urandom which works only Linux
 * - We mix in the bytes from the libc rand() function, not because it really adds 
 *   entropy, but to make observation from the outside (think hypervisors ...) a bit
 *   harder. (TODO: Could do better on BSD with arc4random() ... )
 */
unsigned int random_bytes(unsigned char* buf, unsigned int ln, unsigned char nourand)
{
	srand(random_getseedval32());
	rand();
#ifndef HAVE_GETRANDOM
	const char* rdfnm = (nourand? "/dev/random": "/dev/urandom");
	int fd = open(rdfnm, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "FATAL: Can't open %s for random numbers\n", rdfnm);
		raise(SIGQUIT);
	}
#else
	unsigned int flg = nourand? GRND_RANDOM: 0;
#endif
	unsigned i;
	for (i = 0; i < (ln+3)/4; ++i) {
		unsigned int rnd;
		if (READ_RAND(fd, &rnd, 4, flg) != 4) {
			fprintf(stderr, "FATAL: Error getting random numbers\n");
			RAND_CLOSE(fd);
			raise(SIGQUIT);
		}
		rnd ^= rand();
		if (4*i+3 < ln)
			((unsigned int*)buf)[i] = rnd;
		else
			memcpy(buf+4*i, &rnd, ln-4*i);
	}
	RAND_CLOSE(fd);
	return ln;
}

