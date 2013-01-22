/*
** frandom.c
**      Fast pseudo-random generator 
**
**      (c) Copyright 2003-2011 Eli Billauer
**      http://www.billauer.co.il
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
**
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <asm/errno.h>
#include <unistd.h>
#include <time.h>

#define INTERNAL_SEED 0
#define EXTERNAL_SEED 1

typedef unsigned char u8;

static int frandom_bufsize = 256;
static int frandom_chunklimit = 0; /* =0 means unlimited */


struct frandom_state
{
	u8 S[256]; /* The state array */
	u8 i;        
	u8 j;

	char *buf;
};

static struct frandom_state *erandom_state;

static inline void swap_byte(u8 *a, u8 *b)
{
	u8 swapByte; 
  
	swapByte = *a; 
	*a = *b;      
	*b = swapByte;
}

static void get_random_bytes(char *buf, size_t len)
{
	int i;
	int *lbuf = (int*)buf;
	for (i = 0; i < len/sizeof(int); ++i)
		lbuf[i] = rand();
}


static void init_rand_state(struct frandom_state *state, int seedval)
{
	unsigned int i, j, k;
	u8 *S;
	char *seed = state->buf;

	if (!seedval)
		seedval = time(0) - getpid();
	srand(seedval);
	get_random_bytes(seed, 256);

	S = state->S;
	for (i=0; i<256; i++)
		*S++=i;

	j=0;
	S = state->S;

	for (i=0; i<256; i++) {
		j = (j + S[i] + *seed++) & 0xff;
		swap_byte(&S[i], &S[j]);
	}

	/* It's considered good practice to discard the first 256 bytes
	   generated. So we do it:
	*/

	i=0; j=0;
	for (k=0; k<256; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		swap_byte(&S[i], &S[j]);
	}

	state->i = i; /* Save state */
	state->j = j;
}

int frandom_init(int seed)
{
  
	struct frandom_state *state;

	state = malloc(sizeof(struct frandom_state));
	if (!state)
		return -ENOMEM;

	state->buf = malloc(frandom_bufsize);
	if (!state->buf) {
		free(state);
		return -ENOMEM;
	}

	init_rand_state(state, EXTERNAL_SEED);
	erandom_state = state;

	return 0; /* Success */
}

int frandom_release()
{

	struct frandom_state *state = erandom_state;
	if (!state)
		return -ENOMEM;

	free(state->buf);
	free(state);
  
	return 0;
}

ssize_t get_frandom_bytes(char *buf, size_t count)
{
	struct frandom_state *state = erandom_state;
	ssize_t ret;
	int dobytes, k;
	char *localbuf;

	unsigned int i;
	unsigned int j;
	u8 *S;

	if (!state)
		frandom_init(0);		
  
	if ((frandom_chunklimit > 0) && (count > frandom_chunklimit))
		count = frandom_chunklimit;

	ret = count; /* It's either everything or an error... */
  
	i = state->i;
	j = state->j;
	S = state->S;  

	while (count) {
		if (count > frandom_bufsize)
			dobytes = frandom_bufsize;
		else
			dobytes = count;

		localbuf = state->buf;

		for (k=0; k<dobytes; k++) {
			i = (i + 1) & 0xff;
			j = (j + S[i]) & 0xff;
			swap_byte(&S[i], &S[j]);
			*localbuf++ = S[(S[i] + S[j]) & 0xff];
		}
 
		if (memcpy(buf, state->buf, dobytes)) {
			ret = -EFAULT;
			goto out;
		}

		buf += dobytes;
		count -= dobytes;
	}

 out:
	state->i = i;     
	state->j = j;

	return ret;
}



