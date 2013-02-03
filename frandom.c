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
#include <asm/errno.h>
#include <unistd.h>
#include <time.h>

#include "frandom.h"

#if defined(__arm__) /* || ... */
# define INT_IS_FASTER
/* # warning Using INT */
#else
/* # warning Using CHAR */
#endif

typedef unsigned char u8;


struct frandom_state
{
	u8 S[256]; /* The state array */
	u8 i, j;        
};

static struct frandom_state *int_random_state;

static inline void swap_byte(u8 *a, u8 *b)
{
	const u8 swapByte = *a; 
	*a = *b;      
	*b = swapByte;
}

static inline void swap_byte_notmp(u8 *a, u8 *b)
{
	*a -= *b;
	*b += *a;
	*a  = *b - *a;
}


void init_rand_state(struct frandom_state *state, u8* seedbf)
{
	unsigned int k;
	unsigned char i, j;
	u8 *S;
	S = state->S;
	for (k=0; k<256; ++k)
		*S++ = k;

	j = 0;
	S = state->S;

	for (k=0; k<256; ++k) {
		j = (j + S[k] + seedbf[k]) & 0xff;
		swap_byte(&S[k], &S[j]);
	}

	/* It's considered good practice to discard the first 256 bytes
	   generated. So we do it:
	*/

	i = 0; j = 0;
	for (k=0; k<256; ++k) {
		i = (i + 1);
		j = (j + S[i]);
		swap_byte(&S[i], &S[j]);
	}

	state->i = i; /* Save state */
	state->j = j;
}

void* frandom_init(unsigned char* seedbf)
{
	struct frandom_state *state;

	state = malloc(sizeof(struct frandom_state));
	if (!state)
		return NULL;

	init_rand_state(state, seedbf);
	if (!int_random_state)
		int_random_state = state;

	return state; /* Success */
}

static void get_libc_rand_bytes(u8 *buf, size_t len)
{
	int *lbuf = (int*)buf;
	int i;
	for (i = 0; i < len/sizeof(int); ++i)
		lbuf[i] = rand();
}

void* frandom_init_lrand(int seedval)
{
	u8 seedbuf[256];

	if (!seedval)
		seedval = time(0) - getpid();
	srand(seedval);
	get_libc_rand_bytes(seedbuf, 256);
	return frandom_init(seedbuf);
}

int frandom_release(void* rstate)
{
	struct frandom_state *state = rstate;
	if (!state)
		state = int_random_state;	
	if (!state)
		return -ENOMEM;

	free(state);
	if (state == int_random_state)
		int_random_state = 0;
	return 0;
}

ssize_t get_frandom_bytes(void *rstate, char *buf, size_t count)
{
	struct frandom_state *state = rstate;
	u8 *S;
#ifdef INT_IS_FASTER
	unsigned int i, j;
#else
	unsigned char i, j;
#endif
	const ssize_t ret = count;

	if (!state)
		state = int_random_state;
	if (!state)
		state = frandom_init_lrand(0);
  
	i = state->i;
	j = state->j;
	S = state->S;  

	while (count--) {
#ifdef INT_IS_FASTER
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		swap_byte(&S[i], &S[j]);
		*buf++ = S[(S[i] + S[j]) & 0xff];
#else
		i = i + 1;
		j = j + S[i];
		swap_byte(&S[i], &S[j]);
		*buf++ = S[(unsigned char)(S[i] + S[j])];
#endif
	}

	state->i = i;     
	state->j = j;

	return ret;
}



