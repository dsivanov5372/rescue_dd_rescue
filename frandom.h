/* Header file for frandom.c */

#ifndef _FRANDOM_H
#define _FRANDOM_H

#include <sys/types.h>

/* frandom.c */
ssize_t get_frandom_bytes(void *rstate, char *buf, size_t count);
int frandom_release(void* rstate);
void* frandom_init_lrand(int seedval);
void* frandom_init(unsigned char* seedbf);

#endif
