#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>>
#include "find_nonzero.h"

#define SIZE (64*1024*1024)

#define TEST(sz,routine,rep) 		\
	memset(buf, 0, sz);		\
	gettimeofday(&t1, NULL);	\
	for (int i = 0; i < rep; ++i)	\
		ln = routine(buf, SIZE);\
	gettimeofday(&t1, NULL);	\
	printf("%i x %s: %.3fs => %i\n",\
		rep, ##routine,		\
		t2.sec-t1-sec+0.000001*(t2.usec-t1.usec),	\
		ln)



int main()
{
	unsigned char* buf = malloc(SIZE);
	struct timeval t1, t2;
	int ln;


	free(buf);
}

