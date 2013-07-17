#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include "find_nonzero.h"

#define SIZE (64*1024*1024)

#define TEST(sz,routine,rep) 		\
	memset(buf, 0, sz);		\
	gettimeofday(&t1, NULL);	\
	for (i = 0; i < rep; ++i)	\
		ln = routine(buf, SIZE);\
	gettimeofday(&t2, NULL);	\
	printf("%5i x %18s (%8i): %.3fs => %8i\n",\
		rep, #routine, sz,	\
		t2.tv_sec-t1.tv_sec+0.000001*(t2.tv_usec-t1.tv_usec), ln)


#if defined(__SSE2__) && !defined(NO_SSE2)
#define TEST_SSE(a,b,c) TEST(a,b,c)
#else
#define TEST_SSE(a,b,c) do {} while (0)
#endif

int main()
{
	unsigned char* buf = (unsigned char*)malloc(SIZE);
	struct timeval t1, t2;
	int i, ln;
	memset(buf, 0xa5, SIZE);
	TEST(1024*1024, find_nonzero_c, 2048);
	TEST_SSE(1024*1024, find_nonzero_sse2, 2048);
	TEST(1024*1024+3, find_nonzero_c, 2048);
	TEST_SSE(1024*1024+3, find_nonzero_sse2, 2048);
	TEST(1024*1024+6, find_nonzero_c, 2048);
	TEST_SSE(1024*1024+6, find_nonzero_sse2, 2048);
	TEST(1024*1024+9, find_nonzero_c, 2048);
	TEST_SSE(1024*1024+9, find_nonzero_sse2, 2048);
	TEST(1024*1024+16, find_nonzero_c, 2048);
	TEST_SSE(1024*1024+16, find_nonzero_sse2, 2048);

	TEST(16*1024*1024, find_nonzero_c, 128);
	TEST_SSE(16*1024*1024, find_nonzero_sse2, 128);

	TEST(64*1024*1024, find_nonzero_c, 32);
	TEST_SSE(64*1024*1024, find_nonzero_sse2, 32);

	free(buf);
}

