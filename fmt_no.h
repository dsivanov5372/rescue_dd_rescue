/** Decl for int to str conversion with highlighting */

#ifndef _FMT_NO_H
#define _FMT_NO_H
#include <sys/types.h>
char* fmt_int(unsigned char pre, unsigned char post, unsigned int scale, 
	      off_t no, const char* bold, const char* norm, int leadbold);

#endif

