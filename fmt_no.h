/** Decl for int to str conversion with highlighting */

#ifndef _FMT_NO_H
#define _FMT_NO_H

#include <sys/types.h>
char* fmt_int_b(unsigned char pre, unsigned char post, unsigned int scale,
	       	loff_t no, const char* bold, const char* norm, 
		const char leadbold, const unsigned char base,
		const unsigned char group);
inline 
char* fmt_int(unsigned char pre, unsigned char post, unsigned int scale,
	       	loff_t no, const char* bold, const char* norm, const char leadbold)
{ 
	return fmt_int_b(pre, post, scale, no, bold, norm, leadbold, 10, 3);
}

#endif

