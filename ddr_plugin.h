/** ddr_plugin.h
 *
 * Data structure to register dd_rescue plugins
 */

#ifndef _DDR_PLUGIN_H
#define _DDR_PLUGIN_H

#include <sys/types.h>

typedef int (_open_callback)(int ifd, const char* inm, loff_t ioff, 
			     int ofd, const char* onm, loff_t ooff, 
			     unsigned int bsz, unsigned int hsz,
			     loff_t exfer, void **stat);
typedef unsigned char* (_block_callback)(unsigned char* bf, int *towr, 
				         loff_t ooff, void **stat);
typedef int (_close_callback)(loff_t ooff, void **stat);

typedef struct _ddr_plugin {
	const char* name;
	void* state;
	 _open_callback * open_callback;
	_block_callback *block_callback;
	_close_callback *close_callback;
} ddr_plugin_t;
#endif	/* _DDR_PLUGIN_H */
