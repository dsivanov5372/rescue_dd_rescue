/** ddr_plugin.h
 *
 * Data structure to register dd_rescue plugins
 */

#ifndef _DDR_PLUGIN_H
#define _DDR_PLUGIN_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>


typedef int (_init_callback)(void **stat, char* param);
/** open_calback parameters: input file descriptor, input file name,
 * 	initial offset input file, same 3 params for output file,
 * 	soft (large) block size, hard (fallback) block size,
 * 	estimated xfer size, opaque handle
 */
typedef int (_open_callback)(int ifd, const char* inm, loff_t ioff, 
			     int ofd, const char* onm, loff_t ooff, 
			     unsigned int bsz, unsigned int hsz,
			     loff_t exfer, void **stat);
typedef unsigned char* (_block_callback)(unsigned char* bf, int *towr, 
				         loff_t ooff, void **stat);
typedef int (_close_callback)(loff_t *ooff, void **stat);

enum ddrlog_t { NOHDR=0, INFO, WARN, FATAL };
typedef int (_fplog_callback)(FILE* const f, enum ddrlog_t logpre, 
				const char* const fmt, ...);

typedef struct _ddr_plugin {
	/* Name of the plugin -- will be filled by loader if left empty */
	const char* name;
	/* Amount of extra bytes required in buffer */
	size_t slackspace;
	/* Alignment need */
	unsigned int needs_align;
	/* Handles sparse */
	char handles_sparse;
	/* Internal individual state of plugin */
	void* state;
	/* Will be called after loading the plugin */
	 _init_callback * init_callback;
	/* Will be called after opening the input and output files */
	 _open_callback * open_callback;
	/* Will be called before a block is written */
	_block_callback *block_callback;
	/* Will be called before fsyncing and closing the output file */
	_close_callback *close_callback;
	/* Callback filled by the loader: Logging */
	_fplog_callback *fplog;
	/* Filled by loader: Parameters */
	char* param;
} ddr_plugin_t;
#endif	/* _DDR_PLUGIN_H */
