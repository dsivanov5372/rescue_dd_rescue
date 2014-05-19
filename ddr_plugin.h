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

//#include "ddr_ctrl.h"
typedef struct _opt_t opt_t;
typedef struct _fstate_t fstate_t;
typedef struct _progress_t progress_t;

/** init callback parameters:
 * opaque handle, parameters from commandline, sequece in filter chain
 */
typedef int (_init_callback)(void **stat, char* param, int seq, const opt_t *opt);
/** open_callback parameters: input file descriptor, input file name,
 * 	initial offset input file, same 3 params for output file,
 * 	soft (large) block size, hard (fallback) block size,
 * 	estimated xfer size, flag that olen will change after writing,
 *	total slack size for all plugins,
 *	ptr to buffer ptr, opaque handle.
 * 	Return value: 0 = OK, -x = ERROR, +x = Bytes consumed from input file.
 */
typedef int (_open_callback)(const opt_t *opt, int ilnchange, int olnchange, 
			     unsigned int totslack_pre, unsigned int totslack_post,
			     void **stat);
/** block_callback parameters: file state (contains file descriptors, positions,
 * 	...), buffer to be written (can be modified),
 *  	number of bytes to be written (can be null and can be modified), 
 *  	eof flag, recall request(output!), handle.
 *  Will be called with eof=1 exactly once at the end.
 *  Return value: buffer to be really written.
 */
typedef unsigned char* (_block_callback)(fstate_t *fst, unsigned char* bf, 
					 int *towr, int eof, int *recall, 
					 void **stat);
/** close_callback parameters: final output position and handle.
 * Return value: 0 = OK, -x = ERROR
 * close_callback is called before files are fsynced and closed
 */
typedef int (_close_callback)(loff_t ooff, void **stat);

enum ddrlog_t { NOHDR=0, DEBUG, INFO, WARN, FATAL };
typedef int (_fplog_upcall)(FILE* const f, enum ddrlog_t logpre, 
			    const char* const fmt, ...);

typedef struct _ddr_plugin {
	/* Name of the plugin -- will be filled by loader if left empty */
	const char* name;
	/* Amount of extra bytes required in buffer, negative => softbs*slackspace/16 */
	int slack_pre;
	int slack_post;
	/* Alignment need */
	unsigned int needs_align;
	/* Handles sparse */
	char handles_sparse;
	/* Transforms output */
	char changes_output;
	/* Output transformation changes length -- breaks sparse detection on subsequent plugins */
	char changes_output_len;
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
	_fplog_upcall *fplog;
	/* Filled by loader: Parameters */
	char* param;
} ddr_plugin_t;
#endif	/* _DDR_PLUGIN_H */
