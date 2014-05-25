/* libddr_null.c
 *
 * plugin for dd_rescue, doing nothing (except optionally setting changes_length)
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPLv2 or v3
 */

#include "ddr_plugin.h"
#include "ddr_ctrl.h"
#include <string.h>
#include <stdlib.h>

/* fwd decl */
extern ddr_plugin_t ddr_plug;

typedef struct _null_state {
	int seq;
	char debug;
} null_state;

#define FPLOG(lvl, fmt, args...) \
	ddr_plug.fplog(stderr, lvl, "%s(%i): " fmt, ddr_plug.name, state->seq, ##args)

const char* null_help = "The null plugin does nothing ...\n"
			"Options: lnchange indicates that the length may be changed by null\n"
			" (which is not true, but influences the behavior of the hash plugin\n";

int null_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	null_state *state = (null_state*)malloc(sizeof(null_state));
	*stat = (void*)state;
	memset(state, 0, sizeof(null_state));
	state->seq = seq;
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			FPLOG(INFO, "%s", null_help);
		if (!strcmp(param, "lnchange"))
			ddr_plug.changes_output_len = 1;
		if (!strcmp(param, "lenchange"))
			ddr_plug.changes_output_len = 1;
		if (!strcmp(param, "lnchg"))
			ddr_plug.changes_output_len = 1;
		/* Do we need this if loaded multiple times? */
		if (!strcmp(param, "nolnchange"))
			ddr_plug.changes_output_len = 0;
		if (!strcmp(param, "debug"))
			state->debug = 1;
		else {
			FPLOG(FATAL, "plugin doesn't understand param %s\n",
				param);
			return 1;

		}
	}
	return 0;
}

int null_open(const opt_t *opt, int ilnchg, int olnchg,
	      unsigned int totslack_pre, unsigned int totslack_post,
	      void **stat)
{
	return 0;
}

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif


unsigned char* null_blk_cb(fstate_t *fst, unsigned char* bf, 
			   int *towr, int eof, int *recall, void **stat)
{
	/* TODO: Could actually add debugging output here if wanted ... */
	null_state *state = (null_state*)*stat;
	if (state->debug) 
		FPLOG(DEBUG, "Block ipos %" LL "i opos %" LL "i with %i bytes %s\n",
			fst->ipos, fst->opos, *towr, (eof? "EOF": ""));
	return bf;
}

int null_close(loff_t ooff, void **stat)
{
	//null_state *state = (null_state*)*stat;
	free(*stat);
	return 0;
}

ddr_plugin_t ddr_plug = {
	.name = "null",
	.needs_align = 0,
	.handles_sparse = 1,
	.init_callback  = null_plug_init,
	.open_callback  = null_open,
	.block_callback = null_blk_cb,
	.close_callback = null_close,
};


