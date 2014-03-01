/* libddr_MD5.c
 *
 * plugin for dd_rescue, calculating the md5sum during copying ...
 * A PoC for the plugin infrastructure ...
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPLv2 or v3
 */

#include "ddr_plugin.h"
#include "md5.h"

#include <stdlib.h>

/* fwd decl */
ddr_plugin_t ddr_plug;

typedef struct _md5_state {
	md5_ctx md5;
	loff_t first_ooff;
	const char* onm;
	char closed;
} md5_state;

int md5_open(int ifd, const char* inm, loff_t ioff, 
	     int ofd, const char* onm, loff_t ooff, 
	     unsigned int bsz, unsigned int hsz,
	     loff_t exfer, void **stat)
{
	md5_state *state = (md5_state*)malloc(sizeof(md5_state));
	*stat = (void*)state;
	state->first_ooff = ooff;
	if (ooff % 64)
		ddr_plug.fplog(stderr, WARN, "First block not 64byte aligned, will break\n");
	state->closed = 0;
	state->onm = onm;
	md5_init(&state->md5);
	return 0;
}

unsigned char* md5_block(unsigned char* bf, int *towr, 
			 loff_t ooff, void **stat)
{
	md5_state *state = (md5_state*)*stat;
	/* The initial offset should be 64byte aligned ... */
	if (*towr % 64) {
		md5_calc(bf, *towr, (ooff+*towr-state->first_ooff), &state->md5);
		state->closed = 1;
	} else
		md5_calc(bf, *towr, 0, &state->md5);
	return bf;
}

static char _md5_out_str[36];
char* md5_out(uint8_t* res)
{
	int i;
    	for (i = 0; i < 16; i++)
        	sprintf(_md5_out_str+2*i, "%2.2x", res[i]);
	return _md5_out_str;
}

int md5_close(loff_t ooff, void **stat)
{
	md5_state *state = (md5_state*)*stat;
	if (!state->closed) {
		uint8_t bf[64];
		md5_calc(bf, 0, ooff-state->first_ooff, &state->md5);
		state->closed = 1;
	}
	uint8_t res[16];
	md5_result(&state->md5, res);
	ddr_plug.fplog(stderr, INFO, "md5sum %s (%i bytes): %s\n",
		state->onm, ooff-state->first_ooff, md5_out(res));
	free(*stat);
	return 0;
}


ddr_plugin_t ddr_plug = {
	.name = "MD5",
	.slackspace = 64,
	.open_callback = md5_open,
	.block_callback = md5_block,
	.close_callback = md5_close,
};


