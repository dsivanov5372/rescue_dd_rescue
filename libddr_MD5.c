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

typedef struct _md5_state {
	md5_ctx md5;
	loff_t first_ooff;
} md5_state;

int md5_open(int ifd, const char* inm, loff_t ioff, 
	     int ofd, const char* onm, loff_t ooff, 
	     unsigned int bsz, unsigned int hsz,
	     loff_t exfer, void **stat)
{
	md5_state *state = (md5_state*)malloc(sizeof(md5_state));
	*stat = (void*)state;
	state->first_ooff = ooff;
	md5_init(&state->md5);
	return 0;
}

ddr_plugin_t plug = {
	.name = "MD5",
	.slackspace = 64,
	.open_callback = md5_open
};


