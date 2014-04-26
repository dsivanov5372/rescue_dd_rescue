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
#include <string.h>
#include <assert.h>

/* fwd decl */
ddr_plugin_t ddr_plug;

typedef struct _md5_state {
	md5_ctx md5;
	loff_t first_ooff;
	loff_t md5_pos;
	const char* onm;
	uint8_t buf[128];
	unsigned char buflen;
} md5_state;

char *md5_help = "The MD5 plugin for dd_rescue calculates the md5sum on the fly.\n"
		" It supports unaligned blocks (arbitrary offsets) and sparse writing.\n"
		" Parameters: None\n";

int md5_plug_init(void **stat, char* param)
{
	int err = 0;
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			ddr_plug.fplog(stderr, INFO, "%s", md5_help);
		/* elif .... */
		else {
			ddr_plug.fplog(stderr, FATAL, "MD5 plugin doesn't understand param %s\n",
				param);
			++err;
		}
		param = next;
	}
	return err;
}

int md5_open(int ifd, const char* inm, loff_t ioff, 
	     int ofd, const char* onm, loff_t ooff, 
	     unsigned int bsz, unsigned int hsz,
	     loff_t exfer, void **stat)
{
	md5_state *state = (md5_state*)malloc(sizeof(md5_state));
	*stat = (void*)state;
	md5_init(&state->md5);
	state->first_ooff = ooff;
	state->md5_pos = 0;
	state->onm = onm;
	memset(state->buf, 0, 128);
	state->buflen = 0;
	return 0;
}

void md5_last(md5_state *state, loff_t ooff)
{
	//md5_block(0, 0, ooff, stat);
	loff_t len = ooff - state->first_ooff;
	int left = len - state->md5_pos;
	/*
	fprintf(stderr, "DEBUG: %s: len=%li, md5pos=%li\n", 
		state->onm, len, state->md5_pos);
	 */
	md5_calc(state->buf, left, len, &state->md5);
	state->md5_pos += left;
}

/* This is rather complex, as we handle both non-aligned first block size
 * as well as sparse files */
unsigned char* md5_block(unsigned char* bf, int *towr, 
			 int eof, loff_t ooff, void **stat)
{
	md5_state *state = (md5_state*)*stat;
	int off = 0;
	/* First block */
	if (state->buflen) {
		/* Handle leftover bytes ... */
		if (ooff-state->first_ooff > state->md5_pos+state->buflen) {
			/* Sparse: We have skipped writes ... */
			memset(state->buf+state->buflen, 0, 64-state->buflen);
			md5_64(state->buf, &state->md5);
			state->md5_pos += 64;
			memset(state->buf, 0, state->buflen);
		} else if (bf) {
			off = 64-state->buflen;
			memcpy(state->buf+state->buflen, bf, off);
			md5_64(state->buf, &state->md5);
			state->md5_pos += 64;
			memset(state->buf, 0, 64);
		}
	}
	assert(state->md5_pos <= ooff+off-state->first_ooff);
	/* Bulk sparse process */
	while (ooff-state->first_ooff > state->md5_pos+63) {
		md5_64(state->buf, &state->md5);
		state->md5_pos += 64;
	}
	if (eof)
		md5_last(state, ooff);
	if (!bf)
		return bf;
	int left = ooff-state->first_ooff - state->md5_pos;
	if (left > 0) {
		memcpy(state->buf+64-left, bf, left);
		md5_64(state->buf, &state->md5);
		state->md5_pos += 64;
		off += left;
		memset(state->buf+64-left, 0, left);
	}
	/* Bulk buffer process */
	int mylen = *towr - off; mylen -= mylen%64;
	md5_calc(bf+off, mylen, 0, &state->md5);
	off += mylen; state->md5_pos += mylen;
	/* Copy remainder into buffer */
	assert(state->md5_pos == ooff + off - state->first_ooff);
	state->buflen = *towr - off;
	if (state->buflen)
		memcpy(state->buf, bf+off, state->buflen);
	return bf;
}



#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif

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
	uint8_t res[16];
	md5_result(&state->md5, res);
	ddr_plug.fplog(stderr, INFO, "md5sum %s (%" LL "i-%" LL "i): %s\n",
		state->onm, state->first_ooff, ooff, md5_out(res));
	free(*stat);
	return 0;
}


ddr_plugin_t ddr_plug = {
	.name = "MD5",
	.slackspace = 0 /*128*/,
	.needs_align = 0,
	.handles_sparse = 1,
	.init_callback  = md5_plug_init,
	.open_callback  = md5_open,
	.block_callback = md5_block,
	.close_callback = md5_close,
};


