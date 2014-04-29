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
	unsigned char **bufp;
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
			ddr_plug.fplog(stderr, FATAL, "MD5: plugin doesn't understand param %s\n",
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
	     loff_t exfer, int olnchg, 
	     unsigned int totslack_pre, unsigned int totslack_post,
	     unsigned char **bufp, void **stat)
{
	md5_state *state = (md5_state*)malloc(sizeof(md5_state));
	*stat = (void*)state;
	md5_init(&state->md5);
	state->first_ooff = ooff;
	state->md5_pos = 0;
	state->onm = onm;
	memset(state->buf, 0, 128);
	state->buflen = 0;
	state->bufp = bufp;
	/* breaks direct io -- set slackspace to 4096+64 and increase buf by 4096 to fix */
	*bufp += 64;
	return 0;
}

void md5_last(md5_state *state, loff_t ooff)
{
	//md5_block(0, 0, ooff, stat);
	loff_t len = ooff - state->first_ooff;
	int left = len - state->md5_pos;
	assert(state->buflen == left);
	/*
	fprintf(stderr, "DEBUG: %s: len=%li, md5pos=%li\n", 
		state->onm, len, state->md5_pos);
	 */
	//ddr_plug.fplog(stderr, INFO, "MD5: Last block with %i bytes\n", left);
	md5_calc(state->buf, left, len, &state->md5);
	state->md5_pos += left;
}

#define MIN(a,b) ((a)<(b)? (a): (b))

/* This is rather complex, as we handle both non-aligned first block size
 * as well as sparse files */
unsigned char* md5_block(unsigned char* bf, int *towr, 
			 int eof, loff_t ooff, void **stat)
{
	md5_state *state = (md5_state*)*stat;
	const loff_t opos = ooff - state->first_ooff;
	int consumed = 0;
	/* First block */
	assert(bf);
	if (state->buflen) {
		/* Handle leftover bytes ... */
		if (opos > state->md5_pos+state->buflen) {
			/* First sparse piece  ... */
			memset(state->buf+state->buflen, 0, 64-state->buflen);
			md5_64(state->buf, &state->md5);
			state->md5_pos += 64;
			memset(state->buf, 0, state->buflen);
			state->buflen = 0;
		} else if (*towr) {
			/* Reassemble and process first block */
			consumed = MIN(64-state->buflen, *towr);
			//ddr_plug.fplog(stderr, INFO, "MD5: Append %i bytes @ %i to store\n", consumed, ooff);
			memcpy(state->buf+state->buflen, bf, consumed);
			if (consumed+state->buflen == 64) {
				md5_64(state->buf, &state->md5);
				state->md5_pos += 64;
				memset(state->buf, 0, 64);
				state->buflen = 0;
			} else 
				state->buflen += consumed;
		}
	}
	assert(state->md5_pos <= opos + consumed);
	/* Bulk sparse process */
	while (opos > state->md5_pos+63) {
		assert(state->buflen == 0);
		md5_64(state->buf, &state->md5);
		state->md5_pos += 64;
	}
	/* Last sparse block */
	int left = opos - state->md5_pos;
	if (left > 0 && *towr >= left) {
		assert(consumed == 0);
		memcpy(state->buf+64-left, bf, left);
		md5_64(state->buf, &state->md5);
		state->md5_pos += 64;
		state->buflen = 0;
		consumed = left;
		memset(state->buf+64-left, 0, left);
	}
	/* Bulk buffer process */
	int mylen = *towr - consumed; 
	assert(mylen >= 0);
	mylen -= mylen%64;
	if (mylen) {
		//ddr_plug.fplog(stderr, INFO, "MD5: Consume %i bytes @ %i\n", mylen, ooff+consumed);
		md5_calc(bf+consumed, mylen, 0, &state->md5);
		consumed += mylen; state->md5_pos += mylen;
	}
	/* Copy remainder into buffer */
	assert(state->md5_pos + state->buflen == opos + consumed);
	if (*towr - consumed) {
		assert(state->buflen+*towr-consumed < 64);
		//ddr_plug.fplog(stderr, INFO, "MD5: Store %i bytes @ %i\n", *towr-consumed, ooff+consumed);
		memcpy(state->buf+state->buflen, bf+consumed, *towr-consumed);
		state->buflen += *towr-consumed;
	}
	if (eof)
		md5_last(state, ooff+*towr);
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
	.slack_pre = 64,
	.slack_post = 64,
	.needs_align = 0,
	.handles_sparse = 1,
	.init_callback  = md5_plug_init,
	.open_callback  = md5_open,
	.block_callback = md5_block,
	.close_callback = md5_close,
};


