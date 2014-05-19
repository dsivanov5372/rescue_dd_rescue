/* libddr_MD5.c
 *
 * plugin for dd_rescue, calculating the md5sum during copying ...
 * A PoC for the plugin infrastructure ...
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPLv2 or v3
 */

#include "ddr_plugin.h"
#include "ddr_ctrl.h"
#include "md5.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

// TODO: pass at runtime rather than compile time
#define MD5_DEBUG(x) if (state->debug) x

#define FPLOG(lvl, fmt, args...) \
	ddr_plug.fplog(stderr, lvl, "MD5(%i): " fmt, state->seq, ##args)

/* fwd decl */
extern ddr_plugin_t ddr_plug;

typedef struct _md5_state {
	md5_ctx md5;
	loff_t md5_pos;
	const char* name;
	uint8_t buf[128];
	int seq;
	int outfd;
	unsigned char buflen;
	unsigned char olnchg, debug;
	const opt_t *opts;
} md5_state;

const char *md5_help = "The MD5 plugin for dd_rescue calculates the md5sum on the fly.\n"
		" It supports unaligned blocks (arbitrary offsets) and sparse writing.\n"
		" Parameters: output/outfd=FNO\n";

int md5_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	int err = 0;
	md5_state *state = (md5_state*)malloc(sizeof(md5_state));
	*stat = (void*)state;
	memset(state, 0, sizeof(md5_state));
	state->seq = seq;
	state->opts = opt;
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			FPLOG(INFO, "%s", md5_help);
		else if (!strcmp(param, "debug"))
			state->debug = 1;
		else if (!strcmp(param, "output"))
			state->outfd = 1;
		else if (!memcmp(param, "outfd=", 6))
			state->outfd = atoi(param+6);
		/* elif .... */
		else {
			FPLOG(FATAL, "plugin doesn't understand param %s\n",
				param);
			++err;
		}
		param = next;
	}
	return err;
}

int md5_open(const opt_t *opt, int olnchg,
	     unsigned int totslack_pre, unsigned int totslack_post,
	     void **stat)
{
	md5_state *state = (md5_state*)*stat;
	state->opts = opt;
	md5_init(&state->md5);
	state->md5_pos = 0;
	state->name = (state->seq == 0? opt->iname: opt->oname);
	memset(state->buf, 0, 128);
	state->buflen = 0;
	state->olnchg = olnchg;
	if (olnchg && (state->opts->sparse || !state->opts->nosparse)) {
		FPLOG(WARN, "Size of potential holes may not be correct due to subsequent plugins;\n");
		FPLOG(WARN, " MD5 hash may be miscomputed! Avoid holes (remove -a, specify -A).\n");
	}
	return 0;
}

void md5_last(md5_state *state, loff_t ooff)
{
	//md5_block(0, 0, ooff, stat);
	loff_t len = ooff - state->opts->init_opos;
	int left = len - state->md5_pos;
	assert(state->olnchg || state->buflen == left);
	/*
	fprintf(stderr, "MD5_DEBUG: %s: len=%li, md5pos=%li\n", 
		state->name, len, state->md5_pos);
	 */
	MD5_DEBUG(FPLOG(INFO, "Last block with %i bytes\n", state->buflen));
	md5_calc(state->buf, state->buflen, state->md5_pos+state->buflen, &state->md5);
	state->md5_pos += state->buflen;
}

#define MIN(a,b) ((a)<(b)? (a): (b))

/* This is rather complex, as we handle both non-aligned first block size
 * as well as sparse files */
unsigned char* md5_block(fstate_t *fst, unsigned char* bf, 
			 int *towr, int eof, int *recall, void **stat)
{
	md5_state *state = (md5_state*)*stat;
	const loff_t ooff = fst->opos;
	const loff_t opos = state->olnchg? fst->ipos-state->opts->init_ipos : ooff-state->opts->init_opos;
	int consumed = 0;
	assert(bf);
	MD5_DEBUG(FPLOG(INFO, "block(%i/%i): towr=%i, eof=%i, ooff=%i, md5_pos=%i, buflen=%i\n",
				state->seq, state->olnchg, *towr, eof, ooff, state->md5_pos, state->buflen));
	/* TODO: Replace usage of state->buf by using slack space */
	/* First block */
	if (state->buflen) {
		/* Handle leftover bytes ... */
		if (/*!state->olnchg &&*/ opos > state->md5_pos+state->buflen) {
			/* First sparse piece  ... */
			memset(state->buf+state->buflen, 0, 64-state->buflen);
			md5_64(state->buf, &state->md5);
			state->md5_pos += 64;
			memset(state->buf, 0, state->buflen);
			state->buflen = 0;
		} else if (*towr) {
			/* Reassemble and process first block */
			consumed = MIN(64-state->buflen, *towr);
			MD5_DEBUG(FPLOG(INFO, "Append %i bytes @ %i to store\n", consumed, ooff));
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
	assert(state->olnchg || state->md5_pos <= opos + consumed);
	/* Bulk sparse process */
	while (/*!state->olnchg &&*/ opos > state->md5_pos+63) {
		assert(state->buflen == 0);
		md5_64(state->buf, &state->md5);
		state->md5_pos += 64;
	}
	/* Last sparse block */
	int left = opos - (state->md5_pos+state->buflen);
	if (left > 0 && *towr == 0 && eof) {
		memset(state->buf, 0, left);
		state->buflen = left;
		md5_last(state, ooff);
		return bf;
	}
	if (/*!state->olnchg &&*/ left > 0 && *towr >= left) {
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
		MD5_DEBUG(FPLOG(INFO, "Consume %i bytes @ %i\n", mylen, ooff+consumed));
		md5_calc(bf+consumed, mylen, 0, &state->md5);
		consumed += mylen; state->md5_pos += mylen;
	}
	/* Copy remainder into buffer */
	if (/*!state->olnchg &&*/ state->md5_pos + state->buflen != opos + consumed)
		FPLOG(FATAL, "Inconsistency: MD5 pos %i, buff %i, st pos %i, cons %i, tbw %i\n",
				state->md5_pos, state->buflen, opos, consumed, *towr);
	assert(state->olnchg || eof || state->md5_pos + state->buflen == opos + consumed);
	if (*towr - consumed) {
		assert(state->buflen+*towr-consumed < 64);
		MD5_DEBUG(FPLOG(INFO, "Store %i bytes @ %i\n", *towr-consumed, ooff+consumed));
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
	loff_t firstpos = (state->seq == 0? state->opts->init_ipos: state->opts->init_opos);
	FPLOG(INFO, "%s (%" LL "i-%" LL "i): %s\n",
		state->name, firstpos, firstpos+state->md5_pos, md5_out(res));
	if (state->outfd) {
		char outbuf[256];
		snprintf(outbuf, 255, "%s *%s\n", md5_out(res), state->name);
		if (write(state->outfd, outbuf, strlen(outbuf)) <= 0)
			FPLOG(WARN, "Could not write MD5 result to fd %i\n", state->outfd);
	}
	free(*stat);
	return 0;
}


ddr_plugin_t ddr_plug = {
	.name = "MD5",
	.slack_pre = 64,	// not yet used
	.slack_post = 64,	// not yet used
	.needs_align = 0,
	.handles_sparse = 1,
	.init_callback  = md5_plug_init,
	.open_callback  = md5_open,
	.block_callback = md5_block,
	.close_callback = md5_close,
};


