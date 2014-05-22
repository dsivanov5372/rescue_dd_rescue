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
	ddr_plug.fplog(stderr, lvl, "%s(%i): ", ddr_plug.name, fmt, state->seq, ##args)

/* fwd decl */
extern ddr_plugin_t ddr_plug;

typedef struct _md5_state {
	hash_t md5;
	loff_t md5_pos;
	const char* name;
	uint8_t buf[128];
	int seq;
	int outfd;
	unsigned char buflen;
	unsigned char ilnchg, olnchg, debug;
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
	if (state->debug)
		FPLOG(DEBUG, "Initialized plugin %s\n", ddr_plug.name);
	return err;
}

int md5_open(const opt_t *opt, int ilnchg, int olnchg,
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
	state->ilnchg = ilnchg;
	state->olnchg = olnchg;
	if (ilnchg && olnchg && (state->opts->sparse || !state->opts->nosparse)) {
		FPLOG(WARN, "Size of potential holes may not be correct due to other plugins;\n");
		FPLOG(WARN, " MD5 hash may be miscomputed! Avoid holes (remove -a, use -A).\n");
	}
	return 0;
}

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif

void md5_last(md5_state *state, loff_t pos)
{
	//md5_block(0, 0, ooff, stat);
	int left = pos - state->md5_pos;
	assert(state->buflen == left || (state->ilnchg && state->olnchg));
	/*
	fprintf(stderr, "MD5_DEBUG: %s: len=%li, md5pos=%li\n", 
		state->name, len, state->md5_pos);
	 */
	MD5_DEBUG(FPLOG(DEBUG, "Last block with %i bytes\n", state->buflen));
	md5_calc(state->buf, state->buflen, state->md5_pos+state->buflen, &state->md5);
	state->md5_pos += state->buflen;
}

static inline void md5_64_buf(md5_state* state, int clear)
{
	md5_64(state->buf, &state->md5);
	state->md5_pos += 64;
	state->buflen = 0;
	if (clear)
		memset(state->buf, 0, clear);
}

#define MIN(a,b) ((a)<(b)? (a): (b))

void md5_hole(fstate_t *fst, md5_state *state, loff_t holelen)
{
	if (state->buflen) {
		MD5_DEBUG(FPLOG(DEBUG, "first sparse block (drain %i)\n", state->buflen));
		memset(state->buf+state->buflen, 0, 64-state->buflen);
		if (holelen >= 64-state->buflen) {
			holelen -= (64-state->buflen);
			md5_64_buf(state, state->buflen);
		} else {
			state->buflen += holelen;
			return;
		}
	}
	assert(state->buflen == 0);
	MD5_DEBUG(FPLOG(DEBUG, "bulk sparse %i\n", holelen-holelen%64));
	while (holelen >= 64) {
		md5_64_buf(state, 0);
		holelen -= 64;
	}
	assert(holelen >= 0 && holelen < 64);
	// memset(state->buf, 0, holelen);
	state->buflen = holelen;
	MD5_DEBUG(FPLOG(DEBUG, "sparse left %i (%i+%i)\n", holelen, state->md5_pos, state->buflen));
	return;
}

/* This is rather complex, as we handle both non-aligned first block size
 * as well as sparse files */
unsigned char* md5_block(fstate_t *fst, unsigned char* bf, 
			 int *towr, int eof, int *recall, void **stat)
{
	/* TODO: Replace usage of state->buf by using slack space
	 * Hmmm, really? Probably buffer management is not sophisticated enough currently ... */
	/* TODO: If both ilnchg and olnchg are set, switch off sanity checks and go into dumb mode */
	md5_state *state = (md5_state*)*stat;
	const loff_t pos = state->olnchg? 
			fst->ipos - state->opts->init_ipos:
			fst->opos - state->opts->init_opos;
	MD5_DEBUG(FPLOG(DEBUG, "block(%i/%i): towr=%i, eof=%i, pos=%" LL "i, md5_pos=%" LL "i, buflen=%i\n",
				state->seq, state->olnchg, *towr, eof, pos, state->md5_pos, state->buflen));
	// Handle hole (sparse files)
	const loff_t holesz = pos - (state->md5_pos + state->buflen);
	assert(holesz >= 0 || (state->ilnchg && state->olnchg));
	if (holesz && !(state->ilnchg && state->olnchg))
		md5_hole(fst, state, holesz);

	assert(pos == state->md5_pos+state->buflen || (state->ilnchg && state->olnchg));
	int consumed = 0;
	assert(bf);
	/* First block */
	if (state->buflen && *towr) {
		/* Reassemble and process first block */
		consumed = MIN(64-state->buflen, *towr);
		MD5_DEBUG(FPLOG(DEBUG, "Append %i bytes @ %i to store\n", consumed, pos));
		memcpy(state->buf+state->buflen, bf, consumed);
		if (consumed+state->buflen == 64) {
			md5_64_buf(state, 64);
		} else {
			state->buflen += consumed;
			//memset(state->buf+state->buflen, 0, 64-state->buflen);
		}
	}

	assert(state->md5_pos+state->buflen == pos+consumed || (state->ilnchg && state->olnchg));
	/* Bulk buffer process */
	int to_process = *towr - consumed;
	assert(to_process >= 0);
	to_process -= to_process%64;
	if (to_process) {
		MD5_DEBUG(FPLOG(DEBUG, "Consume %i bytes @ %i\n", to_process, pos+consumed));
		assert(state->buflen == 0);
		md5_calc(bf+consumed, to_process, 0, &state->md5);
		consumed += to_process; state->md5_pos += to_process;
	}
	assert(state->md5_pos+state->buflen == pos+consumed || (state->ilnchg && state->olnchg));
	to_process = *towr - consumed;
	assert(to_process >= 0 && to_process < 64);
	/* Copy remainder into buffer */
	if (!(state->olnchg && state->ilnchg) && state->md5_pos + state->buflen != pos + consumed)
		FPLOG(FATAL, "Inconsistency: MD5 pos %i, buff %i, st pos %" LL "i, cons %i, tbw %i\n",
				state->md5_pos, state->buflen, pos, consumed, *towr);
	if (to_process) {
		MD5_DEBUG(FPLOG(DEBUG, "Store %i bytes @ %" LL "i\n", to_process, pos+consumed));
		assert(state->buflen == 0);
		memcpy(state->buf+state->buflen, bf+consumed, to_process);
		state->buflen = to_process;
	}
	if (eof)
		md5_last(state, pos+*towr);
	return bf;
}



int md5_close(loff_t ooff, void **stat)
{
	md5_state *state = (md5_state*)*stat;
	char res[33];
	loff_t firstpos = (state->seq == 0? state->opts->init_ipos: state->opts->init_opos);
	FPLOG(INFO, "%s (%" LL "i-%" LL "i): %s\n",
		state->name, firstpos, firstpos+state->md5_pos, md5_out(res, &state->md5));
	if (state->outfd) {
		char outbuf[256];
		snprintf(outbuf, 255, "%s *%s\n", md5_out(res, &state->md5), state->name);
		if (write(state->outfd, outbuf, strlen(outbuf)) <= 0)
			FPLOG(WARN, "Could not write MD5 result to fd %i\n", state->outfd);
	}
	free(*stat);
	return 0;
}


ddr_plugin_t ddr_plug = {
	//.name = "MD5",
	.slack_pre = 64,	// not yet used
	.slack_post = 64,	// not yet used
	.needs_align = 0,
	.handles_sparse = 1,
	.init_callback  = md5_plug_init,
	.open_callback  = md5_open,
	.block_callback = md5_block,
	.close_callback = md5_close,
};


