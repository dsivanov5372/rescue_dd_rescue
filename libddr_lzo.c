/* libddr_lzo.c
 *
 * plugin for dd_rescue, doing lzo de/compression during copying ...
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPLv2 or v3
 */

#include "ddr_plugin.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <lzo/lzo1x.h>

/* fwd decl */
ddr_plugin_t ddr_plug;

enum compmode {AUTO, COMPRESS, DECOMPRESS};

typedef struct _lzo_state {
	loff_t first_ooff;
	loff_t lzo_pos;
	const char* onm;
	void* workspace;
	void* decombuf;
	size_t decombuflen;
	enum compmode mode;
} lzo_state;

char *lzo_help = "The lzo plugin for dd_rescue de/compresses data on the fly.\n"
	//	" It supports unaligned blocks (arbitrary offsets) and sparse writing.\n"
		" Parameters: compress/decompress\n";

int lzo_plug_init(void **stat, char* param)
{
	int err = 0;
	lzo_state *state = (lzo_state*)malloc(sizeof(lzo_state));
	if (!state) {
		ddr_plug.fplog(stderr, FATAL, "lzo plugin can't allocate %i bytes\n", sizeof(lzo_state));
		return -1;
	}
	*stat = (void*)state;
	state->mode = AUTO;
	state->workspace = NULL;
	state->decombuflen = 0;
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			ddr_plug.fplog(stderr, INFO, "%s", lzo_help);
		else if (!strcmp(param, "compress"))
			state->mode = COMPRESS;
		else if (!strcmp(param, "decompress"))
			state->mode = DECOMPRESS;
		else {
			ddr_plug.fplog(stderr, FATAL, "lzo plugin doesn't understand param %s\n",
				param);
			++err;
		}
		param = next;
	}
	return err;
}

int lzo_open(int ifd, const char* inm, loff_t ioff, 
	     int ofd, const char* onm, loff_t ooff, 
	     unsigned int bsz, unsigned int hsz,
	     loff_t exfer, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	state->first_ooff = ooff;
	state->lzo_pos = 0;
	state->onm = onm;
	if (state->mode == AUTO) {
		if (!strcmp(inm+strlen(inm)-2, "zo"))
			state->mode = DECOMPRESS;
		else if (!strcmp(onm+strlen(onm)-2, "zo"))
			state->mode = COMPRESS;
		else {
			ddr_plug.fplog(stderr, FATAL, "Can't determine compression/decompression from filenames (and not set)!\n");
			return -1;
		}
	}
	if (state->mode == COMPRESS)
		state->workspace = malloc(LZO1X_1_MEM_COMPRESS);
	return 0;
}

/* This is rather complex, as we handle both non-aligned first block size
 * as well as sparse files */
unsigned char* lzo_block(unsigned char* bf, int *towr, 
			 loff_t ooff, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	int off = 0;
	/* First block */
	if (state->buflen) {
		/* Handle leftover bytes ... */
		if (ooff-state->first_ooff > state->lzo_pos+state->buflen) {
			/* Sparse: We have skipped writes ... */
			memset(state->buf+state->buflen, 0, 64-state->buflen);
			lzo_64(state->buf, &state->md5);
			state->lzo_pos += 64;
			memset(state->buf, 0, state->buflen);
		} else if (bf) {
			off = 64-state->buflen;
			memcpy(state->buf+state->buflen, bf, off);
			lzo_64(state->buf, &state->md5);
			state->lzo_pos += 64;
			memset(state->buf, 0, 64);
		}
	}
	assert(state->lzo_pos <= ooff+off-state->first_ooff);
	/* Bulk sparse process */
	while (ooff-state->first_ooff > state->lzo_pos+63) {
		lzo_64(state->buf, &state->md5);
		state->lzo_pos += 64;
	}
	if (!bf)
		return bf;
	int left = ooff-state->first_ooff - state->lzo_pos;
	if (left > 0) {
		memcpy(state->buf+64-left, bf, left);
		lzo_64(state->buf, &state->md5);
		state->lzo_pos += 64;
		off += left;
		memset(state->buf+64-left, 0, left);
	}
	/* Bulk buffer process */
	int mylen = *towr - off; mylen -= mylen%64;
	lzo_calc(bf+off, mylen, 0, &state->md5);
	off += mylen; state->lzo_pos += mylen;
	/* Copy remainder into buffer */
	assert(state->lzo_pos == ooff+off-state->first_ooff);
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

int lzo_close(loff_t ooff, void **stat)
{
	lzo_block(0, 0, ooff, stat);
	lzo_state *state = (lzo_state*)*stat;
	loff_t len = ooff-state->first_ooff;
	int left = len - state->lzo_pos;
	/*
	fprintf(stderr, "DEBUG: %s: len=%li, md5pos=%li\n", 
		state->onm, len, state->md5_pos);
	 */
	lzo_calc(state->buf, left, len, &state->md5);
	state->lzo_pos += left;
	//ddr_plug.fplog(stderr, INFO, "md5sum %s (%" LL "i-%" LL "i): %s\n",
	//	state->onm, state->first_ooff, ooff, md5_out(res));
	if (state->decombuflen)
		free(state->decombuf);
	if (state->workspace)
		free(state->workspace);
	free(*stat);
	return 0;
}


ddr_plugin_t ddr_plug = {
	.name = "lzo",
	.slackspace = 0 /*128*/,
	.needs_align = 1,
	.handles_sparse = 0,
	.init_callback  = lzo_plug_init,
	.open_callback  = lzo_open,
	.block_callback = lzo_block,
	.close_callback = lzo_close,
};


