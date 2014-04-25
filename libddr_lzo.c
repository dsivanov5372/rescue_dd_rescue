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
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <netinet/in.h>
#include <lzo/lzo1x.h>

/* Some bits from lzop -- we strive for some level of compatibility */

static const unsigned char 
	lzop_hdr[] = { 0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };

/* 9 bytes, ugh --- and header_t has not been designed with alignment considerations either */

typedef struct
{
    uint16_t version;
    uint16_t lib_version;
    uint16_t version_needed_to_extract;
    unsigned char method;
    unsigned char level;
    uint32_t flags;
    //uint32_t filter;
    uint32_t mode;
    uint32_t mtime_low;
    uint32_t mtime_high;
    // Do this for alignment
    unsigned char nmlen;
    char name[7];
    
    uint32_t hdr_checksum;	/* crc32 or adler32 */
    /* only if flags & F_H_EXTRA_FIELD */
   
    /* 
    uint32_t extrafield_len;
    uint32_t extra_seglen;
    uint32_t extrafield_checksum;
     */
    uint32_t uncmpr_len;   
    uint32_t cmpr_len;   
} header_t;

#define ADLER32_INIT_VALUE 1

void dummy_hdr(header_t* hdr, uint32_t ln, int seq, uint32_t ucmp_ln)
{
	memset(hdr, 0, sizeof(header_t));
	hdr->version = 0x4010;	/* 0x1030 big endian, sigh */
	hdr->lib_version = 0x6020;
	hdr->version_needed_to_extract = 0x4009;
	hdr->method = 1;
	hdr->level = 5;
	hdr->flags = 0x00000003UL;	/* Unix | Extra_Field */
	hdr->nmlen = 7;
	char name[8];
	sprintf(name, "%07x", seq); memcpy(hdr->name, name, 7);
	hdr->hdr_checksum = htonl(lzo_adler32(ADLER32_INIT_VALUE, (void*)hdr, offsetof(header_t, hdr_checksum)));
	
	/*
	hdr->extrafield_len = htonl(4);
	hdr->extra_seglen = htonl(ln);
	hdr->extrafield_checksum = htonl(lzo_adler32(ADLER32_INIT_VALUE, (void*)&hdr->extrafield_len, 8));
	 */
	hdr->uncmpr_len = htonl(ucmp_ln);
	hdr->cmpr_len = htonl(ln);
}

/* fwd decl */
ddr_plugin_t ddr_plug;

enum compmode {AUTO, COMPRESS, DECOMPRESS};

typedef struct _lzo_state {
	loff_t first_ooff;
	void *workspace;
	void *buf, *carry;
	size_t buflen, carrylen;
	unsigned int seg_no;
	int ofd;
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
	state->buflen = 0;
	state->carrylen = 0;
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
	state->seg_no = 0;
	state->ofd = ofd;
	if (lzo_init() != LZO_E_OK) {
		ddr_plug.fplog(stderr, FATAL, "Failed to initialize lzo library!");
		return -1;
	}
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
	if (state->mode == COMPRESS) {
		state->workspace = malloc(LZO1X_1_MEM_COMPRESS);
		if (!state->workspace) {
			ddr_plug.fplog(stderr, FATAL, "Can't allocate workspace of size %i for compression!\n", LZO1X_1_MEM_COMPRESS);
			return -1;
		}
		state->buflen = bsz + (bsz>>4) + 72 + sizeof(lzop_hdr) + sizeof(header_t);
	} else 
		state->buflen = 4*bsz;

	state->buf = malloc(state->buflen);
	if (!state->buf) {
		ddr_plug.fplog(stderr, FATAL, "Can't allocate buffer of size %i for de/compression!\n", state->buflen);
		state->buflen = 0;
		return -1;
	}
	return 0;
}

unsigned char* lzo_block(unsigned char* bf, int *towr, 
			 loff_t ooff, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	size_t dst_len;
	/* Bulk buffer process */
	if (state->mode == COMPRESS) {
		lzo1x_1_compress(bf, *towr, state->buf+3+sizeof(lzop_hdr)+sizeof(header_t), &dst_len, state->workspace);
		memcpy(state->buf+3, lzop_hdr, sizeof(lzop_hdr));
		dummy_hdr((header_t*)(state->buf+3+sizeof(lzop_hdr)), dst_len, state->seg_no++, *towr);
		*towr = dst_len + sizeof(header_t) + sizeof(lzop_hdr);
		return state->buf+3;
	}
	/* Decompression is more tricky */
	int err; 
	do {
		dst_len = state->buflen;
		err = lzo1x_decompress_safe(bf, *towr, state->buf, &dst_len, NULL);
		switch (err) {
		case LZO_E_INPUT_OVERRUN:
			/* TODO: Partial block, handle! */
			ddr_plug.fplog(stderr, FATAL, "Overrun %i %i %i; try larger block sizes\n", *towr, state->buflen, dst_len);
			abort();
			break;
		case LZO_E_EOF_NOT_FOUND:
			/* TODO: Partial block, handle! */
			ddr_plug.fplog(stderr, FATAL, "EOF not found %i %i %i; try larger block sizes\n", *towr, state->buflen, dst_len);
			abort();
			break;
		case LZO_E_OUTPUT_OVERRUN:
			state->buflen *= 2;
			state->buf = realloc(state->buf, state->buflen);
			if (!state->buf) {
				ddr_plug.fplog(stderr, FATAL, "Could not allocate output buffer of %i bytes!\n", state->buflen);
				abort();
			}
			break;
		case LZO_E_LOOKBEHIND_OVERRUN:
			ddr_plug.fplog(stderr, FATAL, "Lookbehind overrun %i %i %i; data corrupt?\n", *towr, state->buflen, dst_len);
			abort();
			break;
		case LZO_E_ERROR:
			ddr_plug.fplog(stderr, FATAL, "Unspecified error %i %i %i; data corrupt?\n", *towr, state->buflen, dst_len);
			abort();
			break;
		case LZO_E_INPUT_NOT_CONSUMED:
			/* TODO: Leftover bytes, store */
			/* FIXME: We can't know how many input bytes we consumed, can we? */
			ddr_plug.fplog(stderr, INFO, "Input not fully consumed %i %i %i\n", *towr, state->buflen, dst_len);
			break;
		}
	} while (err == LZO_E_OUTPUT_OVERRUN);
	*towr = dst_len;
	return state->buf;
}

int lzo_close(loff_t *ooff, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	//loff_t len = ooff-state->first_ooff;
	if (state->carrylen)
		free(state->carry);
	if (state->buflen)
		free(state->buf);
	if (state->workspace)
		free(state->workspace);
	ddr_plug.fplog(stderr, INFO, "Write 4 bytes of zero @ %i to end it all ....\n", *ooff);
	unsigned int zero = 0;
	pwrite(state->ofd, &zero, 4, *ooff);
	*ooff += 4;
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


