/* libddr_lzo.c
 *
 * plugin for dd_rescue, doing lzo de/compression during copying ...
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPLv2 or v3
 */

#define _LARGEFILE64_SOURCE 1
#define _FILE_OFFSET_BITS 64

#include "ddr_plugin.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <lzo/lzo1x.h>
#if !defined(HAVE_PREAD64) || defined(TEST_SYSCALL)
#include "pread64.h"
#endif

/* Some bits from lzop -- we strive for some level of compatibility */

static const unsigned char 
	lzop_hdr[] = { 0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };

/* 9 bytes, ugh --- and header_t has not been designed with alignment considerations either */

#define F_ADLER32_D     0x00000001L
#define F_ADLER32_C     0x00000002L
#define F_H_EXTRA_FIELD 0x00000040L
#define F_CRC32_D       0x00000100L
#define F_CRC32_C       0x00000200L
#define F_MULTIPART     0x00000400L
#define F_H_CRC32       0x00001000L


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
    char name[15];
    
    uint32_t hdr_checksum;	/* crc32 or adler32 */

    /* only if flags & F_H_EXTRA_FIELD */
   
    /* 
    uint32_t extrafield_len;
    uint32_t extra_seglen;
    uint32_t extrafield_checksum;
     */
} header_t;

typedef struct {
    uint32_t uncmpr_len;   
    uint32_t cmpr_len;   
    uint32_t uncmpr_chksum;
    uint32_t cmpr_chksum;
} blockhdr_t;

#define ADLER32_INIT_VALUE 1
#define CRC32_INIT_VALUE 0

#define MIN(a,b) ((a)<(b)? (a): (b))

/* fwd decl */
ddr_plugin_t ddr_plug;

enum compmode {AUTO, COMPRESS, DECOMPRESS};

typedef struct _lzo_state {
	loff_t first_ooff;
	const char *iname, *oname;
	void *workspace;
	void *buf, *carry;
	size_t buflen, carrylen, carried;
	unsigned char **bufp;
	size_t addslack, slackoff;
	size_t softbs;
	uint32_t flags;
	int ofd;
	enum compmode mode;
} lzo_state;

void lzo_hdr(header_t* hdr, lzo_state *state)
{
	memset(hdr, 0, sizeof(header_t));
	hdr->version = ntohs(0x1024);
	hdr->lib_version = ntohs(LZO_VERSION);
	hdr->version_needed_to_extract = ntohs(0x0940);
	hdr->method = 1;
	hdr->level = 5;
	/* Notes: We want checksums on compressed content; lzop forces us to do both then 
	 * CRC32C has better error protection quality than adler32 -- but the implementation
	 * in liblzo is rather slow, so stick with adler32 for now ... */
	state->flags = 0x03000003UL;	/* UNIX | ADLER32_C | ADLER32_D */
	hdr->flags = ntohl(state->flags);
	hdr->nmlen = 15;
	if (state->iname) {
		memcpy(hdr->name, state->iname, MIN(15,strlen(state->iname)));
		struct stat stbf;
		if (0 == stat(state->iname, &stbf)) {
			hdr->mode = ntohl(stbf.st_mode);
			hdr->mtime_low = ntohl(stbf.st_mtime & 0xffffffff);
#if __WORDSIZE != 32
			hdr->mtime_high = ntohl(stbf.st_mtime >> 32);
#endif
		}
	}
	hdr->hdr_checksum = htonl(lzo_adler32(ADLER32_INIT_VALUE, (void*)hdr, offsetof(header_t, hdr_checksum)));
	
	/*
	hdr->extrafield_len = htonl(4);
	hdr->extra_seglen = htonl(ln);
	hdr->extrafield_checksum = htonl(lzo_adler32(ADLER32_INIT_VALUE, (void*)&hdr->extrafield_len, 8));
	 */
}

int lzo_parse_hdr(unsigned char* bf, lzo_state *state)
{
	if (memcmp(bf, lzop_hdr, sizeof(lzop_hdr))) {
		ddr_plug.fplog(stderr, FATAL, "lzo: lzop magic broken\n");
		return -1;
	}
	header_t *hdr = (header_t*)(bf+sizeof(lzop_hdr));
	if (hdr->version_needed_to_extract > htons(0x1030)) {
		ddr_plug.fplog(stderr, FATAL, "lzo: requires version %02x.%02x to extract\n",
			ntohs(hdr->version_needed_to_extract) >> 8,
			ntohs(hdr->version_needed_to_extract) & 0xff);
		return -2;
	}
	if (hdr->method != 1 /*|| hdr->level != 5*/) {
		ddr_plug.fplog(stderr, FATAL, "lzo: unsupported method %i level %i\n",
			hdr->method, hdr->level);
		return -3;
	}
	state->flags = ntohl(hdr->flags);
	if (state->flags & F_MULTIPART) {
		ddr_plug.fplog(stderr, FATAL, "lzo: unsupported multipart archive\n");
		return -4;
	}
	uint32_t cksum = ntohl(*(uint32_t*)((char*)hdr+offsetof(header_t,name)+hdr->nmlen));
	uint32_t comp = (state->flags & F_H_CRC32 ? lzo_crc32(  CRC32_INIT_VALUE, (void*)hdr, sizeof(header_t)-15+hdr->nmlen-4)
						: lzo_adler32(ADLER32_INIT_VALUE, (void*)hdr, sizeof(header_t)-15+hdr->nmlen-4));
	if (cksum != comp) {
		ddr_plug.fplog(stderr, FATAL, "lzo: header fails checksum %08x != %08x\n",
			cksum, comp);
		return -5;
	}
	int off = sizeof(lzop_hdr) + sizeof(header_t) + hdr->nmlen-15;
	if (state->flags & F_H_EXTRA_FIELD) {
		off += 8 + ntohl(*(uint32_t*)(bf+off));
		if (off > 4096)
			abort();
	}
	return off;
}

void block_hdr(blockhdr_t* hdr, uint32_t uncompr, uint32_t compr, uint32_t unc_adl, void *cdata)
{
	hdr->uncmpr_len = htonl(uncompr);
	hdr->cmpr_len = htonl(compr);
	hdr->uncmpr_chksum = htonl(unc_adl);
	hdr->cmpr_chksum = htonl(lzo_adler32(ADLER32_INIT_VALUE, cdata, compr));
}

char *lzo_help = "The lzo plugin for dd_rescue de/compresses data on the fly.\n"
	//	" It supports unaligned blocks (arbitrary offsets) and sparse writing.\n"
		" Parameters: compress/decompress\n";

int lzo_plug_init(void **stat, char* param)
{
	int err = 0;
	lzo_state *state = (lzo_state*)malloc(sizeof(lzo_state));
	if (!state) {
		ddr_plug.fplog(stderr, FATAL, "lzo: can't allocate %i bytes\n", sizeof(lzo_state));
		return -1;
	}
	*stat = (void*)state;
	//memset(state, 0, sizeof(lzo_state));
	state->mode = AUTO;
	state->workspace = NULL;
	state->buflen = 0;
	state->carrylen = 0;
	state->carry = NULL;
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
			ddr_plug.fplog(stderr, FATAL, "lzo: plugin doesn't understand param %s\n",
				param);
			++err;
		}
		param = next;
	}
	return err;
}

void* slackalloc(size_t ln, lzo_state *state)
{
	void* ptr = malloc(ln+state->addslack);
	if (!ptr) {
		ddr_plug.fplog(stderr, FATAL, "lzo: allocation of %i bytes failed: %s\n",
			ln+state->addslack, strerror(errno));
		exit(13);
	}
	return ptr+state->slackoff;
}

void* slackrealloc(void* base, size_t newln, lzo_state *state)
{
	void* ptr = realloc(base-state->slackoff, newln+state->addslack);
	if (!ptr) {
		ddr_plug.fplog(stderr, FATAL, "lzo: reallocation of %i bytes failed: %s\n",
			newln+state->addslack, strerror(errno));
		exit(13);
	}
	return ptr+state->slackoff;
}

void slackfree(void* base, lzo_state *state)
{
	free(base-state->slackoff);
}

int lzo_open(int ifd, const char* inm, loff_t ioff, 
	     int ofd, const char* onm, loff_t ooff, 
	     unsigned int bsz, unsigned int hsz,
	     loff_t exfer, int olnchg, size_t totslack,
	     unsigned char **bufp, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	state->first_ooff = ooff;
	state->iname = inm;
	state->oname = onm;
	state->ofd = ofd;
	state->bufp = bufp;
	state->softbs = bsz;
	if (lzo_init() != LZO_E_OK) {
		ddr_plug.fplog(stderr, FATAL, "lzo: failed to initialize lzo library!");
		return -1;
	}
	if (state->mode == AUTO) {
		if (!strcmp(inm+strlen(inm)-2, "zo"))
			state->mode = DECOMPRESS;
		else if (!strcmp(onm+strlen(onm)-2, "zo"))
			state->mode = COMPRESS;
		else {
			ddr_plug.fplog(stderr, FATAL, "lzo: can't determine compression/decompression from filenames (and not set)!\n");
			return -1;
		}
	}
	if (state->mode == COMPRESS) {
		state->workspace = malloc(LZO1X_1_MEM_COMPRESS);
		if (!state->workspace) {
			ddr_plug.fplog(stderr, FATAL, "lzo: can't allocate workspace of size %i for compression!\n", LZO1X_1_MEM_COMPRESS);
			return -1;
		}
		state->buflen = bsz + (bsz>>4) + 72 + sizeof(lzop_hdr) + sizeof(header_t);
	} else 
		state->buflen = 4*bsz;

	size_t ownslack = -ddr_plug.slackspace*bsz;
	state->addslack = totslack - ownslack;	
	/* FIXME: This happens to work for md5, needs more generic approach */
	state->slackoff = state->addslack/2;
	state->buf = slackalloc(state->buflen, state);
	return 0;
}

unsigned char* lzo_compress(unsigned char *bf, int *towr,
			    int eof, loff_t ooff, lzo_state *state)
{
	lzo_uint dst_len;
	void *hdrp = state->buf+3+sizeof(lzop_hdr);
	void *bhdp = hdrp+sizeof(header_t);
	void* wrbf = bhdp;
	if (*towr) {
		void *cdata = bhdp+sizeof(blockhdr_t);
		/* Compat with lzop forces us to compute adler32 also on uncompressed data
		 * when doing it for compressed (I would preder only the latter and I would
		 * also prefer crc32,but that's slow in liblzo ...) */
		uint32_t unc_adl = lzo_adler32(ADLER32_INIT_VALUE, bf, *towr);
		lzo1x_1_compress(bf, *towr, cdata, &dst_len, state->workspace);
		block_hdr((blockhdr_t*)bhdp, *towr, dst_len, unc_adl, cdata);
		*towr = dst_len + sizeof(blockhdr_t);
		if (ooff == state->first_ooff) {
			memcpy(state->buf+3, lzop_hdr, sizeof(lzop_hdr));
			lzo_hdr((header_t*)hdrp, state);
			*towr += sizeof(header_t) + sizeof(lzop_hdr);
			wrbf = state->buf+3;
		}
	}
	if (eof) {
		//memset(cdata+dst_len, 0, 4);
		memset(wrbf+*towr, 0, 4);
		*towr += 4;
	}
	return wrbf;
}

unsigned char* lzo_decompress(unsigned char* bf, int *towr,
			      int eof, loff_t ooff, lzo_state *state)
{
	/* Decompression is tricky */
	int err; 
	lzo_uint dst_len;
	if (ooff == 0) {
		/* Parse header */
		/* Validate header checksum */
	}
	/* Now do processing: Do we have a full block */
	do {
		dst_len = state->buflen;
		err = lzo1x_decompress_safe(bf, *towr, state->buf, &dst_len, NULL);
		switch (err) {
		case LZO_E_INPUT_OVERRUN:
			/* TODO: Partial block, handle! */
			ddr_plug.fplog(stderr, FATAL, "lzo: ocverrun %i %i %i; try larger block sizes\n", *towr, state->buflen, dst_len);
			abort();
			break;
		case LZO_E_EOF_NOT_FOUND:
			/* TODO: Partial block, handle! */
			ddr_plug.fplog(stderr, FATAL, "lzo: EOF not found %i %i %i; try larger block sizes\n", *towr, state->buflen, dst_len);
			abort();
			break;
		case LZO_E_OUTPUT_OVERRUN:
			state->buflen *= 2;
			state->buf = slackrealloc(state->buf, state->buflen, state);
			break;
		case LZO_E_LOOKBEHIND_OVERRUN:
			ddr_plug.fplog(stderr, FATAL, "lzo: lookbehind overrun %i %i %i; data corrupt?\n", *towr, state->buflen, dst_len);
			abort();
			break;
		case LZO_E_ERROR:
			ddr_plug.fplog(stderr, FATAL, "lzo: unspecified error %i %i %i; data corrupt?\n", *towr, state->buflen, dst_len);
			abort();
			break;
		case LZO_E_INPUT_NOT_CONSUMED:
			/* TODO: Leftover bytes, store */
			/* FIXME: We can't know how many input bytes we consumed, can we? */
			ddr_plug.fplog(stderr, INFO, "lzo: input not fully consumed %i %i %i\n", *towr, state->buflen, dst_len);
			break;
		}
	} while (err == LZO_E_OUTPUT_OVERRUN);
	*towr = dst_len;
	return state->buf;
}


unsigned char* lzo_block(unsigned char* bf, int *towr, 
			 int eof, loff_t ooff, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	/* Bulk buffer process */
	if (state->mode == COMPRESS) 
		return lzo_compress(bf, towr, eof, ooff, state);
	else
		return lzo_decompress(bf, towr, eof, ooff, state);
}

int lzo_close(loff_t ooff, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	//loff_t len = ooff-state->first_ooff;
	if (state->carry)
		free(state->carry);
	if (state->buflen)
		slackfree(state->buf, state);
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
	.changes_output = 1,
	.changes_output_len = 1,
	.init_callback  = lzo_plug_init,
	.open_callback  = lzo_open,
	.block_callback = lzo_block,
	.close_callback = lzo_close,
};

