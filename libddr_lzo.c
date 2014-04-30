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
#include <signal.h>
#include <lzo/lzo1x.h>

// TODO: pass at runtime rather than compile time
#ifdef DEBUG
# define LZO_DEBUG(x) x
#else
# define LZO_DEBUG(x) do {} while (0)
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

#define NAMELEN 14

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
    char name[NAMELEN];
    
    uint32_t hdr_checksum;	/* crc32 or adler32 */

    /* only if flags & F_H_EXTRA_FIELD */
   
    /* 
    uint32_t extrafield_len;
    uint32_t extra_seglen;
    uint32_t extrafield_checksum;
     */
} __attribute__((packed)) header_t;

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
	void *dbuf;
	size_t dbuflen;
       	int hdroff;
	unsigned char *obuf;
	unsigned char **bufp;
	unsigned int slackpre, slackpost;
	size_t softbs;
	uint32_t flags;
	int ofd;
	int seq;
	enum compmode mode;
	int hdr_seen;
	/* Statistics */
	unsigned int nr_memmove, nr_realloc;
	size_t cmp_ln, unc_ln;
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
	hdr->nmlen = NAMELEN;
	if (state->iname) {
		memcpy(hdr->name, state->iname, MIN(NAMELEN,strlen(state->iname)));
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
}

int lzo_parse_hdr(unsigned char* bf, lzo_state *state)
{
	header_t *hdr = (header_t*)bf;
	if (ntohs(hdr->version_needed_to_extract) > 0x1030) {
		ddr_plug.fplog(stderr, FATAL, "lzo: requires version %02x.%02x to extract\n",
			ntohs(hdr->version_needed_to_extract) >> 8,
			ntohs(hdr->version_needed_to_extract) & 0xff);
		return -2;
	}
	if (hdr->method != 1 && hdr->method != 2 && hdr->method != 3 /*|| hdr->level != 5*/) {
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
	uint32_t comp = (state->flags & F_H_CRC32 ? lzo_crc32(  CRC32_INIT_VALUE, (void*)hdr, sizeof(header_t)-NAMELEN+hdr->nmlen-4)
						: lzo_adler32(ADLER32_INIT_VALUE, (void*)hdr, sizeof(header_t)-NAMELEN+hdr->nmlen-4));
	if (cksum != comp) {
		ddr_plug.fplog(stderr, FATAL, "lzo: header fails checksum %08x != %08x\n",
			cksum, comp);
		return -5;
	}
	int off = sizeof(header_t) + hdr->nmlen-NAMELEN;
	if (state->flags & F_H_EXTRA_FIELD) {
		off += 8 + ntohl(*(uint32_t*)(bf+off));
		if (off > 4096)
			abort();
	}
	state->hdr_seen = 1;
	return off;
}

void block_hdr(blockhdr_t* hdr, uint32_t uncompr, uint32_t compr, uint32_t unc_adl, void *cdata)
{
	hdr->uncmpr_len = htonl(uncompr);
	hdr->cmpr_len = htonl(compr);
	hdr->uncmpr_chksum = htonl(unc_adl);
	/* Don't compute a second time if we've just done a copy */
	hdr->cmpr_chksum = (uncompr == compr ?
			hdr->uncmpr_chksum :
			htonl(lzo_adler32(ADLER32_INIT_VALUE, cdata, compr)));
}

/* Returns compressed len */
int parse_block_hdr(blockhdr_t *hdr, unsigned int *unc_cksum, unsigned int *cmp_cksum, lzo_state *state)
{
	int off = sizeof(blockhdr_t);
	if (state->flags & (F_ADLER32_D | F_CRC32_D)) {
		if (unc_cksum)
			*unc_cksum = ntohl(hdr->uncmpr_chksum);
		if (state->flags & (F_ADLER32_C | F_CRC32_C)) {
			if (cmp_cksum)
				*cmp_cksum = ntohl(hdr->cmpr_chksum);
		} else
			off -= 4;
	} else if (state->flags & (F_ADLER32_C | F_CRC32_C)) {
		if (cmp_cksum)
			*cmp_cksum = ntohl(hdr->uncmpr_chksum);
		off -= 4;
	} else {
		off -= 8;
	}
	return off;
}

char *lzo_help = "The lzo plugin for dd_rescue de/compresses data on the fly.\n"
	//	" It supports unaligned blocks (arbitrary offsets) and sparse writing.\n"
		" Parameters: compress/decompress\n";

int lzo_plug_init(void **stat, char* param, int seq)
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
	state->dbuflen = 0;
	state->seq = seq;
	state->hdr_seen = 0;
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
	state->nr_memmove = 0; state->nr_realloc = 0;
	state->cmp_ln = 0; state->unc_ln = 0;
	return err;
}

void* slackalloc(size_t ln, lzo_state *state)
{
	/* TODO: pagesize alignment ... */
	void* ptr = malloc(ln+state->slackpre+state->slackpost);
	if (!ptr) {
		ddr_plug.fplog(stderr, FATAL, "lzo: allocation of %i bytes failed: %s\n",
			ln+state->slackpre+state->slackpost, strerror(errno));
		exit(13);
	}
	return ptr+state->slackpre;
}

void* slackrealloc(void* base, size_t newln, lzo_state *state)
{
	void* ptr;
	++state->nr_realloc;
	/* Note: We could use free and malloc IF we have no data decompressed yet 
	 * (d_off == 0) and no slack space from plugins behind us is needed.
	 * Probably not worth the effort ... */
	/* This does not preserve pagesize alignment */
	ptr = realloc(base-state->slackpre, newln+state->slackpre+state->slackpost);
	/* Note: We can be somewhat graceful if realloc fails by returning the original
	 * pointer and buffer size and raise(SIGQUIT) -- this would result in 
	 * writing out data that has been processed already.
	 */
	if (!ptr) {
		ddr_plug.fplog(stderr, FATAL, "lzo: reallocation of %i bytes failed: %s\n",
			newln+state->slackpre+state->slackpost, strerror(errno));
		raise(SIGQUIT);
		return NULL;
	}
	return ptr+state->slackpre;
}

void slackfree(void* base, lzo_state *state)
{
	free(base-state->slackpre);
}

int lzo_open(int ifd, const char* inm, loff_t ioff, 
	     int ofd, const char* onm, loff_t ooff, 
	     unsigned int bsz, unsigned int hsz,
	     loff_t exfer, int olnchg, 
	     unsigned int totslack_pre, unsigned int totslack_post,
	     unsigned char **bufp, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	state->first_ooff = ooff;
	state->iname = inm;
	state->oname = onm;
	state->ofd = ofd;
	state->bufp = bufp;
	state->obuf = *bufp;
	state->softbs = bsz;
	state->hdroff = 0;
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
		state->dbuflen = bsz + (bsz>>4) + 72 + sizeof(lzop_hdr) + sizeof(header_t);
	} else {
		state->dbuflen = 4*bsz;
	}
	state->slackpost = totslack_post;
	state->slackpre  = totslack_pre ;
	state->dbuf = slackalloc(state->dbuflen, state);
	return 0;
	/* This breaks MD5 in chain before us
	return consumed;
	*/
}

unsigned char* lzo_compress(unsigned char *bf, int *towr,
			    int eof, loff_t ooff, lzo_state *state)
{
	lzo_uint dst_len;
	void *hdrp = state->dbuf+3+sizeof(lzop_hdr);
	void *bhdp = hdrp+sizeof(header_t);
	void* wrbf = bhdp;
	if (*towr) {
		void *cdata = bhdp+sizeof(blockhdr_t);
		/* Compat with lzop forces us to compute adler32 also on uncompressed data
		 * when doing it for compressed (I would preder only the latter and I would
		 * also prefer crc32,but that's slow in liblzo ...) */
		uint32_t unc_adl = lzo_adler32(ADLER32_INIT_VALUE, bf, *towr);
		lzo1x_1_compress(bf, *towr, cdata, &dst_len, state->workspace);
		/* We NEED to do the same optimization as lzop if dst_len >= *towr, if we
		 * want to be compatible, as the * lzop ddecompression code otherwise bails
		 * out, sigh.
		 * So if this is the case, copy original block; decompression recognizes
		 * this by cmp_len == unc_len ....
		 */
		if (dst_len >= *towr) {
			/* TODO: We could return original buffer instead
			 * and save a copy -- don't bother for now ...
			 * as the added header makes this somewhat complex.
			 */
			memcpy(cdata, bf, *towr);
			dst_len = *towr;
		}
		state->cmp_ln += dst_len; state->unc_ln += *towr;
		block_hdr((blockhdr_t*)bhdp, *towr, dst_len, unc_adl, cdata);
		*towr = dst_len + sizeof(blockhdr_t);
		if (ooff == state->first_ooff) {
			memcpy(state->dbuf+3, lzop_hdr, sizeof(lzop_hdr));
			lzo_hdr((header_t*)hdrp, state);
			*towr += sizeof(header_t) + sizeof(lzop_hdr);
			wrbf = state->dbuf+3;
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
	int c_off = 0;
	int d_off = 0;
	if (!*towr)
		return bf;
	/* header parsing has happened in _open callback ... */
	if (!state->hdr_seen) {
		assert(ooff - state->first_ooff == 0);
		if (memcmp(bf, lzop_hdr, sizeof(lzop_hdr))) {
			ddr_plug.fplog(stderr, FATAL, "lzo: lzop magic broken\n");
			abort();
		}
		c_off += sizeof(lzop_hdr);
		int err = lzo_parse_hdr(bf+c_off, state);
		if (err < 0)
			abort();
		c_off += err;
	}
	/* Now do processing: Do we have a full block? */
	do {
		uint32_t cmp_len, unc_len = 0;
		lzo_uint dst_len;
		const size_t totbufln = state->softbs - ddr_plug.slack_post*((state->softbs+15)/16);
		unsigned char* effbf = bf+c_off+state->hdroff;
		LZO_DEBUG(ddr_plug.fplog(stderr, INFO, "lzo: dec blk @ %p (offs %i, stoffs %i, bln %zi, tbw %i)\n",
				effbf, effbf-state->obuf, state->hdroff, totbufln, *towr));
		blockhdr_t *hdr = (blockhdr_t*)effbf;
		const size_t have_len = *towr-state->hdroff-c_off;
		/* No more bytes left: This is ideal :-) */
		if (have_len == 0) {
			state->hdroff = 0;
			*state->bufp = state->obuf;
			break;
		}
		/* EOF marker */
		if (have_len >= 4) {
			unc_len = ntohl(hdr->uncmpr_len);
			if (!unc_len)	/* EOF */
				break;
		}
		/* Not enough data to read header; move to beginning of buffer */
		if (have_len < 8) {
			if (effbf != state->obuf) {
				memmove(state->obuf, effbf, have_len);
				++state->nr_memmove;
			}
			state->hdroff = -have_len;
			*state->bufp = state->obuf+have_len;
			break;
		}
		/* Parse rest of header header */
		cmp_len = ntohl(hdr->cmpr_len);
		unsigned int unc_cksum, cmp_cksum;
		int addoff;
		if (have_len >= 16)
			addoff = parse_block_hdr(hdr, &unc_cksum, &cmp_cksum, state);
		else
			addoff = parse_block_hdr(hdr, NULL, NULL, state);
		LZO_DEBUG(ddr_plug.fplog(stderr, INFO, "lzo: dec blk @ %p (hdroff %i, cln %i, uln %i, have %i)\n",
				effbf, c_off+state->hdroff, cmp_len, unc_len, have_len));
		/* Block incomplete? */
		if (addoff+cmp_len > have_len) {
			/* incomplete block */
			if (effbf+addoff+cmp_len <= state->obuf+totbufln 
				&& *state->bufp+*towr+state->softbs <= state->obuf+totbufln) {
				/* We have enough space to just append: 
				 * Block will fit and so will next read ... */
				state->hdroff -= *towr-c_off;
				*state->bufp += *towr;
				LZO_DEBUG(ddr_plug.fplog(stderr, INFO, "lzo: append  @ %p\n", *state->bufp));
				/* Simplify to addoff+cmp_len+state->softbs < totbufln ? */
			} else if (addoff+cmp_len < totbufln &&
					have_len+state->softbs < totbufln) {
				/* We need to move block to beg of buffer */
				LZO_DEBUG(ddr_plug.fplog(stderr, INFO, "lzo: move %i bytes to buffer head\n", have_len));
				if (effbf != state->obuf) {
					memmove(state->obuf, effbf, have_len);
					++state->nr_memmove;
				}
				state->hdroff = -have_len;
				*state->bufp = state->obuf+have_len;
				//c_off = 0;
			} else {
				/* Our buffer is too small */
				ddr_plug.fplog(stderr, FATAL, "Can't assemble block of size %i, increase softblocksize to at least %i\n", 
						cmp_len, cmp_len/2);
				raise(SIGQUIT);
			}
			break;
		}
		if (state->flags & ( F_ADLER32_C | F_CRC32_C)) {
			uint32_t cksum = state->flags & F_ADLER32_C ?
				lzo_adler32(ADLER32_INIT_VALUE, effbf+addoff, cmp_len) :
				lzo_crc32  (  CRC32_INIT_VALUE, effbf+addoff, cmp_len);
			if (cksum != cmp_cksum) {
				ddr_plug.fplog(stderr, FATAL, "lzo: compr checksum mismatch @ %i\n",
						ooff+d_off);
				raise(SIGQUIT);
				break;
			}
		}
		dst_len = state->dbuflen-d_off;
		if (dst_len < unc_len) {
			/* If memalloc fails, we'll abort in a second, so warn ... */
			if (unc_len > 16*1024*1024)
				ddr_plug.fplog(stderr, WARN, "lzo: large uncompressed block sz %i @%i\n",
						unc_len, ooff+d_off);
			size_t newlen = unc_len+d_off+255;
			newlen -= newlen%256;
			void *newbuf = slackrealloc(state->dbuf, newlen, state);
			/* if realloc failed, exit loop, write out existing data and exit;
			 * slackrealloc has done raise(SIGQUIT) already ... */
			if (!newbuf)
				break;
			state->dbuf = newbuf;
			state->dbuflen = newlen;
			dst_len = newlen-d_off;
		}
		int err = 0;
		/* lzop: cmp_len == unc_len means that we just have a copy of the original */
		if (cmp_len != unc_len) {
			err = lzo1x_decompress_safe(effbf+addoff, cmp_len, state->dbuf+d_off, &dst_len, NULL);
			LZO_DEBUG(ddr_plug.fplog(stderr, INFO, "lzo: decompressed %i@%p -> %i\n",
				cmp_len, effbf+addoff, dst_len));
			if (dst_len != unc_len)
				ddr_plug.fplog(stderr, WARN, "lzo: inconsistent uncompressed size @%i: %i <-> %i\n",
					ooff+d_off, unc_len, dst_len);
		} else {
			memcpy(state->dbuf+d_off, effbf+addoff, unc_len);
			dst_len = unc_len;
		}
		switch (err) {
		case LZO_E_INPUT_OVERRUN:
			/* TODO: Partial block, handle! */
			ddr_plug.fplog(stderr, FATAL, "lzo: input overrun %i %i %i; try larger block sizes\n", *towr, state->dbuflen, dst_len);
			raise(SIGQUIT);
			break;
		case LZO_E_EOF_NOT_FOUND:
			/* TODO: Partial block, handle! */
			ddr_plug.fplog(stderr, FATAL, "lzo: EOF not found %i %i %i; try larger block sizes\n", *towr, state->dbuflen, dst_len);
			raise(SIGQUIT);
			break;
		case LZO_E_OUTPUT_OVERRUN:
			ddr_plug.fplog(stderr, FATAL, "lzo: output overrun %i %i %i; try larger block sizes\n", *towr, state->dbuflen, dst_len);
			raise(SIGQUIT);
			break;
		case LZO_E_LOOKBEHIND_OVERRUN:
			ddr_plug.fplog(stderr, FATAL, "lzo: lookbehind overrun %i %i %i; data corrupt?\n", *towr, state->dbuflen, dst_len);
			raise(SIGQUIT);
			break;
		case LZO_E_ERROR:
			ddr_plug.fplog(stderr, FATAL, "lzo: unspecified error %i %i %i; data corrupt?\n", *towr, state->dbuflen, dst_len);
			raise(SIGQUIT);
			break;
		case LZO_E_INPUT_NOT_CONSUMED:
			/* TODO: Leftover bytes, store */
			ddr_plug.fplog(stderr, INFO, "lzo: input not fully consumed %i %i %i\n", *towr, state->dbuflen, dst_len);
			break;
		}
		if (state->flags & ( F_ADLER32_D | F_CRC32_D)) {
			uint32_t cksum;
			/* If we have just copied and tested the compressed checksum before,
			 * no need to adler32/crc32 the same memory again ... */
		       	if (cmp_len == unc_len && state->flags & (F_ADLER32_C | F_CRC32_C))
				cksum = cmp_cksum;
			else
				cksum = state->flags & F_ADLER32_D ?
					lzo_adler32(ADLER32_INIT_VALUE, state->dbuf+d_off, dst_len) :
					lzo_crc32  (  CRC32_INIT_VALUE, state->dbuf+d_off, dst_len);
			if (cksum != unc_cksum) {
				ddr_plug.fplog(stderr, FATAL, "lzo: decompr checksum mismatch @ %i\n",
						ooff+d_off);
				raise(SIGQUIT);
				break;
			}
		}
		c_off += cmp_len+addoff;
		d_off += dst_len;
		state->cmp_ln += cmp_len; 
		state->unc_ln += dst_len;
	} while (1);
	/* reset to normal buffer start */
	*towr = d_off;
	return state->dbuf;
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
	if (state->dbuflen)
		slackfree(state->dbuf, state);
	if (state->workspace)
		free(state->workspace);
	if (state->mode == COMPRESS)
		ddr_plug.fplog(stderr, INFO, "lzo: compr %.1fkiB <- %.1fkiB (%.1f%)\n",
			state->cmp_ln/1024.0, state->unc_ln/1024.0,
			100.0*((double)state->cmp_ln/state->unc_ln - 1.0));
	else
		ddr_plug.fplog(stderr, INFO, "lzo: compr %.1fkiB -> %.1fkiB (%.1f%), %i reallocs (%ikiB), %i moves\n",
			state->cmp_ln/1024.0, state->unc_ln/1024.0,
			100.0*((double)state->cmp_ln/state->unc_ln - 1.0),
			state->nr_realloc, state->dbuflen/1024, 
			state->nr_memmove);
	free(*stat);
	return 0;
}


ddr_plugin_t ddr_plug = {
	.name = "lzo",
	.slack_pre = 0, /* sizeof(lzop_hdr), */
	.slack_post = -33,
	.needs_align = 1,
	.handles_sparse = 0,
	.changes_output = 1,
	.changes_output_len = 1,
	.init_callback  = lzo_plug_init,
	.open_callback  = lzo_open,
	.block_callback = lzo_block,
	.close_callback = lzo_close,
};


