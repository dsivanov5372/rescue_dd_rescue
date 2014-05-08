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
#include "ddr_ctrl.h"

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
#include <lzo/lzo1y.h>
#include <lzo/lzo1f.h>
#include <lzo/lzo1b.h>
#include <lzo/lzo2a.h>
#include <time.h>

// TODO: pass at runtime rather than compile time
#ifdef DEBUG
# define LZO_DEBUG(x) x
#else
# define LZO_DEBUG(x) do {} while (0)
#endif

/* Some bits from lzop -- we strive for some level of compatibility */
/* We use version numbers that are not likely to clash with lzop anytime soon;
 * let's see whether this can be coordinated with Markus Oberhumer */ 
#define F_VERSION 0x1789	/* BCD 1.789 */

static const unsigned char 
	lzop_hdr[] = { 0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a };

/* 9 bytes, ugh --- and header_t has not been designed with alignment considerations either */

#define F_ADLER32_D	0x00000001UL
#define F_ADLER32_C	0x00000002UL
#define F_H_EXTRA_FIELD	0x00000040UL
#define F_CRC32_D	0x00000100UL
#define F_CRC32_C	0x00000200UL
#define F_MULTIPART	0x00000400UL
#define F_H_CRC32	0x00001000UL
#define F_OS_UNIX	0x03000000UL

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


/* All algs need zero workmem to decompress, so no need to put in table */
typedef struct {
	const char* name;
	lzo_compress_t compress;
	lzo_decompress_t decompr;
	lzo_optimize_t optimize;
	unsigned int workmem;
	unsigned char meth, lev;
} comp_alg;

/* Only 1/5, 2/1 and 3/9 are defined by lzop (and 2/1 is x1_1_15 in lzop not _1_11) */
comp_alg calgos[] = { {"lzo1x_1",    lzo1x_1_compress,    lzo1x_decompress_safe, lzo1x_optimize, LZO1X_1_MEM_COMPRESS,    1, 5},
		      {"lzo1x_1_11", lzo1x_1_11_compress, lzo1x_decompress_safe, lzo1x_optimize, LZO1X_1_11_MEM_COMPRESS, 2, 1},
		      {"lzo1x_1_12", lzo1x_1_12_compress, lzo1x_decompress_safe, lzo1x_optimize, LZO1X_1_12_MEM_COMPRESS, 2, 2},
		      {"lzo1x_1_15", lzo1x_1_15_compress, lzo1x_decompress_safe, lzo1x_optimize, LZO1X_1_15_MEM_COMPRESS, 2, 5},
      		      {"lzo1x_999",  lzo1x_999_compress,  lzo1x_decompress_safe, lzo1x_optimize, LZO1X_999_MEM_COMPRESS,  3, 9},
		      /* We DON'T use a different method indicator for the variants unlike lzop */
		      {"lzo1y_1",    lzo1y_1_compress,    lzo1y_decompress_safe, lzo1y_optimize, LZO1Y_MEM_COMPRESS,     64, 1},
		      {"lzo1y_999",  lzo1y_999_compress,  lzo1y_decompress_safe, lzo1y_optimize, LZO1Y_999_MEM_COMPRESS, 65, 9},
		      {"lzo1f_1",    lzo1f_1_compress,    lzo1f_decompress_safe, NULL,           LZO1F_MEM_COMPRESS,     66, 1},
		      {"lzo1f_999",  lzo1f_999_compress,  lzo1f_decompress_safe, NULL,           LZO1F_999_MEM_COMPRESS, 67, 9},
		      {"lzo1b_1",    lzo1b_1_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     68, 1},
		      {"lzo1b_2",    lzo1b_2_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     68, 2},
		      {"lzo1b_3",    lzo1b_3_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     68, 3},
		      {"lzo1b_4",    lzo1b_4_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     68, 4},
		      {"lzo1b_5",    lzo1b_5_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     68, 5},
		      {"lzo1b_6",    lzo1b_6_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     68, 6},
		      {"lzo1b_7",    lzo1b_7_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     68, 7},
		      {"lzo1b_8",    lzo1b_8_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     68, 8},
		      {"lzo1b_9",    lzo1b_9_compress,    lzo1b_decompress_safe, NULL,           LZO1B_MEM_COMPRESS,     68, 9},
		      {"lzo1b_99",   lzo1b_99_compress,   lzo1b_decompress_safe, NULL,           LZO1B_99_MEM_COMPRESS,  69, 9},
		      {"lzo1b_999",  lzo1b_999_compress,  lzo1b_decompress_safe, NULL,           LZO1B_999_MEM_COMPRESS, 70, 9},
		      {"lzo2a_999",  lzo2a_999_compress,  lzo2a_decompress_safe, NULL,           LZO2A_999_MEM_COMPRESS, 80, 9},

		    };	      


/* fwd decl */
extern ddr_plugin_t ddr_plug;

enum compmode {AUTO=0, COMPRESS, DECOMPRESS};

typedef struct _lzo_state {
	void *workspace;
	unsigned char *dbuf, *orig_dbuf;
	size_t dbuflen;
       	int hdroff;
	unsigned char *obuf;
	unsigned int slackpre, slackpost;
	uint32_t flags;
	int seq;
	char hdr_seen, eof_seen, do_bench, do_opt;
	enum compmode mode;
	comp_alg *algo;
	const opt_t *opts;
	/* Statistics */
	unsigned int nr_memmove, nr_realloc;
	unsigned int cmp_hdr;
	size_t cmp_ln, unc_ln;
	/* Bench */
	clock_t cpu;
} lzo_state;

#define FPLOG(lvl, fmt, args...) \
	ddr_plug.fplog(stderr, lvl, "lzo(%i): " fmt, state->seq, ##args)

static unsigned int pagesize = 4096;

void lzo_hdr(header_t* hdr, lzo_state *state)
{
	memset(hdr, 0, sizeof(header_t));
	hdr->version = htons(F_VERSION);
	hdr->lib_version = htons(LZO_VERSION);
	if (state->algo->meth <= 3)
		hdr->version_needed_to_extract = htons(0x0940);
	else
		hdr->version_needed_to_extract = htons(F_VERSION);
	hdr->method = state->algo->meth;
	hdr->level = state->algo->lev;
	hdr->flags = htonl(state->flags);
	hdr->nmlen = NAMELEN;
	if (state->opts->iname) {
		memcpy(hdr->name, state->opts->iname, MIN(NAMELEN,strlen(state->opts->iname)));
		struct stat stbf;
		if (0 == stat(state->opts->iname, &stbf)) {
			hdr->mode = htonl(stbf.st_mode);
			hdr->mtime_low = htonl(stbf.st_mtime & 0xffffffff);
#if __WORDSIZE != 32
			hdr->mtime_high = htonl(stbf.st_mtime >> 32);
#endif
		}
	}
	hdr->hdr_checksum = htonl(lzo_adler32(ADLER32_INIT_VALUE, (const lzo_bytep)hdr, offsetof(header_t, hdr_checksum)));
	state->hdr_seen = sizeof(header_t);
}

int lzo_parse_hdr(unsigned char* bf, lzo_state *state)
{
	header_t *hdr = (header_t*)bf;
	if (ntohs(hdr->version_needed_to_extract) > 0x1030 && hdr->version_needed_to_extract != htons(F_VERSION)) {
		FPLOG(FATAL, "requires version %01x.%03x to extract\n",
			ntohs(hdr->version_needed_to_extract) >> 12,
			ntohs(hdr->version_needed_to_extract) & 0xfff);
		return -2;
	}
	comp_alg *ca, *ca2 = NULL;
	state->algo = NULL;
	for (ca = calgos; ca < calgos+sizeof(calgos)/sizeof(comp_alg); ++ca) {
		if (hdr->method == ca->meth) {
			ca2 = ca;
			if (hdr->level == ca->lev) {
				state->algo = ca;
				break;
			}
		}
	}
	if (!ca2) {
		FPLOG(FATAL, "unsupported method %i level %i\n", hdr->method, hdr->level);
		return -3;
	}
	/* lzop -1 special case: 2/1 means lzo1x_1_15 not _1_11 */
	if (state->algo == calgos+1 && ntohs(hdr->version) != F_VERSION)
		state->algo += 2;
	/* If we have not found an exact match, just use the family -- good enough to decode */
	if (!state->algo)
		state->algo = ca2;

	state->flags = ntohl(hdr->flags);
	if (state->flags & F_MULTIPART) {
		FPLOG(FATAL, "unsupported multipart archive\n");
		return -4;
	}
	if ((state->flags & (F_CRC32_C | F_ADLER32_C)) == (F_CRC32_C | F_ADLER32_C)) {
		FPLOG(FATAL, "Can't have both CRC32_C and ADLER32_C\n");
		return -5;
	}
	if ((state->flags & (F_CRC32_D | F_ADLER32_D)) == (F_CRC32_D | F_ADLER32_D)) {
		FPLOG(FATAL, "Can't have both CRC32_D and ADLER32_D\n");
		return -5;
	}

	uint32_t cksum = ntohl(*(uint32_t*)((char*)hdr+offsetof(header_t,name)+hdr->nmlen));
	uint32_t comp = (state->flags & F_H_CRC32 ? lzo_crc32(  CRC32_INIT_VALUE, (const lzo_bytep)hdr, sizeof(header_t)-NAMELEN+hdr->nmlen-4)
						: lzo_adler32(ADLER32_INIT_VALUE, (const lzo_bytep)hdr, sizeof(header_t)-NAMELEN+hdr->nmlen-4));
	if (cksum != comp) {
		FPLOG(FATAL, "header fails checksum %08x != %08x\n",
			cksum, comp);
		return -6;
	}
	int off = sizeof(header_t) + hdr->nmlen-NAMELEN;
	if (state->flags & F_H_EXTRA_FIELD) {
		off += 8 + ntohl(*(uint32_t*)(bf+off));
		if (off > 4000) {
			FPLOG(FATAL, "excessive extra field size %i\n", off);
			return -7;
		}
	}
	state->hdr_seen = off;
	state->cmp_hdr += off;
	return off;
}

void block_hdr(blockhdr_t* hdr, uint32_t uncompr, uint32_t compr, uint32_t unc_cks, void *cdata, uint32_t flags)
{
	hdr->uncmpr_len = htonl(uncompr);
	hdr->cmpr_len = htonl(compr);
	hdr->uncmpr_chksum = htonl(unc_cks);
	/* Don't overwrite copied data or compressed data without F_ADLER32_C 
	 * TODO: We should support CRC32 here ... */
	if (cdata != &hdr->cmpr_chksum)
	       	hdr->cmpr_chksum = htonl(flags & F_ADLER32_C?
				lzo_adler32(ADLER32_INIT_VALUE, (const lzo_bytep)cdata, compr):
				lzo_crc32(CRC32_INIT_VALUE, (const lzo_bytep)cdata, compr));
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

const char *lzo_help = "The lzo plugin for dd_rescue de/compresses data on the fly.\n"
		" It does not support sparse writing.\n"
		" Parameters: compress/decompress/benchmark/algo=lzo1?_?/optimize/flags=XXX\n"
		"  Use algo=help for a list of (de)compression algorithms.\n";


void chose_alg(char* anm, lzo_state *state)
{
	comp_alg *ca;
	if (!strcmp(anm, "help")) {
		FPLOG(INFO, "Algorithm (mem, meth, lev)\n");
		for (ca = calgos; ca < calgos+sizeof(calgos)/sizeof(comp_alg); ++ca)
			FPLOG(INFO, "%s (%i, %i, %i)\n",
					ca->name, ca->workmem, ca->meth, ca->lev);
		exit(1);
	}
	for (ca = calgos; ca < calgos+sizeof(calgos)/sizeof(comp_alg); ++ca) {
		if (!strcmp(ca->name, anm)) {
			state->algo = ca;
			return;
		}
	}
	FPLOG(FATAL, "Algorithm %s not found, try algo=help\n", anm);
	exit(13);
}


int lzo_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	int err = 0;
	lzo_state *state = (lzo_state*)malloc(sizeof(lzo_state));
	if (!state) {
		FPLOG(FATAL, "can't allocate %i bytes\n", sizeof(lzo_state));
		return -1;
	}
	memset(state, 0, sizeof(lzo_state));
	*stat = (void*)state;
	state->mode = AUTO;
	state->seq = seq;
	state->algo = calgos;
	state->opts = opt;
	/* Notes: We want checksums on compressed content; lzop forces us to do both then 
	 * CRC32 has better error protection quality than adler32 -- but the implementation
	 * in liblzo is rather slow, so stick with adler32 for now ..., unfortunately
	 * file fmt does not allow crc32c, which has HW acceleration on various platforms */
	state->flags = F_OS_UNIX | F_ADLER32_C | F_ADLER32_D;	/* 0x03000003 */
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			FPLOG(INFO, "%s", lzo_help);
		else if (!memcmp(param, "compr", 5))
			state->mode = COMPRESS;
		else if (!memcmp(param, "decom", 5))
			state->mode = DECOMPRESS;
		else if (!memcmp(param, "bench", 5))
			state->do_bench = 1;
		else if (!memcmp(param, "opt", 3))
			state->do_opt = 1;
		else if (!memcmp(param, "algo=", 5))
			chose_alg(param+5, state);
		else if (!memcmp(param, "alg=", 4))
			chose_alg(param+4, state);
		else if (!memcmp(param, "algorithm=", 10))
			chose_alg(param+10, state);
		else if (!memcmp(param, "flags=", 6)) {
			state->flags = strtol(param+6, NULL, 0);
			/* TODO Sanity check for flags ... */
			//FPLOG(INFO, "Flags: %08x\n", state->flags);
		} else {
			FPLOG(FATAL, "plugin doesn't understand param %s\n",
				param);
			++err;
		}
		param = next;
	}
	pagesize = opt->pagesize;
	return err;
}

void* slackalloc(size_t ln, lzo_state *state)
{
	unsigned char *ptr = (unsigned char*)malloc(ln+state->slackpre+state->slackpost+pagesize);
	if (!ptr) {
		FPLOG(FATAL, "allocation of %i bytes failed: %s\n",
			ln+state->slackpre+state->slackpost, strerror(errno));
		exit(13);
	}
	state->orig_dbuf = ptr;
	ptr += state->slackpre + pagesize-1;
	ptr -= (unsigned long)ptr%pagesize;
	return ptr;
}

void* slackrealloc(void* base, size_t newln, lzo_state *state)
{
	unsigned char *ptr, *optr;
	++state->nr_realloc;
	/* Note: We could use free and malloc IF we have no data decompressed yet 
	 * (d_off == 0) and no slack space from plugins behind us is needed.
	 * Probably not worth the effort ... */
	ptr = (unsigned char*)malloc(newln+state->slackpre+state->slackpost+pagesize);
	/* Note: We can be somewhat graceful if realloc fails by returning the original
	 * pointer and buffer size and raise(SIGQUIT) -- this would result in 
	 * writing out data that has been processed already.
	 */
	if (!ptr) {
		FPLOG(FATAL, "reallocation of %i bytes failed: %s\n",
			newln+state->slackpre+state->slackpost, strerror(errno));
		raise(SIGQUIT);
		return NULL;
	}
	optr = ptr;
	ptr += state->slackpre + pagesize-1;
	ptr -= (unsigned long)ptr%pagesize;
	memcpy(ptr-state->slackpre, (char*)base-state->slackpre, state->dbuflen+state->slackpre+state->slackpost);
	free(state->orig_dbuf);
	state->orig_dbuf = optr;
	return ptr;
}

void slackfree(void* base, lzo_state *state)
{
	//free(base-state->slackpre);
	free(state->orig_dbuf);
}

/* int ifd, const char* inm, loff_t ioff, 
	     int ofd, const char* onm, loff_t ooff, 
	     unsigned int bsz, unsigned int hsz,
	     loff_t exfer, */
int lzo_open(const opt_t *opt, int olnchg, 
	     unsigned int totslack_pre, unsigned int totslack_post,
	     void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	state->opts = opt;
	state->hdroff = 0;
	const unsigned int bsz = opt->softbs;
	if (lzo_init() != LZO_E_OK) {
		FPLOG(FATAL, "failed to initialize lzo library!");
		return -1;
	}
	if (state->mode == AUTO) {
		if (!strcmp(opt->iname+strlen(opt->iname)-2, "zo"))
			state->mode = DECOMPRESS;
		else if (!strcmp(opt->oname+strlen(opt->oname)-2, "zo"))
			state->mode = COMPRESS;
		else {
			FPLOG(FATAL, "can't determine compression/decompression from filenames (and not set)!\n");
			return -1;
		}
	}
	if (state->mode == COMPRESS) {
		state->workspace = malloc(state->algo->workmem);
		if (!state->workspace) {
			FPLOG(FATAL, "can't allocate workspace of size %i for compression!\n", state->algo->workmem);
			return -1;
		}
		state->dbuflen = bsz + (bsz>>4) + 72 + sizeof(lzop_hdr) + sizeof(header_t);
	} else {
		state->dbuflen = 4*bsz+16;
	}
	state->slackpost = totslack_post;
	state->slackpre  = totslack_pre ;
	state->dbuf = (unsigned char*)slackalloc(state->dbuflen, state);
	if (state->do_bench) 
		state->cpu = 0;
	return 0;
	/* This breaks MD5 in chain before us
	return consumed;
	*/
}

/* TODO: 
 * - Detect sparseness and encode 
 */
unsigned char* lzo_compress(fstate_t *fst, unsigned char *bf, 
			    int *towr, int eof, lzo_state *state)
{
	const loff_t ooff = fst->opos;
	lzo_uint dst_len = state->dbuflen-3-sizeof(lzop_hdr)-sizeof(header_t);
	unsigned char *hdrp = state->dbuf+3+sizeof(lzop_hdr);
	unsigned char *bhdp = hdrp+sizeof(header_t);
	unsigned char *wrbf = bhdp;
	unsigned int addwr = 0;
	if (ooff == state->opts->init_opos) {
		if (state->opts->init_opos > 0 && state->opts->extend) {
			ssize_t ln = pread(fst->odes, bhdp, 512, 0);
			if (ln < (int)(sizeof(lzop_hdr)+sizeof(header_t)-NAMELEN)) {
				FPLOG(FATAL, "Can't extend lzo file with incomplete header of size %i\n", ln);
				abort();
			}
			if (memcmp(bhdp, lzop_hdr, sizeof(lzop_hdr))) {
				FPLOG(FATAL, "Can only extend lzo files with existing magic\n", ln);
				abort();
			};
			if (lzo_parse_hdr(bhdp+sizeof(lzop_hdr), state) < 0)
				abort();
			/* TODO (optional): Jump block headers to see whether we are at a valid offset */
			/* Overwrite EOF */
			fst->opos -= 4;
		} else {
			memcpy(state->dbuf+3, lzop_hdr, sizeof(lzop_hdr));
			lzo_hdr((header_t*)hdrp, state);
			addwr = sizeof(header_t) + sizeof(lzop_hdr);
			wrbf = state->dbuf+3;
			state->cmp_hdr += sizeof(lzop_hdr)+sizeof(header_t);
		}
	}
	/* NOTE: We always calc checksum of uncompressed data, as we don't get a
	 * checksum at all otherwise (lzop decompressor does bit allow for checksums
	 * exclusively on compressed data). */
	unsigned int hlen = sizeof(blockhdr_t)-4+((state->flags&(F_ADLER32_C|F_CRC32_C))? 4: 0);
	if (*towr) {
		/* TODO: Sparse support: Check for jumps and encode in blocks ... */
		unsigned char *cdata = bhdp+hlen;
		uint32_t unc_cks = state->flags & F_ADLER32_D? 
			lzo_adler32(ADLER32_INIT_VALUE, bf, *towr):
			lzo_crc32(CRC32_INIT_VALUE, bf, *towr);
		int err = state->algo->compress(bf, *towr, cdata, &dst_len, state->workspace);
		assert(err == 0);
		if (dst_len >= (unsigned int)*towr) {
			/* We NEED to do the same optimization as lzop if dst_len >= *towr, if we
			 * want to be compatible, as the * lzop ddecompression code otherwise bails
			 * out, sigh.
			 * So if this is the case, copy original block; decompression recognizes
			 * this by cmp_len == unc_len ....
			 * lzop does not write second checksum IF it's just a mem cop
			 *
			 * TODO: We could return original buffer instead  
			 * and save a copy -- don't bother for now ...
			 * as the added header makes this somewhat complex.
			 */
			hlen = sizeof(blockhdr_t)-4;
			cdata = bhdp+hlen;
			memcpy(cdata, bf, *towr);
			dst_len = *towr;
		} else if (state->do_opt && state->algo->optimize) {
			/* Note that this memcpy could be avoided for performance.
			 * But we don't optimize for optimize ... it's not useful enough */
			memcpy(bf, cdata, dst_len);
			state->algo->optimize(bf, dst_len, cdata, &dst_len, state->workspace);
		}
		state->cmp_hdr += hlen;
		state->cmp_ln += dst_len; state->unc_ln += *towr;
		block_hdr((blockhdr_t*)bhdp, *towr, dst_len, unc_cks, cdata, state->flags);
		*towr = dst_len + hlen + addwr;
	}
	if (eof) {
		state->cmp_hdr += 4;
		memset(wrbf+*towr, 0, 4);
		*towr += 4;
	}
	return wrbf;
}
				
int recover_decompr_error(lzo_state *state, fstate_t *fst,
			  int c_off, int d_off, int addoff,
       			  uint32_t cmp_len, uint32_t unc_len,
			  const char* msg)
{
	int can_recover = 0;
	/* TODO: Do magic to determine if we can recover ... */
	enum ddrlog_t prio = can_recover? WARN: FATAL;
	FPLOG(prio, "decompr error in block @%i/%i (size %i+%i/%i): %s\n",
			fst->ipos + c_off + state->hdroff,
			fst->opos + d_off,
			addoff, cmp_len, unc_len,
			msg);
	loff_t alt_ipos = state->opts->init_ipos?
				state->opts->init_ipos+state->cmp_ln+state->cmp_hdr-sizeof(lzop_hdr)-state->hdr_seen:
				state->cmp_ln+state->cmp_hdr;
	assert(fst->ipos+c_off+state->hdroff == alt_ipos);
	return can_recover;
}


/* TODO:
 * - Debug: Output block boundaries
 * - On error, see whether we can be graceful (jump ahead and continue),
 *    otherwise output info on where we left off ... (sparseness)
 */
unsigned char* lzo_decompress(fstate_t *fst, unsigned char* bf, int *towr,
			      int eof, lzo_state *state)
{
	const loff_t ooff = fst->opos;
	/* Decompression is tricky */
	int c_off = 0;
	int d_off = 0;
	if (!*towr)
		return bf;
	/* header parsing has happened in _open callback ... */
	if (!state->hdr_seen) {
		assert(ooff - state->opts->init_opos == 0);
		if (memcmp(bf, lzop_hdr, sizeof(lzop_hdr))) {
			if (state->opts->init_ipos == 0) {
				FPLOG(FATAL, "lzop magic broken\n");
				abort();
			} else {
				ssize_t ln = pread(fst->ides, state->dbuf, 512, 0);
				if (ln < (int)(sizeof(lzop_hdr) + sizeof(header_t)-NAMELEN)) {
					FPLOG(FATAL, "lzop read too short (%i) for header\n", ln);
					abort();
				}
				if (memcmp(state->dbuf, lzop_hdr, sizeof(lzop_hdr))) {
					FPLOG(FATAL, "lzop magic broken\n");
					abort();
				}
				if (lzo_parse_hdr(state->dbuf+sizeof(lzop_hdr), state) < 0)
					abort();
			}
		} else {	
			state->cmp_hdr = sizeof(lzop_hdr);
			c_off += sizeof(lzop_hdr);
			int err = lzo_parse_hdr(bf+c_off, state);
			if (err < 0)
				abort();
			c_off += err;
		}
	}
	/* Now do processing: Do we have a full block? */
	do {
		uint32_t cmp_len, unc_len = 0;
		lzo_uint dst_len;
		const size_t totbufln = state->opts->softbs - ddr_plug.slack_post*((state->opts->softbs+15)/16);
		unsigned char* effbf = bf+c_off+state->hdroff;
		LZO_DEBUG(FPLOG(INFO, "dec blk @ %p (offs %i, stoffs %i, bln %zi, tbw %i)\n",
				effbf, effbf-state->obuf, state->hdroff, totbufln, *towr));
		blockhdr_t *hdr = (blockhdr_t*)effbf;
		const size_t have_len = *towr-state->hdroff-c_off;
		/* No more bytes left: This is ideal :-) */
		if (have_len == 0) {
			state->hdroff = 0;
			fst->buf = state->obuf;
			break;
		}
		/* EOF marker */
		if (have_len >= 4) {
			unc_len = ntohl(hdr->uncmpr_len);
			if (!unc_len) {	
				/* EOF */
				state->eof_seen = 1;
				state->cmp_hdr += 4;
				if (have_len != 4)
					FPLOG(WARN, "%i+ bytes after EOF @ %i ignored\n", have_len-4, 
						state->cmp_ln+state->cmp_hdr);
				break;
			}
		}
		/* Not enough data to read header; move to beginning of buffer */
		if (have_len < 8) {
			if (effbf != state->obuf) {
				memmove(state->obuf, effbf, have_len);
				++state->nr_memmove;
			}
			state->hdroff = -have_len;
			fst->buf = state->obuf+have_len;
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

		/* No second checksum .... */
		if (cmp_len == unc_len && addoff > 12) {
			addoff -= 4;
			cmp_cksum = unc_cksum;
		}
		LZO_DEBUG(FPLOG(INFO, "dec blk @ %p (hdroff %i, cln %i, uln %i, have %i)\n",
				effbf, c_off+state->hdroff, cmp_len, unc_len, have_len));
		/* Block incomplete? */
		if (addoff+cmp_len > have_len) {
			/* incomplete block */
			if (effbf+addoff+cmp_len <= state->obuf+totbufln 
				&& fst->buf+*towr+state->opts->softbs <= state->obuf+totbufln) {
				/* We have enough space to just append: 
				 * Block will fit and so will next read ... */
				state->hdroff -= *towr-c_off;
				fst->buf += *towr;
				LZO_DEBUG(FPLOG(INFO, "append  @ %p\n", fst->buf));
				/* Simplify to addoff+cmp_len+state->softbs < totbufln ? */
			} else if (addoff+cmp_len < totbufln &&
					have_len+state->opts->softbs < totbufln) {
				/* We need to move block to beg of buffer */
				LZO_DEBUG(FPLOG(INFO, "move %i bytes to buffer head\n", have_len));
				if (effbf != state->obuf) {
					memmove(state->obuf, effbf, have_len);
					++state->nr_memmove;
				}
				state->hdroff = -have_len;
				fst->buf = state->obuf+have_len;
				//c_off = 0;
			} else {
				/* Our buffer is too small */
				recover_decompr_error(state, fst, c_off, d_off, addoff, cmp_len, unc_len,
						"Read blocks too small");
				FPLOG(FATAL, "Can't assemble block of size %i, increase softblocksize to at least %i\n", 
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
				int rec = recover_decompr_error(state, fst, c_off, d_off, addoff, cmp_len, unc_len,
					"compr checksum mismatch");
				if (!rec)
					raise(SIGQUIT);
				break;
			}
		}
		dst_len = state->dbuflen-d_off;
		if (dst_len < unc_len) {
			/* If memalloc fails, we'll abort in a second, so warn ... */
			if (unc_len > 16*1024*1024)
				FPLOG(WARN, "large uncompressed block sz %i @%i\n",
						unc_len, state->cmp_ln+state->cmp_hdr);
			size_t newlen = unc_len+d_off+255;
			newlen -= newlen%256;
			unsigned char *newbuf = (unsigned char*)slackrealloc(state->dbuf, newlen, state);
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
			if (cmp_len > unc_len)
				FPLOG(WARN, "compressed %i > uncompressed %i breaks lzop\n",
					cmp_len, unc_len);
			err = state->algo->decompr(effbf+addoff, cmp_len, (unsigned char*)state->dbuf+d_off, &dst_len, NULL);
			LZO_DEBUG(FPLOG(INFO, "decompressed %i@%p -> %i\n",
				cmp_len, effbf+addoff, dst_len));
			if (dst_len != unc_len)
				FPLOG(WARN, "inconsistent uncompressed size @%i: %i <-> %i\n",
					state->cmp_ln+state->cmp_hdr, unc_len, dst_len);
		} else {
			memcpy(state->dbuf+d_off, effbf+addoff, unc_len);
			dst_len = unc_len;
		}
		switch (err) {
		case LZO_E_INPUT_OVERRUN:
			/* TODO: Partial block, handle! */
			FPLOG(FATAL, "input overrun @ %i: %i %i %i; try larger block sizes\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			if (0 == recover_decompr_error(state, fst, c_off, d_off, addoff, cmp_len, unc_len,
						       "input overrun"))
				raise(SIGQUIT);
			break;
		case LZO_E_EOF_NOT_FOUND:
			/* TODO: Partial block, handle! */
			FPLOG(FATAL, "EOF not found @ %i: %i %i %i; try larger block sizes\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			if (0 == recover_decompr_error(state, fst, c_off, d_off, addoff, cmp_len, unc_len,
						       "EOF not found"))
				raise(SIGQUIT);
			break;
		case LZO_E_OUTPUT_OVERRUN:
			FPLOG(FATAL, "output overrun @ %i: %i %i %i; try larger block sizes\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			if (0 == recover_decompr_error(state, fst, c_off, d_off, addoff, cmp_len, unc_len,
						       "output overrun"))
				raise(SIGQUIT);
			break;
		case LZO_E_LOOKBEHIND_OVERRUN:
			FPLOG(FATAL, "lookbehind overrun @ %i: %i %i %i; data corrupt?\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			if (0 == recover_decompr_error(state, fst, c_off, d_off, addoff, cmp_len, unc_len,
						       "lookbehind overrun"))
				raise(SIGQUIT);
			break;
		case LZO_E_ERROR:
			FPLOG(FATAL, "unspecified error @ %i: %i %i %i; data corrupt?\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			if (0 == recover_decompr_error(state, fst, c_off, d_off, addoff, cmp_len, unc_len,
						       "unspecified error"))
				raise(SIGQUIT);
			break;
		case LZO_E_INPUT_NOT_CONSUMED:
			/* TODO: Leftover bytes, store */
			FPLOG(INFO, "input not fully consumed @ %i: %i %i %i\n", 
					state->cmp_ln+state->cmp_hdr, *towr, state->dbuflen, dst_len);
			recover_decompr_error(state, fst, c_off, d_off, addoff, cmp_len, unc_len,
					       "input not consumed");
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
				FPLOG(FATAL, "decompr checksum mismatch @ %i\n",
						state->cmp_ln+state->cmp_hdr);
				if (0 == recover_decompr_error(state, fst, c_off, d_off, addoff, cmp_len, unc_len,
							       "decompr checksum mismatch"))
					raise(SIGQUIT);
				break;
			}
		}
		state->cmp_hdr += addoff;
		c_off += cmp_len+addoff;
		d_off += dst_len;
		state->cmp_ln += cmp_len; 
		state->unc_ln += dst_len;
	} while (1);
	if (eof && !state->eof_seen)
		FPLOG(WARN, "End of input @ %i but no EOF marker seen\n", state->cmp_ln+state->cmp_hdr);
	*towr = d_off;
	return state->dbuf;
}


unsigned char* lzo_block(fstate_t *fst, unsigned char* bf, 
			 int *towr, int eof, void **stat)
{
	lzo_state *state = (lzo_state*)*stat;
	if (!state->obuf)
		state->obuf = fst->buf;
	unsigned char* ptr;
	clock_t t1 = 0;
	if (state->do_bench) 
		t1 = clock();
	if (state->mode == COMPRESS) 
		ptr = lzo_compress(  fst, bf, towr, eof, state);
	else
		ptr = lzo_decompress(fst, bf, towr, eof, state);
	if (state->do_bench)
		state->cpu += clock() - t1;
	return ptr;
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
		FPLOG(INFO, "%s_compress %.1fkiB (%1.f%%) + %i <- %.1fkiB\n",
			state->algo->name,
			state->cmp_ln/1024.0, 
			100.0*((double)state->cmp_ln/state->unc_ln),
			state->cmp_hdr,
			state->unc_ln/1024.0);
	else {
		FPLOG(INFO, "%s_decompr %.1fkiB (%.1f%%) + %i -> %.1fkiB\n",
			state->algo->name,
			state->cmp_ln/1024.0, 
			100.0*((double)state->cmp_ln/state->unc_ln),
			state->cmp_hdr,
			state->unc_ln/1024.0);
		if (state->do_bench)
			FPLOG(INFO, "%i reallocs (%ikiB), %i moves\n",
				state->nr_realloc, state->dbuflen/1024,
				state->nr_memmove);
	}
	/* Only output if it took us more than 0.05s, otherwise it's completely meaningless */
	if (state->do_bench && state->cpu/(CLOCKS_PER_SEC/20) > 0)
		FPLOG(INFO, "%.2fs CPU time, %.1fMiB/s\n",
				(double)state->cpu/CLOCKS_PER_SEC, 
				state->unc_ln/1024 / (state->cpu/(CLOCKS_PER_SEC/1024.0)));
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


