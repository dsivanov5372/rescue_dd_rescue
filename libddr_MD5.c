/* libddr_MD5.c
 *
 * plugin for dd_rescue, calculating a hash value during copying ...
 * A PoC for the plugin infrastructure ...
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPLv2 or v3
 */

#include "ddr_plugin.h"
#include "ddr_ctrl.h"
#include "hash.h"
#include "md5.h"
#include "sha256.h"
#include "sha512.h"
#include "sha1.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

// TODO: pass at runtime rather than compile time
#define HASH_DEBUG(x) if (state->debug) x

#define FPLOG(lvl, fmt, args...) \
	ddr_plug.fplog(stderr, lvl, "%s(%i): " fmt, ddr_plug.name, state->seq, ##args)

/* fwd decl */
extern ddr_plugin_t ddr_plug;

typedef void (hash_init_fn)(hash_t*);
typedef void (hash_block_fn)(const uint8_t* ptr, hash_t*);
typedef void (hash_calc_fn)(uint8_t* ptr, size_t chunk, size_t final, hash_t*);
typedef char* (hash_out_fn)(char* buf, const hash_t*);

typedef struct {
	const char* name;
	hash_init_fn *hash_init;
	hash_block_fn *hash_block;
	hash_calc_fn *hash_calc;
	hash_out_fn *hash_out;
	unsigned int blksz;
} hashalg_t;

hashalg_t hashes[] = { 	{ "md5", md5_init, md5_64, md5_calc, md5_out, 64 },
			{ "sha1", sha1_init, sha1_64, sha1_calc, sha1_out, 64 },
			{ "sha256", sha256_init, sha256_64 , sha256_calc, sha256_out,  64 },
			{ "sha224", sha224_init, sha256_64 , sha256_calc, sha224_out,  64 },
			{ "sha512", sha512_init, sha512_128, sha512_calc, sha512_out, 128 },
			{ "sha384", sha384_init, sha512_128, sha512_calc, sha384_out, 128 }
};


typedef struct _hash_state {
	hash_t hash;
	loff_t hash_pos;
	const char* fname;
	hashalg_t *alg;
	uint8_t buf[128];
	int seq;
	int outfd;
	unsigned char buflen;
	unsigned char ilnchg, olnchg, debug;
	const opt_t *opts;
} hash_state;


const char *hash_help = "The HASH plugin for dd_rescue calculates a cryptographic checksum on the fly.\n"
		" It supports unaligned blocks (arbitrary offsets) and sparse writing.\n"
		" Parameters: output:outfd=FNO:debug:alg[o[rithm]=ALG\n"
		" Use algorithm=help to get a list of supported hash algorithms\n";


hashalg_t *get_hashalg(hash_state *state, const char* nm)
{
	int i;
	const char help = !strcmp(nm, "help");
	if (help)
		FPLOG(INFO, "Supported algorithms:");
	// TODO: Handle alg=help
	for (i = 0; i < sizeof(hashes)/sizeof(hashalg_t); ++i) {
		if (help)
			fprintf(stderr, " %s", hashes[i].name);
		else if (!strcasecmp(nm, hashes[i].name))
			return hashes+i;
	}
	if (help)
		fprintf(stderr, "\n");
	return NULL;
}



int hash_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	int err = 0;
	hash_state *state = (hash_state*)malloc(sizeof(hash_state));
	*stat = (void*)state;
	memset(state, 0, sizeof(hash_state));
	state->seq = seq;
	state->opts = opt;
	state->alg = get_hashalg(state, ddr_plug.name);
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			FPLOG(INFO, "%s", hash_help);
		else if (!strcmp(param, "debug"))
			state->debug = 1;
		else if (!strcmp(param, "output"))
			state->outfd = 1;
		else if (!memcmp(param, "outfd=", 6))
			state->outfd = atoi(param+6);
		else if (!memcmp(param, "algo=", 5))
			state->alg = get_hashalg(state, param+5);
		else if (!memcmp(param, "alg=", 4))
			state->alg = get_hashalg(state, param+4);
		else if (!memcmp(param, "algorithm=", 10))
			state->alg = get_hashalg(state, param+10);
		/* elif .... */
		/* Hmmm, ok, let's support algname without alg= */
		else {
			hashalg_t *hash = get_hashalg(state, param);
			if (hash)
				state->alg = hash;
			else {
				FPLOG(FATAL, "plugin doesn't understand param %s\n",
					param);
				++err;
			}
		}
		param = next;
	}
	if (!state->alg) {
		FPLOG(FATAL, "No hash algorithm specified\n");
		++err;
	}
	if (state->debug)
		FPLOG(DEBUG, "Initialized plugin %s\n", ddr_plug.name);
	return err;
}

int hash_open(const opt_t *opt, int ilnchg, int olnchg,
	     unsigned int totslack_pre, unsigned int totslack_post,
	     void **stat)
{
	hash_state *state = (hash_state*)*stat;
	state->opts = opt;
	state->alg->hash_init(&state->hash);
	state->hash_pos = 0;
	state->fname = (state->seq == 0? opt->iname: opt->oname);
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

void hash_last(hash_state *state, loff_t pos)
{
	//hash_block(0, 0, ooff, stat);
	int left = pos - state->hash_pos;
	assert(state->buflen == left || (state->ilnchg && state->olnchg));
	/*
	fprintf(stderr, "HASH_DEBUG: %s: len=%li, hashpos=%li\n", 
		state->fname, len, state->hash_pos);
	 */
	HASH_DEBUG(FPLOG(DEBUG, "Last block with %i bytes\n", state->buflen));
	state->alg->hash_calc(state->buf, state->buflen, state->hash_pos+state->buflen, &state->hash);
	state->hash_pos += state->buflen;
}

static inline void hash_block_buf(hash_state* state, int clear)
{
	state->alg->hash_block(state->buf, &state->hash);
	state->hash_pos += state->alg->blksz;
	state->buflen = 0;
	if (clear)
		memset(state->buf, 0, clear);
}

#define MIN(a,b) ((a)<(b)? (a): (b))

void hash_hole(fstate_t *fst, hash_state *state, loff_t holelen)
{
	if (state->buflen) {
		HASH_DEBUG(FPLOG(DEBUG, "first sparse block (drain %i)\n", state->buflen));
		memset(state->buf+state->buflen, 0, state->alg->blksz-state->buflen);
		if (holelen >= state->alg->blksz-state->buflen) {
			holelen -= (state->alg->blksz-state->buflen);
			hash_block_buf(state, state->buflen);
		} else {
			state->buflen += holelen;
			return;
		}
	}
	assert(state->buflen == 0);
	HASH_DEBUG(FPLOG(DEBUG, "bulk sparse %i\n", holelen-holelen%state->alg->blksz));
	while (holelen >= state->alg->blksz) {
		hash_block_buf(state, 0);
		holelen -= state->alg->blksz;
	}
	assert(holelen >= 0 && holelen < state->alg->blksz);
	// memset(state->buf, 0, holelen);
	state->buflen = holelen;
	HASH_DEBUG(FPLOG(DEBUG, "sparse left %i (%i+%i)\n", holelen, state->hash_pos, state->buflen));
	return;
}

/* This is rather complex, as we handle both non-aligned first block size
 * as well as sparse files */
unsigned char* hash_blk_cb(fstate_t *fst, unsigned char* bf, 
			   int *towr, int eof, int *recall, void **stat)
{
	/* TODO: Replace usage of state->buf by using slack space
	 * Hmmm, really? Probably buffer management is not sophisticated enough currently ... */
	/* TODO: If both ilnchg and olnchg are set, switch off sanity checks and go into dumb mode */
	hash_state *state = (hash_state*)*stat;
	const loff_t pos = state->olnchg? 
			fst->ipos - state->opts->init_ipos:
			fst->opos - state->opts->init_opos;
	HASH_DEBUG(FPLOG(DEBUG, "block(%i/%i): towr=%i, eof=%i, pos=%" LL "i, hash_pos=%" LL "i, buflen=%i\n",
				state->seq, state->olnchg, *towr, eof, pos, state->hash_pos, state->buflen));
	// Handle hole (sparse files)
	const loff_t holesz = pos - (state->hash_pos + state->buflen);
	assert(holesz >= 0 || (state->ilnchg && state->olnchg));
	if (holesz && !(state->ilnchg && state->olnchg))
		hash_hole(fst, state, holesz);

	assert(pos == state->hash_pos+state->buflen || (state->ilnchg && state->olnchg));
	int consumed = 0;
	assert(bf);
	/* First block */
	if (state->buflen && *towr) {
		/* Reassemble and process first block */
		consumed = MIN(state->alg->blksz-state->buflen, *towr);
		HASH_DEBUG(FPLOG(DEBUG, "Append %i bytes @ %i to store\n", consumed, pos));
		memcpy(state->buf+state->buflen, bf, consumed);
		if (consumed+state->buflen == state->alg->blksz) {
			hash_block_buf(state, state->alg->blksz);
		} else {
			state->buflen += consumed;
			//memset(state->buf+state->buflen, 0, state->alg->blksz-state->buflen);
		}
	}

	assert(state->hash_pos+state->buflen == pos+consumed || (state->ilnchg && state->olnchg));
	/* Bulk buffer process */
	int to_process = *towr - consumed;
	assert(to_process >= 0);
	to_process -= to_process%state->alg->blksz;
	if (to_process) {
		HASH_DEBUG(FPLOG(DEBUG, "Consume %i bytes @ %i\n", to_process, pos+consumed));
		assert(state->buflen == 0);
		state->alg->hash_calc(bf+consumed, to_process, -1, &state->hash);
		consumed += to_process; state->hash_pos += to_process;
	}
	assert(state->hash_pos+state->buflen == pos+consumed || (state->ilnchg && state->olnchg));
	to_process = *towr - consumed;
	assert(to_process >= 0 && to_process < state->alg->blksz);
	/* Copy remainder into buffer */
	if (!(state->olnchg && state->ilnchg) && state->hash_pos + state->buflen != pos + consumed)
		FPLOG(FATAL, "Inconsistency: HASH pos %i, buff %i, st pos %" LL "i, cons %i, tbw %i\n",
				state->hash_pos, state->buflen, pos, consumed, *towr);
	if (to_process) {
		HASH_DEBUG(FPLOG(DEBUG, "Store %i bytes @ %" LL "i\n", to_process, pos+consumed));
		assert(state->buflen == 0);
		memcpy(state->buf+state->buflen, bf+consumed, to_process);
		state->buflen = to_process;
	}
	if (eof)
		hash_last(state, pos+*towr);
	return bf;
}



int hash_close(loff_t ooff, void **stat)
{
	hash_state *state = (hash_state*)*stat;
	char res[129];
	loff_t firstpos = (state->seq == 0? state->opts->init_ipos: state->opts->init_opos);
	FPLOG(INFO, "%s %s (%" LL "i-%" LL "i): %s\n",
		state->alg->name, state->fname, firstpos, firstpos+state->hash_pos, 
		state->alg->hash_out(res, &state->hash));
	if (state->outfd) {
		char outbuf[512];
		snprintf(outbuf, 511, "%s *%s\n", state->alg->hash_out(res, &state->hash), state->fname);
		if (write(state->outfd, outbuf, strlen(outbuf)) <= 0)
			FPLOG(WARN, "Could not write HASH result to fd %i\n", state->outfd);
	}
	free(*stat);
	return 0;
}


ddr_plugin_t ddr_plug = {
	//.name = "MD5",
	.slack_pre = 128,	// not yet used
	.slack_post = 128,	// not yet used
	.needs_align = 0,
	.handles_sparse = 1,
	.init_callback  = hash_plug_init,
	.open_callback  = hash_open,
	.block_callback = hash_blk_cb,
	.close_callback = hash_close,
};


