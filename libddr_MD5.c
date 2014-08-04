/* libddr_MD5.c
 *
 * plugin for dd_rescue, calculating a hash value during copying ...
 * A PoC for the plugin infrastructure ...
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 2014
 * License: GNU GPLv2 or v3
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#define _LARGEFILE64_SOURCE 1
#define _FILE_OFFSET_BITS 64

#include "ddr_plugin.h"
#include "ddr_ctrl.h"
#include "hash.h"
#include "md5.h"
#include "sha256.h"
#include "sha512.h"
#include "sha1.h"

#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#ifdef HAVE_ATTR_XATTR_H
# include <attr/xattr.h>
#endif

#include <netinet/in.h>	/* For ntohl/htonl */

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
	unsigned int hashln; /* in bytes */
} hashalg_t;

hashalg_t hashes[] = { 	{ "md5", md5_init, md5_64, md5_calc, md5_out, 64, 16 },
			{ "sha1", sha1_init, sha1_64, sha1_calc, sha1_out, 64, 20 },
			{ "sha256", sha256_init, sha256_64 , sha256_calc, sha256_out,  64, 32 },
			{ "sha224", sha224_init, sha256_64 , sha256_calc, sha224_out,  64, 28 },
			{ "sha512", sha512_init, sha512_128, sha512_calc, sha512_out, 128, 64 },
			{ "sha384", sha384_init, sha512_128, sha512_calc, sha384_out, 128, 48 }
			// SHA3 ...
};


typedef struct _hash_state {
	hash_t hash;
	loff_t hash_pos;
	const char *fname;
	const char *append, *prepend;
	hashalg_t *alg;
	uint8_t buf[288];	// enough for SHA-3 with max blksz of 144Bytes
	int seq;
	int outfd;
	unsigned char buflen;
	unsigned char ilnchg, olnchg, ichg, ochg, debug, outf, chkf, chkfalloc;
	const char* chkfnm;
	const opt_t *opts;
#ifdef HAVE_ATTR_XATTR_H
	char chk_xattr, set_xattr, xnmalloc, xfallback;
	char* xattr_name;
#endif
} hash_state;

/* TO DO: Add updating and reading MD5SUMS style files, optionally
 * as fallback for unavailable xattrs
 */

const char *hash_help = "The HASH plugin for dd_rescue calculates a cryptographic checksum on the fly.\n"
		" It supports unaligned blocks (arbitrary offsets) and holes(sparse writing).\n"
		" Parameters: output:outfd=FNO:outnm=FILE:check:chknm=FILE:debug:[alg[o[rithm]=]ALG\n"
		"\t:append=STR:prepend=STR:pbkdf2=ALG/PWD/SALT/ITER/LEN\n"
#ifdef HAVE_ATTR_XATTR_H
		"\t:chk_xattr[=xattr_name]:set_xattr[=xattr_name]:fallb[ack][=FILE]\n"
#endif
		" Use algorithm=help to get a list of supported hash algorithms\n";


hashalg_t *get_hashalg(hash_state *state, const char* nm)
{
	int i;
	const char help = !strcmp(nm, "help");
	if (help)
		FPLOG(INFO, "Supported algorithms:");
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

int do_pbkdf2(hash_state*, char*);

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
		else if (!memcmp(param, "append=", 7))
			state->append = param+7;
		else if (!memcmp(param, "prepend=", 8))
			state->prepend = param+8;
#ifdef HAVE_ATTR_XATTR_H
		else if (!memcmp(param, "chk_xattr=", 10)) {
			state->chk_xattr = 1; state->xattr_name = param+10; }
		else if (!strcmp(param, "chk_xattr"))
			state->chk_xattr = 1;
		else if (!memcmp(param, "set_xattr=", 10)) {
			state->set_xattr = 1; state->xattr_name = param+10; }
		else if (!strcmp(param, "set_xattr")) 
			state->set_xattr = 1;
		else if (!strcmp(param, "fallb")) 
			state->xfallback = 1;
		else if (!strcmp(param, "fallback")) 
			state->xfallback = 1;
		else if (!memcmp(param, "fallback=", 9)) {
			state->xfallback = 1; state->chkfnm = param+9; }
		else if (!memcmp(param, "fallb=", 6)) {
			state->xfallback = 1; state->chkfnm = param+6; }
#endif
		else if (!memcmp(param, "outnm=", 6)) {
			state->outf = 1; state->chkfnm=param+6; }
		else if (!memcmp(param, "chknm=", 6)) {
			state->chkf = 1; state->chkfnm=param+6; }
		else if (!strcmp(param, "check")) {
			state->chkf = 1; state->chkfnm="-"; }
		else if (!memcmp(param, "algo=", 5))
			state->alg = get_hashalg(state, param+5);
		else if (!memcmp(param, "alg=", 4))
			state->alg = get_hashalg(state, param+4);
		else if (!memcmp(param, "algorithm=", 10))
			state->alg = get_hashalg(state, param+10);
		else if (!memcmp(param, "pbkdf2=", 7))
			err += do_pbkdf2(state, param+7);
		/* elif .... */
		/* Hmmm, ok, let's support algname without alg= */
		else {
			hashalg_t *hash = get_hashalg(state, param);
			if (hash)
				state->alg = hash;
			else {
				FPLOG(FATAL, "plugin doesn't understand param %s\n",
					param);
				--err;
			}
		}
		param = next;
	}
	if (!state->alg) {
		FPLOG(FATAL, "No hash algorithm specified\n");
		--err;
	}
#ifdef HAVE_ATTR_XATTR_H
	if ((state->chk_xattr || state->set_xattr) && !state->xattr_name) {
		state->xattr_name = (char*)malloc(24);
		state->xnmalloc = 1;
		snprintf(state->xattr_name, 24, "user.checksum.%s", state->alg->name);
	}
#endif
	if ((!state->chkfnm || !*state->chkfnm) && (state->chkf || state->outf
#ifdef HAVE_ATTR_XATTR_H
				|| state->xfallback
#endif
			     				)) {
		char cfnm[32];
		// if (!strcmp(state->alg->name, "md5")) strcpy(cfnm, "MD5SUMS"); else
		snprintf(cfnm, 32, "CHECKSUMS.%s", state->alg->name);
		state->chkfalloc = 1;
		state->chkfnm = strdup(cfnm);
	}
	if (state->debug)
		FPLOG(DEBUG, "Initialized plugin %s (%s)\n", ddr_plug.name, state->alg->name);
	return err;
}

#define MIN(a,b) ((a)<(b)? (a): (b))
#define MAX(a,b) ((a)<(b)? (b): (a))

int hash_open(const opt_t *opt, int ilnchg, int olnchg, int ichg, int ochg,
	     unsigned int totslack_pre, unsigned int totslack_post,
	     void **stat)
{
	int err = 0;
	hash_state *state = (hash_state*)*stat;
	state->opts = opt;
	state->alg->hash_init(&state->hash);
	state->hash_pos = 0;
	if (!ochg && state->seq != 0)
		state->fname = opt->oname;
	else if (!ichg)
		state->fname = opt->iname;
	else {
		char* nnm = (char*)malloc(strlen(opt->iname)+strlen(opt->oname)+3);
		strcpy(nnm, opt->iname);
		strcat(nnm, "->");
		strcat(nnm, opt->oname);
		state->fname = nnm;
#ifdef HAVE_ATTR_XATTR_H
		if (state->chk_xattr || state->set_xattr) {
			--err;
			FPLOG(WARN, "Can't access xattr in the middle of a plugin chain!");
		}
#endif
	}
	if (state->prepend) {
		const int blksz = state->alg->blksz;
		int done = 0; int remain = strlen(state->prepend);
		while (remain >= blksz) {
			state->alg->hash_block((uint8_t*)(state->prepend)+done, &state->hash);
			remain -= blksz;
			done += blksz;
		}
		HASH_DEBUG(FPLOG(DEBUG, "Prepending %i+%i bytes (padded with %i bytes)\n",
				done, remain, blksz-remain));
		if (remain) {
			memcpy(state->buf, state->prepend+done, remain);
			memset(state->buf+remain, 0, blksz-remain);
			state->alg->hash_block(state->buf, &state->hash);
		}
	}
	memset(state->buf, 0, sizeof(state->buf));
	state->buflen = 0;
	state->ilnchg = ilnchg;
	state->olnchg = olnchg;
	state->ichg = ichg;
	state->ochg = ochg;
	if (ichg && ochg && (state->opts->sparse || !state->opts->nosparse)) {
		FPLOG(WARN, "Size of potential holes may not be correct due to other plugins;\n");
		FPLOG(WARN, " MD5 hash may be miscomputed! Avoid holes (remove -a, use -A).\n");
	}
	return err;
}

#if __WORDSIZE == 64
#define LL "l"
#elif __WORDSIZE == 32
#define LL "ll"
#else
#error __WORDSIZE unknown
#endif

inline int round_down(int val, const int gran)
{
	return val-val%gran;
}
	
#define round_up(v, g) round_down(v+g-1, g)

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
	if (state->append) {
		memcpy(state->buf+state->buflen, state->append, strlen(state->append));
		state->buflen += strlen(state->append);
		HASH_DEBUG(FPLOG(DEBUG, "Append string with %i bytes for hash\n", strlen(state->append)));
	}
	int preln = state->prepend? round_up(strlen(state->prepend), state->alg->blksz): 0;
	if (preln)
		HASH_DEBUG(FPLOG(DEBUG, "Account for %i extra prepended bytes\n", preln));
	state->alg->hash_calc(state->buf, state->buflen, state->hash_pos+state->buflen+preln, &state->hash);
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

/* 
 * XXXSUM file parsing and updating routines
 */

#ifndef HAVE_FEOF_UNLOCKED
#define feof_unlocked(x) feof(x)
#endif

#ifndef HAVE_GETLINE
ssize_t getline(char **bf, size_t *sz, FILE *f)
{
	if (*sz == 0) {
		*bf = (char*)malloc(1024);
		*sz = 1024;
	}
	char* bret = fgets(*bf, *sz, f);
	if (!bret)
		return -1;
	int ln = strlen(bret);
	//if (bret[ln-1] != '\n') increase_buffersize();
	return ln;
}
#endif

/* file offset in the chksum file which has the chksum for nm, -1 = not found */
off_t find_chks(hash_state* st, FILE* f, const char* nm, char* res)
{
	char *lnbf = NULL;
	size_t lln = 0;
	char* bnm = basename((char*)nm);
	while (!feof_unlocked(f)) {
		char *fnm, *fwh;
		off_t pos = ftello(f);
		ssize_t n = getline(&lnbf, &lln, f);
		if (n <= 0)
			break;
		fwh = strchr(lnbf, ' ');
		if (!fwh)
			continue;
		fnm = fwh;
		++fnm;
		if (*fnm == '*' || *fnm == ' ')
			fnm++;
		int last = strlen(fnm)-1;
		// Remove trailing \n\r
		while (last > 0 && (fnm[last] == '\n' || fnm[last] == '\r'))
			fnm[last--] = 0;
		if (!strcmp(fnm, nm) || !strcmp(fnm, bnm)) {
			if (res && fwh-lnbf <= 2*sizeof(hash_t)) {
				memcpy(res, lnbf, fwh-lnbf);
				res[fwh-lnbf] = 0;
			}
			free(lnbf);
			return pos;
		}
	}
	if (lnbf)
		free(lnbf);
	return -1;
}

FILE* fopen_chks(hash_state *state, const char* mode)
{
	const char* fnm = state->chkfnm;
	assert(fnm);
	if (!strcmp("-", fnm))
		return stdin;
	else
		return fopen(fnm, mode);
}

static char _chks[129];
/* get chksum */
char* get_chks(hash_state* state, const char* nm)
{
	FILE *f = fopen_chks(state, "r");
	if (!f)
		return NULL;
	*_chks = 0;
	find_chks(state, f, nm, _chks);
	if (f != stdin)
		fclose(f);
	return *_chks? _chks: NULL;
}

/* update chksum */
int upd_chks(hash_state* state, const char *nm, const char *chks)
{
	FILE *f = fopen_chks(state, "r+");
	int err = 0;
	if (!f) {
		errno = 0;
		f = fopen_chks(state, "w");
		if (!f)
			return -errno;
		fprintf(f, "%s *%s\n", chks, nm);
		err = -errno;
	} else {
		off_t pos = find_chks(state, f, nm, _chks);
		if (pos == -1 || strlen(chks) != strlen(_chks)) {
			fclose(f);
			f = fopen_chks(state, "a");
			fprintf(f, "%s *%s\n", chks, nm);
			err = -errno;
		} else {
			if (strcmp(chks, _chks)) {
				if (pwrite(fileno(f), chks, strlen(chks), pos) <= 0)
					err = -errno;
				//pwrite(fileno(f), "*", 1, pos+strlen(chks)+1);
			}
		}
	}
	fclose(f);
	return err;
}


#ifdef HAVE_ATTR_XATTR_H
int check_xattr(hash_state* state, const char* res)
{
	char xatstr[128];
	strcpy(xatstr, "xattr");
	const char* name = state->opts->iname;
	if (state->ichg && !state->ochg) {
		name = state->opts->oname;
		if (!state->opts->quiet)
			FPLOG(INFO, "Read xattr from output file %s\n", name);
	} else if (state->ichg) {
		FPLOG(WARN, "Can't read xattrs in the middle of plugin chain (%s)\n", state->fname);
		return -ENOENT;
	}
	/* Longest is 128byte hex for SHA512 (8x64byte numbers -> 8x16 digits) */
	char chksum[129];
	ssize_t itln = getxattr(name, state->xattr_name, chksum, 129);
	const int rln = strlen(res);
	if (itln <= 0) {
		if (state->xfallback) {
			char* cks = get_chks(state, name);
			snprintf(xatstr, 128, "chksum file %s", state->chkfnm);
			if (!cks) {
				FPLOG(WARN, "no hash found in xattr nor %s for %s\n", xatstr, name);
				return -ENOENT;
			} else if (strcmp(cks, res)) {
				FPLOG(WARN, "Hash from %s for %s does not match\n", xatstr, name);
				return -EBADF;
			}
		} else {
			FPLOG(WARN, "Hash could not be read from xattr of %s\n", name);
			return -ENOENT;
		}
	} else if (itln < rln || memcmp(res, chksum, rln)) {
		FPLOG(WARN, "Hash from xattr of %s does not match\n", name);
		return -EBADF;
	}
	if (!state->opts->quiet || state->debug)
		FPLOG(INFO, "Successfully validated hash from %s for %s\n", xatstr, name);
	return 0;
}

int write_xattr(hash_state* state, const char* res)
{
	const char* name = state->opts->oname;
	char xatstr[128];
	snprintf(xatstr, 128, "xattr %s", state->xattr_name);
	if (state->ochg && !state->ichg) {
		name = state->opts->iname;
		if (!state->opts->quiet)
			FPLOG(INFO, "Write xattr to input file %s\n", name);
	} else if (state->ochg) {
		FPLOG(WARN, "Can't write xattr in the middle of plugin chain (%s)\n",
				state->fname);
		return -ENOENT;
	}
	if (setxattr(name, state->xattr_name, res, strlen(res), 0)) {
		if (state->xfallback) {
			int err = upd_chks(state, name, res);
			snprintf(xatstr, 128, "chksum file %s", state->chkfnm);
			if (err) {
				FPLOG(WARN, "Failed writing to %s for %s: %s\n", 
						xatstr, name, strerror(-err));
				return err;
			}
		} else {
			FPLOG(WARN, "Failed writing hash to xattr of %s\n", name);
			return -errno;
		}
	}
	if (state->debug)
		FPLOG(DEBUG, "Set %s for %s to %s\n",
				xatstr, name, res);
	return 0;
}
#endif

int check_chkf(hash_state *state, const char* res)
{
	const char* name = state->opts->iname;
	if (state->ichg && !state->ochg) {
		name = state->opts->oname;
		if (!state->opts->quiet)
			FPLOG(INFO, "Read checksum from %s for output file %s\n", state->chkfnm, name);
	} else if (state->ichg) {
		FPLOG(WARN, "Can't read checksum in the middle of plugin chain (%s)\n", state->fname);
		return -ENOENT;
	}
	char* cks = get_chks(state, name);
	if (!cks) {
		FPLOG(WARN, "Can't find checksum in %s for %s\n", state->chkfnm, name);
		return -ENOENT;
	}
	if (strcmp(cks, res)) {
		FPLOG(WARN, "Hash from chksum file %s for %s does not match\n", state->chkfnm, name);
		return -EBADF;
	}
	return 0;
}

int write_chkf(hash_state *state, const char *res)
{
	const char* name = state->opts->oname;
	if (state->ochg && !state->ichg) {
		name = state->opts->iname;
		if (!state->opts->quiet)
			FPLOG(INFO, "Write checksum to %s for input file %s\n", state->chkfnm, name);
	} else if (state->ochg) {
		FPLOG(WARN, "Can't write checksum in the middle of plugin chain (%s)\n",
				state->fname);
		return -ENOENT;
	}
	int err = upd_chks(state, name, res);
	if (err) 
		FPLOG(WARN, "Hash writing to %s for %s failed\n", state->chkfnm, name);
	return err;
}

int hash_close(loff_t ooff, void **stat)
{
	int err = 0;
	hash_state *state = (hash_state*)*stat;
	char res[129];
	loff_t firstpos = (state->seq == 0? state->opts->init_ipos: state->opts->init_opos);
	state->alg->hash_out(res, &state->hash);
	if (!state->opts->quiet) 
		FPLOG(INFO, "%s %s (%" LL "i-%" LL "i): %s\n",
			state->alg->name, state->fname, firstpos, firstpos+state->hash_pos, res);
	if (state->outfd) {
		char outbuf[512];
		snprintf(outbuf, 511, "%s *%s\n", res, state->fname);
		if (write(state->outfd, outbuf, strlen(outbuf)) <= 0) {
			FPLOG(WARN, "Could not write HASH result to fd %i\n", state->outfd);
			--err;
		}
	}
	if (state->chkf) 
		err += check_chkf(state, res);
	if (state->outf)
		err += write_chkf(state, res);
#ifdef HAVE_ATTR_XATTR_H
	if (state->chk_xattr)
		err += check_xattr(state, res);
	if (state->set_xattr)
		err += write_xattr(state, res);
	if (state->xnmalloc)
		free((void*)state->xattr_name);
#endif
	if (state->chkfalloc)
		free((void*)state->chkfnm);
	if (strcmp(state->fname, state->opts->iname) && strcmp(state->fname, state->opts->oname))
		free((void*)state->fname);
	free(*stat);
	return err;
}

void memxor(unsigned char* p1, const unsigned char *p2, ssize_t ln)
{
	while (ln >= 4) {
		*(unsigned int*)p1 ^= *(unsigned int*)p2;
		ln -= 4;
		p1 += 4; p2 += 4;
	}
	while (ln-- > 0) 
		*p1++ ^= *p2++;
}

void hashout(unsigned char* hv, unsigned int hln)
{
	int i;
	for (i = 0; i < hln; ++i)
		fprintf(stderr, "%02x", hv[i+3-2*(i%4)]);
	fprintf(stderr, "\n");
}

int hmac(hashalg_t* hash, unsigned char* pwd, int plen,
			  unsigned char* msg, ssize_t mlen,
			  hash_t *hval)
{
	const unsigned int hlen = hash->hashln; 
	const unsigned int blen = hash->blksz;
	unsigned char ibuf[blen], obuf[blen];
	memset(ibuf, 0x36, blen);
	memset(obuf, 0x5c, blen);
	/* FIXME: Shouldn't this be blksz-9 */
	if (plen > hash->blksz) {
		hash_t hv;
		unsigned char pcpy[2*blen];
		memcpy(pcpy, pwd, plen);
		hash->hash_init(&hv);
		hash->hash_calc(pcpy, plen, plen, &hv);
		memcpy(pwd, &hv, hlen); 
		pwd[hlen] = 0;
		plen = hlen;
	}
	memxor(ibuf, pwd, plen);
	memxor(obuf, pwd, plen);
	assert(blen >= hlen);
	unsigned char ihv[blen];
	hash->hash_init((hash_t*)ihv);
	hash->hash_block(ibuf, (hash_t*)ihv);
	hash->hash_calc(msg, mlen, blen+mlen, (hash_t*)ihv);
	hash->hash_init(hval);
	hash->hash_block(obuf, hval);
	hash->hash_calc(ihv, hlen, blen+hlen, hval);
#if 1
	hashout((unsigned char*)&hval, hlen);
#endif
	return 0;
}
		


int pbkdf2(hashalg_t *hash,   unsigned char* pwd,  int plen,
			      unsigned char* salt, int slen,
	   unsigned int iter, unsigned char* key,  int klen)
{
	/* TODO: Use secure buffer */
	hash_t hashval;
	const unsigned int hlen = hash->hashln;
	const unsigned int khrnd = 1+(klen-1)/hlen;
	const unsigned int khlen = hlen*khrnd;
	const unsigned int bflen = MAX(slen+4, hlen)+hash->blksz;
	unsigned char* buf = (unsigned char*)malloc(bflen);
	unsigned char* khash = (unsigned char*)malloc(khlen);
	memset(buf, 0, bflen); memset(khash, 0, khlen);
	if (plen > hlen) {
		hash_t hv;
		hash->hash_init(&hv);
		hash->hash_calc(pwd, plen, plen, &hv);
		memcpy(pwd, &hv, hlen); 
		pwd[hlen] = 0;
		plen = hlen;
	}
	/* TODO: Input validation */
	int i, p;
	int blen = slen+4;
	memcpy(buf, salt, slen);
	for (p = 0; p < khrnd; ++p) {
		unsigned int ctr = htonl(p+1);
		memcpy(buf+slen, &ctr, 4);
		if (iter) 
			hmac(hash, pwd, plen, buf, blen, &hashval);
		else 
			memcpy(&hashval, buf, hlen);
		memcpy(khash+p*hlen, &hashval, hlen);
		memcpy(key+p*hlen, &hashval, MIN(hlen, klen-p*hlen));
	}
	blen = hlen;
	for (i = 1; i < iter; ++i) {
		for (p = 0; p < khrnd; ++p) {
			memcpy(buf, khash+p*hlen, hlen);
			hmac(hash, pwd, plen, buf, hlen, (hash_t*)(khash+p*hlen));
			/* Store as init val for next iter */
			memxor(key+p*hlen, khash+p*hlen, MIN(hlen, klen-p*hlen));
		}
	}
	memset(khash, 0, khlen);
	memset(buf, 0, bflen);
	asm("":::"memory");
	free(khash);
	free(buf);
	return 0;
}

int do_pbkdf2(hash_state *state, char* param)
{
	char* next = strchr(param, '/');
	if (next)
		*next++ = 0;
	else
		goto out_err;
	hashalg_t *halg = get_hashalg(state, param);
	
	param = next;
	next = strchr(param, '/');
	if (next)
		*next++ = 0;
	else
		goto out_err;
	char* pwd = param;
	
	param = next;
	next = strchr(param, '/');
	if (next)
		*next++ = 0;
	else
		goto out_err;
	char* salt = param;

	param = next;
	next = strchr(param, '/');
	if (next)
		*next++ = 0;
	else
		goto out_err;
	unsigned int iter = atol(param);

	int klen = atol(next)/8;

	unsigned char *key = (unsigned char*)malloc(klen);

	int err = pbkdf2(halg, (unsigned char*)pwd, strlen(pwd), 
			 (unsigned char*)salt, strlen(salt),
			 iter, key, klen);
	
	FPLOG(INFO, "PBKDF2(%s, %s, %s, %i, %i) = ",
		halg->name, pwd, salt, iter, klen*8);
	hashout(key, klen);
	free(key);
	return err;
    out_err:
	FPLOG(FATAL, "Syntax: pbkdf2=ALG/PWD/SALT/ITER/KEYLEN\n");		
	return 1;
}


ddr_plugin_t ddr_plug = {
	//.name = "MD5",
	.slack_pre = 144,	// not yet used
	.slack_post = 288,	// not yet used
	.needs_align = 0,
	.handles_sparse = 1,
	.init_callback  = hash_plug_init,
	.open_callback  = hash_open,
	.block_callback = hash_blk_cb,
	.close_callback = hash_close,
};


