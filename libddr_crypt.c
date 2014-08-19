/** libddr_crypt.c
 *
 * plugin for dd_rescue, de/encrypting during copying ...
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
#include "aes.h"
#include "hash.h"
#include "pbkdf2.h"
#include "secmem.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

// TODO: pass at runtime rather than compile time
#define HASH_DEBUG(x) if (state->debug) x

#define FPLOG(lvl, fmt, args...) \
	ddr_plug.fplog(stderr, lvl, "%s(%i): " fmt, ddr_plug.name, state->seq, ##args)

/* fwd decl */
extern ddr_plugin_t ddr_plug;


typedef struct _crypt_state {
	alg_desc_t *alg, *engine;
	int seq;
	char enc, debug;
	int pad;
	sec_fields *sec;
	const opt_t *opts;
} crypt_state;

	

const char *crypt_help = "The crypt plugin for dd_rescue de/encrypts data copied on the fly.\n"
		" It supports unaligned blocks (arbitrary offsets) and holes(sparse writing).\n"
		" Parameters: [alg[o[rithm]]=]ALG:enc[rypt]:dec[rypt]:engine=STR:pad=STR\n"
		"\t:keyhex=HEX:keyfd=INT[@INT]:keyhexfd=INT[@INT]\n"
		"\t:ivhex=HEX:ivfd=INT[@INT]:ivhexfd=INT[@INT]\n"
		"\t:pass=STR:passhex=HEX:passfd=INT[@INT]:passhexfd=INT[@INT]\n"
		"\t:salt=STR:salthex=HEX:saltfd=INT[@INT]:salthexfd=INT[@INT]\n"
		" Use algorithm=help to get a list of supported crypt algorithms\n";


int crypt_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	int err = 0;
	crypt_state *state = (crypt_state*)malloc(sizeof(crypt_state));
	*stat = (void*)state;
	memset(state, 0, sizeof(crypt_state));
	state->seq = seq;
	state->opts = opt;
	state->enc = -1;
	char* algnm = NULL;
	char* eng = NULL;
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help"))
			FPLOG(INFO, "%s", crypt_help);
		else if (!strcmp(param, "debug"))
			state->debug = 1;
		else if (!strcmp(param, "encrypt") || !strcmp(param, "enc"))
			state->enc = 1;
		else if (!strcmp(param, "decrypt") || !strcmp(param, "dec"))
			state->enc = 0;
		else if (!memcmp(param, "engine=", 7))
			eng = param+7;
		else if (!memcmp(param, "algorithm=", 10))
			algnm = param+10;
		else if (!memcmp(param, "algo=", 5))
			algnm = param+5;
		else if (!memcmp(param, "alg=", 4))
			algnm = param+4;
		/* TODO: Parse key ... */

		/* Hmmm, ok, let's support algname without alg= */
		else
			algnm = param;
	}
	/* Now process params ... */
	/* 1st: Set engine: Default: aesni/aes_c */
	/* 2nd: Set alg: Default: AES192-CTR */
	/* 3rd: Padding */
	/* 4th: pass */
	/* 5th: salt (later: if not given: derive from outnm) */
	/* 6th: key (later: defaults to pbkdf(pass, salt) */
	/* 7th: iv (later: defaults to salt) */

}

