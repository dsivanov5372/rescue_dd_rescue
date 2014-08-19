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

#include "aes_c.h"
#include "aes_ossl.h"
#ifdef HAVE_AESNI
#include "aesni.h"
#endif

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
	aes_desc_t *alg, *engine;
	int seq;
	char enc, debug, kgen, igen;
	int pad;
	sec_fields *sec;
	const opt_t *opts;
} crypt_state;

	

const char *crypt_help = "The crypt plugin for dd_rescue de/encrypts data copied on the fly.\n"
		" It supports unaligned blocks (arbitrary offsets) and holes(sparse writing).\n"
		" Parameters: [alg[o[rithm]]=]ALG:enc[rypt]:dec[rypt]:engine=STR:pad=STR\n"
		"\t:keyhex=HEX:keyfd=INT[@INT]:keyhexfd=INT[@INT]:keygen\n"
		"\t:ivhex=HEX:ivfd=INT[@INT]:ivhexfd=INT[@INT]:ivgen\n"
		"\t:pass=STR:passhex=HEX:passfd=INT[@INT]:passhexfd=INT[@INT]\n"
		"\t:salt=STR:salthex=HEX:saltfd=INT[@INT]:salthexfd=INT[@INT]\n"
		" Use algorithm=help to get a list of supported crypt algorithms\n";

/* TODO: Need o output key and iv if generated to KEYS.alg and IVS.alg 
 *	And optionally also read and parse these
 */


int crypt_plug_init(void **stat, char* param, int seq, const opt_t *opt)
{
	int err = 0;
	crypt_state *state = (crypt_state*)malloc(sizeof(crypt_state));
	*stat = (void*)state;
	memset(state, 0, sizeof(crypt_state));
	state->seq = seq;
	state->opts = opt;
	state->enc = -1;
	state->sec = secmem_init();
	assert(state->sec);
	state->pad = PAD_ALWAYS;
#ifdef HAVE_AESNI
	state->engine = AESNI_Methods;
#else
	state->engine = AES_C_Methods;
#endif
	char* algnm = NULL;
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
		else if (!memcmp(param, "engine=", 7)) {
			if (!strcmp(param+7, "aes_c"))
				state->engine = AES_C_Methods;
#ifdef HAVE_AESNI
			else if (!strcmp(param+7, "aesni"))
				state->engine = AESNI_Methods;
#endif
			else if (!strcmp(param+7, "openssl"))
				state->engine = AES_OSSL_Methods;
			else {
				FPLOG(FATAL, "Engine %s unknown, specify aesni/aes_c/openssl\n",
					param+7);
				--err;
				continue;
			}
		}
		else if (!memcmp(param, "algorithm=", 10))
			algnm = param+10;
		else if (!memcmp(param, "algo=", 5))
			algnm = param+5;
		else if (!memcmp(param, "alg=", 4))
			algnm = param+4;
		else if (!memcmp(param, "pad=", 4)) {
			if (!strcmp(param+4, "zero"))
				state->pad = PAD_ZERO;
			else if (!strcmp(param+4, "always"))
				state->pad = PAD_ALWAYS;
			else if (!strcmp(param+4, "asneeded"))
				state->pad = PAD_ASNEEDED;
			else {
				FPLOG(FATAL, "Illegal padding %s: Specify zero/always/asneeded!\n",
					param+4);
				--err;
				continue;
			}
		}
		else if (!memcmp(param, "keyhex=", 7))
			err -= parse_hex(state->sec->userkey1, param+7, 32);
		else if (!memcmp(param, "keyfd=", 6))
			err -= read_bin(state->sec->userkey1, param+6, 32);
		else if (!memcmp(param, "keyhexfd=", 9))
			err -= read_hex(state->sec->userkey1, param+9, 32);
		else if (!strcmp(param, "keygen"))
			state->kgen = 1;
		else if (!memcmp(param, "ivhex=", 6))
			err -= parse_hex(state->sec->iv1, param+6, 16);
		else if (!memcmp(param, "ivfd=", 5))
			err -= read_bin(state->sec->iv1, param+5, 16);
		else if (!memcmp(param, "ivhexfd=", 8))
			err -= read_hex(state->sec->iv1, param+8, 16);
		else if (!strcmp(param, "ivgen"))
			state->igen = 1;
		else if (!memcmp(param, "pass=", 5))
			mystrncpy(state->sec->passphr, param+5, 128);
		else if (!memcmp(param, "passhex=", 8))
			err -= parse_hex(state->sec->passphr, param+8, 128);
		else if (!memcmp(param, "passfd=", 7))
			err -= read_bin(state->sec->passphr, param+7, 128);
		else if (!memcmp(param, "passhexfd=", 10))
			err -= read_hex(state->sec->passphr, param+10, 128);
		else if (!memcmp(param, "salt=", 5))
			mystrncpy(state->sec->salt, param+5, 64);
		else if (!memcmp(param, "salthex=", 8))
			err -= parse_hex(state->sec->salt, param+8, 64);
		else if (!memcmp(param, "saltfd=", 7))
			err -= read_bin(state->sec->salt, param+7, 64);
		else if (!memcmp(param, "salthexfd=", 10))
			err -= read_hex(state->sec->salt, param+10, 64);

		/* Hmmm, ok, let's support algname without alg= */
		else
			algnm = param;
	}
	/* Now process params ... */
	/* 1st: Set engine: Default: aesni/aes_c: Done */
	/* 2nd: Set alg: Default: AES192-CTR */
	if (algnm)
		state->alg = findalg(state->engine, algnm);
	if (!state->alg) {
		FPLOG(FATAL, "Unknown parameter/algorithm %s\n", algnm);
		secmem_release(state->sec);
		return -1;
	}
	/* 3rd: Padding */
	/* 4th: pass */
	/* 5th: salt (later: if not given: derive from outnm) */
	/* 6th: key (later: defaults to pbkdf(pass, salt) */
	/* 7th: iv (later: defaults to salt) */

	return err;
}

