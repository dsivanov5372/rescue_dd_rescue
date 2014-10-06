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
#include "archdep.h"
#include "checksum_file.h"
#include "random.h"

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


#define FPLOG(lvl, fmt, args...) \
	plug_log(ddr_plug.logger, stderr, lvl, fmt, ##args)

/* fwd decl */
extern ddr_plugin_t ddr_plug;


typedef struct _crypt_state {
	aes_desc_t *alg, *engine;
	int seq;
	char enc, debug, kgen, igen, keyf, ivf;
	char kset, iset, pset, sset;
	int pad;
	sec_fields *sec;
	const opt_t *opts;
} crypt_state;

/* FIXME HACK!!! aesni currently assumes avail of global crypto symbol to point to sec_fields ... */
sec_fields *crypto;

const char *crypt_help = "The crypt plugin for dd_rescue de/encrypts data copied on the fly.\n"
		" It supports unaligned blocks (arbitrary offsets) and holes(sparse writing).\n"
		" Parameters: [alg[o[rithm]]=]ALG:enc[rypt]:dec[rypt]:engine=STR:pad=STR\n"
		"\t:keyhex=HEX:keyfd=[x]INT[@INT@INT]:keyfile=NAME[@INT@INT]:keygen:keysfile\n"
		"\t:ivhex=HEX:ivfd=[x]INT[@INT@INT]:ivfile=NAME[@INT@INT]:ivgen:ivsfile\n"
		"\t:pass=STR:passhex=HEX:passfd=[x]INT[@INT@INT]:passfile=NAME[@INT@INT]\n"
		"\t:salt=STR:salthex=HEX:saltfd=[x]INT[@INT@INT]:saltfile=NAME[@INT@INT]\n"
		" Use algorithm=help to get a list of supported crypt algorithms\n";

/* TODO: Need o output key and iv if generated to KEYS.alg and IVS.alg 
 *	And optionally also read and parse these.
 *	Need to read from filename
 */

int parse_hex(unsigned char*, const char*, uint maxlen);
int read_fd(unsigned char*, const char*, uint maxlen, const char*);
int read_file(unsigned char*, const char*, uint maxlen);
char* mystrncpy(unsigned char*, const char*, uint maxlen);

int set_flag(char* flg, const char* msg)
{
	if (*flg) {
		FPLOG(FATAL, "%s already set\n", msg);
		return -1;
	}
	*flg = 1;
	return 0;
}

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
	crypto = state->sec;
	assert(state->sec);
	state->pad = PAD_ALWAYS;
#ifdef HAVE_AESNI
	if (have_aesni)
		state->engine = AESNI_Methods;
	else
#endif
		state->engine = AES_C_Methods;
	char* algnm = NULL;
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!strcmp(param, "help")) {
			FPLOG(INFO, "%s", crypt_help);
			return -1;
		} else if (!strcmp(param, "debug"))
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
		else if (!memcmp(param, "keyhex=", 7)) {
			err += parse_hex(state->sec->userkey1, param+7, 32); 
			err += set_flag(&state->kset, "key");
		} else if (!memcmp(param, "keyfd=", 6)) {
			err += read_fd(state->sec->userkey1, param+6, 32, "key");
			err += set_flag(&state->kset, "key");
		} else if (!memcmp(param, "keyfile=", 8)) {
			err += read_file(state->sec->userkey1, param+8, 32);
			err += set_flag(&state->kset, "key");
		} else if (!strcmp(param, "keygen"))
			state->kgen = 1;
		else if (!strcmp(param, "keysfile"))
			state->keyf = 1;
		else if (!memcmp(param, "ivhex=", 6)) {
			err += parse_hex(state->sec->iv1.data, param+6, 16);
			err += set_flag(&state->iset, "IV");
		} else if (!memcmp(param, "ivfd=", 5)) {
			err += read_fd(state->sec->iv1.data, param+5, 16, "iv");
			err += set_flag(&state->iset, "IV");
		} else if (!memcmp(param, "ivfile=", 7)) {
			err += read_file(state->sec->iv1.data, param+7, 16);
			err += set_flag(&state->iset, "IV");
		} else if (!strcmp(param, "ivgen"))
			state->igen = 1;
		else if (!strcmp(param, "ivsfile"))
			state->ivf = 1;
		else if (!memcmp(param, "pass=", 5)) {
			mystrncpy(state->sec->passphr, param+5, 128);
			err += set_flag(&state->pset, "password");
		} else if (!memcmp(param, "passhex=", 8)) {
			err += parse_hex(state->sec->passphr, param+8, 128);
			err += set_flag(&state->pset, "password");
		} else if (!memcmp(param, "passfd=", 7)) {
			err += read_fd(state->sec->passphr, param+7, 128, "passphrase");
			err += set_flag(&state->pset, "password");
		} else if (!memcmp(param, "passfile=", 9)) {
			err += read_file(state->sec->passphr, param+9, 128);
			err += set_flag(&state->pset, "password");
		} else if (!memcmp(param, "salt=", 5)) {
			mystrncpy(state->sec->salt, param+5, 64);
			err += set_flag(&state->sset, "salt");
		} else if (!memcmp(param, "salthex=", 8)) {
			err += parse_hex(state->sec->salt, param+8, 64);
			err += set_flag(&state->sset, "salt");
		} else if (!memcmp(param, "saltfd=", 7)) {
			err += read_fd(state->sec->salt, param+7, 64, "salt");
			err += set_flag(&state->sset, "salt");
		} else if (!memcmp(param, "saltfile=", 9)) {
			err += read_file(state->sec->salt, param+9, 64);
			err += set_flag(&state->sset, "salt");

		/* Hmmm, ok, let's support algname without alg= */
		} else
			algnm = param;
		param = next;
	}
	/* Now process params ... */
	/* 1st: Set engine: Default: aesni/aes_c: Done */
	/* 2nd: Set alg: Default: AES192-CTR */
	if (algnm) {
		if (!strcmp(algnm, "help")) {
			FPLOG(INFO, "Crypto algorithms:", NULL);
			aes_desc_t *alg;
			for (alg = state->engine; alg->name != NULL; ++alg)
				FPLOG(NOHDR, " %s", alg->name);
			FPLOG(NOHDR, "\n", NULL);
			return -1;
		} else
			state->alg = findalg(state->engine, algnm);
	}
	if (!state->alg) {
		FPLOG(FATAL, "Unknown parameter/algorithm %s\n", algnm);
		--err;
	}
	/* 3rd: Padding: Already done */
	/* 4th: pass: done */
	/* 5th: salt (later: if not given: derive from outnm) */
	/* 6th: key (later: defaults to pbkdf(pass, salt) */
	if (!state->pset && !state->kset && !state->keyf && (!state->kgen || !state->enc)) {
		FPLOG(FATAL, "Need to set key or password\n", NULL);
		--err;
	}
	if (state->kset && state->kgen) {
		FPLOG(FATAL, "Can't set and generate a key\n", NULL);
		--err;
	}
	/* 7th: iv (later: defaults to salt) */
	return err;
}

int crypt_plug_release(void **stat)
{
	if (!stat || !*stat)
		return -1;
	crypt_state *state = (crypt_state*)*stat;
	if (state->sec)
		secmem_release(state->sec);
	else
		return -2;
	free(*stat);
	return 0;
}

int hexchar(const char v)
{
	if (isdigit(v))
		return v - '0';
	if (v >= 'a' && v <= 'f')
		return v - 'a' + 10;
	if (v >= 'A' && v >= 'F')
		return v - 'A' + 10;
	return -1;
}


int hexbyte(const char s[2])
{
	int i = hexchar(s[0]);
	if (i < 0)
		return i;
	int j = hexchar(s[1]);
	if (j < 0)
		return j;
	return (i << 4) | j;
}

int parse_hex(unsigned char* res, const char* str, uint maxlen)
{
	if (str[0] == '0' && str[1] == 'x')
		str += 2;
	uint i;
	for (i = 0; i < maxlen; ++i) {
		int v = hexbyte(str+i*2);
		if (v < 0)
			break;
		res[i] = v;
	}
	if (i < maxlen)
		memset(res+i, 0, maxlen-i);
	return (i < 4? -1: 0);
}

char* hexout(char* buf, unsigned char* val, unsigned int ln)
{
	int i;
	for (i = 0; i < ln; ++i)
		sprintf(buf+2*i, "%02x", val[i]);
	return buf;
}

void get_offs_len(const char* str, off_t *off, size_t *len)
{
	const char* ptr = strrchr(str, '@');
	const char* pt2 = ptr? strrchr(ptr, '@'): NULL;
	*off = 0;
	*len = 0;
	if (!pt2 && !ptr)
		return;
	if (pt2) {
		*off = atol(ptr+1);
		*len = atol(pt2+1);
		return;
	}
	*len = atol(ptr+1);
}

#define MIN(a,b) ((a)<(b)? (a): (b))
int read_fd(unsigned char* res, const char* param, uint maxlen, const char* what)
{
	char ibuf[2*maxlen+3];
	int hex = 0;	
	if (*param == 'x') {
		++param;
		++hex;
	}
	int fd = atol(param);
	int ln = -1;
	if (fd == 0 && isatty(fd)) {
		FPLOG(INPUT, "Enter %s : ", what);
		if (hex) {
			ln = hidden_input(fd, ibuf, 2*maxlen+2, 1);
			ibuf[ln] = 0;
			ln = parse_hex(res, ibuf, maxlen);
		} else {
			ln = hidden_input(fd, (char*)res, maxlen, 1);
		}
	} else {
		off_t off = 0;
		size_t sz = 0;
		get_offs_len(param, &off, &sz);
		if (hex) {
			ln = pread(fd, ibuf, MIN(2*maxlen+2, (sz? sz: 4096)), off);
			ibuf[ln] = 0;
			ln = parse_hex(res, ibuf, maxlen);
		} else {
			ln = pread(fd, res, MIN(maxlen, (sz? sz: 4096)), off);
			if (ln < (int)maxlen)
				memset(res+ln, 0, maxlen-ln);
		}
	}
	return ln<0? ln: 0;
}

int read_file(unsigned char* res, const char* param, uint maxlen)
{
	off_t off = 0;
	size_t sz = 0;
	get_offs_len(param, &off, &sz);
	int fd = open(param, O_RDONLY);
	if (fd < 0) {
		FPLOG(FATAL, "Can't open %s for reading: %s\n", 
			param, strerror(errno));
		return -1;
	}
	int ln = pread(fd, res, MIN(maxlen, (sz? sz: 4096)), off);
	if (ln < (int)maxlen)
		memset(res+ln, 0, maxlen-ln);
	return ln>0? 0: -1;
}

char* mystrncpy(unsigned char* res, const char* param, uint maxlen)
{
	size_t ln = strlen(param);
	memcpy(res, param, MIN(ln+1, maxlen));
	return (char*)res;
}

int crypt_open(const opt_t *opt, int ilnchg, int olnchg, int ichg, int ochg,
	     unsigned int totslack_pre, unsigned int totslack_post,
	     const fstate_t *fst, void **stat)
{
	int err = 0;
	crypt_state *state = (crypt_state*)*stat;
	state->opts = opt;
	/* Are we en- or decrypting? */
	/* 5th: salt (later: if not given: derive from outnm) */
	if ((state->pset && !state->sset) || !state->iset) {
		if (state->enc) {
			if (!strcmp(opt->oname, "-")) {
				FPLOG(FATAL, "Can't initialize salt from name -\n", NULL);
				return -1;
			}
			size_t elen = opt->init_opos + fst->estxfer;
			if (state->pad == PAD_ALWAYS || (state->pad == PAD_ASNEEDED && (elen&15)))
				elen += 16-(elen&15);
			/* TODO: Check for zero elen and for size changing plugins */
			gensalt(state->sec->salt, 64, opt->oname, NULL, elen);
		} else {
			if (!strcmp(opt->iname, "-")) {
				FPLOG(FATAL, "Can't initialize salt from name -\n", NULL);
				return -1;
			}
			size_t elen = fst->ilen;
			gensalt(state->sec->salt, 64, opt->iname, NULL, elen);
		}
	}		
	/* 6th: key - defaults to pbkdf(pass, salt) */
	if (!state->kset) {
		if (state->kgen) {
			/* Do key generation */
			/* Write to keysfile or warn ... */
		} else if (state->pset) {
			/* Do pbkdf2 stuff to generate key */
			/* Write to keysf if requested */
		} else if (state->keyf) {
			/* Read from keyfile */
			// FIXME: Search for oname when encrypting?
			int off = get_chks("IVS", opt->iname, state->sec->charbuf1);
			if (off < 0) {
				char* ptr = strrchr(opt->iname, '/');
				if (ptr) {
					char *ivnm = malloc(ptr-opt->iname+5);
					if (ivnm) {
						memcpy(ivnm, opt->iname, ptr-opt->iname);
						strcpy(ivnm+(ptr-opt->iname), "/IVS");
						off = get_chks(ivnm, ptr+1, state->sec->charbuf1);
						free(ivnm);
					}
				}
			}
			/* Fatal if not successful */
			if (off < 0) {
				FPLOG(FATAL, "Can't read IV for %s from IVS file!\n", opt->iname);
				return -1;
			}
			err += parse_hex(state->sec->iv1.data, state->sec->charbuf1, 16);
		}
	} else {
		if (state->keyf)
			/* Write to keyfile */
			;
	}
	/* 7th: iv (defaults to salt) */
	if (!state->iset) {
		if (state->igen) {
			/* Generate IV */
			random_bytes(state->sec->iv1.data, 16, 0);
			char iout[33];
			FPLOG(INFO, "Generated IV: %s\n", hexout(iout, state->sec->iv1.data, 16)); 
			/* Save IV ... */
		} else if (state->ivf) {
			/* Read IV from ivsfile */
			
			/* Fatal if not successful */
		} else {
			/* Generate from salt */
			
		}
	} else if (state->ivf)
		/* Save to IVs file */
		;
	
	return err;
}

ddr_plugin_t ddr_plug = {
	//.name = "crypt",
	.needs_align = 16,
	.handles_sparse = 0,
	.init_callback  = crypt_plug_init,
	.open_callback  = crypt_open,
	/*
	.block_callback = crypt_blk_cb,
	.close_callback = crypt_close,
	*/
	.release_callback = crypt_plug_release,
};


