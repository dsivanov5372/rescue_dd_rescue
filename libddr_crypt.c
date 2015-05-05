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
#include "sha256.h"
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
#include <time.h>
#include <endian.h>
#include <signal.h>

#if __WORDSIZE == 64
#define LL "l"
#define ATOL atol
#elif __WORDSIZE == 32
#define LL "ll"
#define ATOL atoll
#else
#error __WORDSIZE unknown
#endif


#define FPLOG(lvl, fmt, args...) \
	plug_log(ddr_plug.logger, stderr, lvl, fmt, ##args)

/* fwd decl */
extern ddr_plugin_t ddr_plug;


typedef struct _crypt_state {
	ciph_desc_t *alg, *engine;
	int seq;
	char enc, debug, kgen, igen, sgen, keyf, ivf, saltf;
	char kset, iset, pset, sset;
	char finfirst, rev, bench, skiphole;
	clock_t cpu;
	int pad;
	int inbuf;
	int pbkdf2r;
	sec_fields *sec;
	const opt_t *opts;
	char *pfnm, *sfnm;
	size_t saltlen;
	loff_t lastpos;
	loff_t processed;
} crypt_state;

/* FIXME HACK!!! aesni currently assumes avail of global crypto symbol to point to sec_fields ... */
sec_fields *crypto;

const char *crypt_help = "The crypt plugin for dd_rescue de/encrypts data copied on the fly.\n"
		" It only supports aligned blocks (with CTR) and no holes (sparse writing).\n"
		" Parameters: [alg[o[rithm]]=]ALG:enc[rypt]:dec[rypt]:engine=STR:pad=STR\n"
		"\t:keyhex=HEX:keyfd=[x]INT[@INT@INT]:keyfile=NAME[@INT@INT]:keygen:keysfile\n"
		"\t:ivhex=HEX:ivfd=[x]INT[@INT@INT]:ivfile=NAME[@INT@INT]:ivgen:ivsfile\n"
		"\t:pass=STR:passfd=[x]INT[@INT@INT]:passfile=NAME[@INT@INT]\n"
		"\t:salt=STR:salthex=HEX:saltfd=[x]INT[@INT@INT]:saltfile=NAME[@INT@INT]\n"
		"\t:saltlen=INT:saltgen:saltsfile\n"
		"\t:pbkdf2[=INT]:debug:bench[mark]:skiphole\n"
		" Use algorithm=help to get a list of supported crypt algorithms\n";

/* TODO: 
 * openssl compatibility (Salted__ <SALT> header)
 */

int parse_hex(unsigned char*, const char*, uint maxlen);
int parse_hex_u32(unsigned int*, const char*, uint maxlen);
int read_fd(unsigned char*, const char*, uint maxlen, const char*);
int read_file(unsigned char*, const char*, uint maxlen);
char* mystrncpy(unsigned char*, const char*, uint maxlen);
int stripcrlf(char* str, uint maxlen);
void whiteout(char* str, char quiet);

int set_flag(char* flg, const char* msg)
{
	if (*flg) {
		FPLOG(FATAL, "%s already set\n", msg);
		return -1;
	}
	*flg = 1;
	return 0;
}

int set_alg(crypt_state* state, const char* algnm)
{
	if (state->alg) {
		FPLOG(FATAL, "alg already set to %s, can't override with %s\n",
			state->alg->name, algnm);
		return -1;
	}
	if (!strcmp(algnm, "help")) {
		FPLOG(INFO, "Crypto algorithms:", NULL);
		ciph_desc_t *alg;
		for (alg = state->engine; alg->name != NULL; ++alg)
			FPLOG(NOHDR, " %s", alg->name);
		FPLOG(NOHDR, "\n", NULL);
		return -1;
	} else {
		state->alg = findalg(state->engine, algnm);
		if (!state->alg) {
			FPLOG(FATAL, "Unknown parameter/algorithm %s\n", algnm);
			return -1;
		}
	}
	return 0;
}

#define BLKSZ (state->alg? state->alg->blocksize: 16)

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
	crypto = state->sec;	// HACK for aesni
	assert(state->sec);
	state->pad = PAD_ALWAYS;
	state->saltlen = -1;
#ifdef HAVE_AESNI
	if (have_aesni)
		state->engine = AESNI_Methods;
	else
#endif
		state->engine = AES_C_Methods;
	while (param) {
		char* next = strchr(param, ':');
		if (next)
			*next++ = 0;
		if (!*param) {
			param = next;
			continue;
		}
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
				param = next;
				continue;
			}
		}
		else if (!memcmp(param, "algorithm=", 10))
			err += set_alg(state, param+10);
		else if (!memcmp(param, "algo=", 5))
			err += set_alg(state, param+5);
		else if (!memcmp(param, "alg=", 4))
			err += set_alg(state, param+4);
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
				param = next;
				continue;
			}
		}
		else if (!memcmp(param, "keyhex=", 7)) {
			//err += parse_hex_u32((unsigned int*)state->sec->userkey1, param+7, state->alg->keylen/(8*sizeof(int))); 
			err += parse_hex(state->sec->userkey1, param+7, state->alg->keylen/8); 
			whiteout(param+7, opt->quiet);
			err += set_flag(&state->kset, "key");
		} else if (!memcmp(param, "keyfd=", 6)) {
			err += read_fd(state->sec->userkey1, param+6, 32, "key");
			err += set_flag(&state->kset, "key");
		} else if (!memcmp(param, "keyfile=", 8)) {
			err += read_file(state->sec->userkey1, param+8, state->alg->keylen/8);
			err += set_flag(&state->kset, "key");
		} else if (!strcmp(param, "keygen"))
			state->kgen = 1;
		else if (!strcmp(param, "keysfile"))
			state->keyf = 1;
		else if (!memcmp(param, "ivhex=", 6)) {
			//err += parse_hex_u32((unsigned int*)state->sec->nonce1, param+6, BLKSZ/sizeof(int));
			err += parse_hex(state->sec->nonce1, param+6, BLKSZ);
			whiteout(param+6, opt->quiet);
			err += set_flag(&state->iset, "IV");
		} else if (!memcmp(param, "ivfd=", 5)) {
			err += read_fd(state->sec->nonce1, param+5, BLKSZ, "iv");
			err += set_flag(&state->iset, "IV");
		} else if (!memcmp(param, "ivfile=", 7)) {
			err += read_file(state->sec->nonce1, param+7, BLKSZ);
			err += set_flag(&state->iset, "IV");
		} else if (!strcmp(param, "ivgen"))
			state->igen = 1;
		else if (!strcmp(param, "ivsfile"))
			state->ivf = 1;
		else if (!memcmp(param, "pass=", 5)) {
			mystrncpy(state->sec->passphr, param+5, 128);
			whiteout(param+5, opt->quiet);
			err += set_flag(&state->pset, "password");
#if 0
		} else if (!memcmp(param, "passhex=", 8)) {
			/* FIXME: This will error out on shorter passphrases! */
			err += parse_hex(state->sec->passphr, param+8, 128);
			err += set_flag(&state->pset, "password");
#endif
		} else if (!memcmp(param, "passfd=", 7)) {
			err += read_fd(state->sec->passphr, param+7, 128, "passphrase");
			stripcrlf((char*)state->sec->passphr, 128);
			err += set_flag(&state->pset, "password");
		} else if (!memcmp(param, "passfile=", 9)) {
			if (!state->pset) {
				err += read_file(state->sec->passphr, param+9, 128);
				stripcrlf((char*)state->sec->passphr, 128);
				err += set_flag(&state->pset, "password");
			} else /* Later: save if pset */
				state->pfnm = param+9;
		} else if (!memcmp(param, "salt=", 5)) {
			//mystrncpy(state->sec->salt, param+5, 64);
			gensalt(state->sec->salt, 8, param+5, NULL, 0); 
			whiteout(param+5, opt->quiet);
			err += set_flag(&state->sset, "salt");
		} else if (!memcmp(param, "salthex=", 8)) {
			err += parse_hex(state->sec->salt, param+8, 8);
			whiteout(param+8, opt->quiet);
			err += set_flag(&state->sset, "salt");
		} else if (!memcmp(param, "saltfd=", 7)) {
			err += read_fd(state->sec->salt, param+7, 8, "salt");
			err += set_flag(&state->sset, "salt");
		} else if (!memcmp(param, "saltfile=", 9)) {
			if (!state->sset && !state->sgen) {
				err += read_file(state->sec->salt, param+9, 8);
				err += set_flag(&state->sset, "salt");
			} else /* sset is set, so save later */
				state->sfnm = param+9;
		} else if (!strcmp(param, "saltsfile"))
			state->saltf = 1;
		else if (!memcmp(param, "saltlen=", 8))
			state->saltlen = ATOL(param+8);
		else if (!strcmp(param, "saltgen"))
			state->sgen = 1;
		else if (!memcmp(param, "bench", 5))
			state->bench = 1;
		else if (!memcmp(param, "pbkdf2=", 7))
			state->pbkdf2r = atol(param+7);
		else if (!strcmp(param, "pbkdf2"))
			state->pbkdf2r = 17000;
		else if (!strcmp(param, "skiphole"))
			state->skiphole = 1;
		/* Hmmm, ok, let's support algname without alg= */
		else {
			err += set_alg(state, param);
		}
		param = next;
	}
	/* Now process params ... */
	/* 0th: encryption or decryption? */
	if (state->enc == (char)-1) {
		FPLOG(FATAL, "Need to specify enc[rypt] or dec[rypt]\n", NULL);
		return -1;
	}
	/* 1st: Set engine: Default: aesni/aes_c: Done */
	/* 2nd: Set alg: Already done if set explicitly */
	if (!err && !state->alg)
		state->alg = findalg(state->engine, "AES192-CTR");
	if (!state->alg)
		return -1;

	/* Actually, we can support seeks/reverse copies with CTR and ECB */
	ddr_plug.needs_align = state->alg->blocksize;
	ddr_plug.supports_seek = state->alg->stream->seek_blk;

	/* 3rd: Padding: Already done */
	/* 4th: pass: done */
	/* 5th: salt (later: if not given: derive from outnm) */
	/* 6th: key (later: defaults to pbkdf2(pass, salt) */
	if (state->kgen && !state->enc) {
		FPLOG(FATAL, "Decrypting with a generated key does not make sense\n", NULL);
		return -1;
	}
	if (!state->pset && !state->kset && !state->keyf && !state->kgen) {
		FPLOG(FATAL, "Need to set key or password\n", NULL);
		--err;
	}
	if (state->kset && state->kgen) {
		FPLOG(FATAL, "Can't set and generate a key\n", NULL);
		--err;
	}
	state->finfirst = state->rev = opt->reverse;
	/* 7th: iv (later: defaults to generation from salt) */
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
	if (v >= 'A' && v <= 'F')
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
	if (i < maxlen) {
		memset(res+i, 0, maxlen-i);
		FPLOG(FATAL, "Too short key/IV (%i/%i) bytes\n", i, maxlen);
		return -1;
	}
	return 0;
}

int parse_hex_u32(unsigned int* res, const char* str, uint maxlen)
{
	if (str[0] == '0' && str[1] == 'x')
		str += 2;
	uint i;
	for (i = 0; i < maxlen; ++i) {
		int v3 = hexbyte(str+i*8);
		int v2 = hexbyte(str+i*8+2);
		int v1 = hexbyte(str+i*8+4);
		int v0 = hexbyte(str+i*8+6);
		if (v3 < 0 || v2 < 0 || v1 < 0 || v0 < 0)
			break;
		res[i] = v3 << 24 | v2 << 16 | v1 << 8 | v0;
	}
	if (i < maxlen) {
		memset(res+i, 0, 4*(maxlen-i));
		FPLOG(FATAL, "Too short key/IV (%i/%i) u32s\n", i, maxlen);
		return -1;
	}
	return 0;
}

char* hexout(char* buf, const unsigned char* val, unsigned int ln)
{
	int i;
	for (i = 0; i < ln; ++i)
		sprintf(buf+2*i, "%02x", val[i]);
	return buf;
}

char* hexout_u32(char* buf, const unsigned int* val, unsigned int ln)
{
	int i;
	for (i = 0; i < ln; ++i)
		sprintf(buf+8*i, "%08x", val[i]);
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
		FPLOG(INPUT, "Enter %s: ", what);
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
	if (ln <= 0)
		FPLOG(FATAL, "%s empty!\n", what);
	return ln<=0? 1: 0;
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

int write_file(const unsigned char *data, const char* param, uint maxlen, int mode)
{
	off_t off = 0;
	size_t sz = 0;
	get_offs_len(param, &off, &sz);
	if (!sz)
		sz = maxlen;
	int fd = open(param, O_RDWR|O_CREAT, mode);
	if (fd < 0) {
		FPLOG(FATAL, "Can't open %s for writing: %s\n", 
			param, strerror(errno));
		return -1;
	}
	off_t o = lseek(fd, off, SEEK_SET);
	assert(o == off);
	int ln = write(fd, data, sz);
	//assert(ln == sz);
	return ln==sz? 0: -1;
}

char* mystrncpy(unsigned char* res, const char* param, uint maxlen)
{
	size_t ln = strlen(param);
	memcpy(res, param, MIN(ln+1, maxlen));
	if (ln+1 < maxlen)
		memset(res+ln+1, 0, maxlen-ln-1);
	return (char*)res;
}

int stripcrlf(char* str, uint maxlen)
{
	/* Note: We may read beyond str -- but we have zeros in secmem, so it's harmless */
	size_t ln = strlen(str);
	if (ln >= maxlen)
		return 0;
	if (ln+1 < maxlen)
		memset(str+ln+1, 0, maxlen-ln-1);
	size_t oln = ln;
	/* This removes a trailing \n (Unix), \r (Mac) or \r\n (DOS). */
	if (str[ln-1] == '\n')
		str[--ln] = 0;
	if (str[ln-1] == '\r')
		str[--ln] = 0;
	return (oln == ln? 0: 1);
}

void whiteout(char* str, char quiet)
{
#ifndef NO_WRITE_ARGV
	int ln = strlen(str);
	assert(ln<=512 && ln >=0);
	memset(str, 'X', ln);
#endif
	if (!quiet)
		FPLOG(WARN, "Don't specify sensitive data on the command line!\n", NULL);
}

/* Constructs name for KEYS and IVS files (in alocated mem) */
char *keyfnm(const char* base, const char *encnm)
{
	char* ptr = strrchr(encnm, '/');	// FIXME: Unix
	if (!ptr)
		return strdup(base);
	else {
		char* kfnm = malloc(ptr-encnm + 2 + strlen(base));
		assert(kfnm);
		memcpy(kfnm, encnm, ptr-encnm);
		*(kfnm+(ptr-encnm+1)) = 0;
		strcat(kfnm, base);
		return kfnm;
	}
}

char* chartohex(crypt_state *state, const unsigned char* key, const int bytes)
{
	assert(bytes < 144);
	hexout(state->sec->charbuf1, key, bytes);
	return state->sec->charbuf1;
}

char* chartohex_u32(crypt_state *state, const unsigned int* key, const int words)
{
	assert(words < 36);
	hexout_u32(state->sec->charbuf1, key, words);
	return state->sec->charbuf1;
}


int write_keyfile(crypt_state *state, const char* base, const char* name, const unsigned char* key, const int bytes, int acc, char confnm, char isu32)
{
	char *fnm;
	if (confnm)
		fnm = keyfnm(base, name);
	else
		fnm = strdup(base);
	int err = isu32?
		upd_chks(fnm, name, chartohex_u32(state, (unsigned int*)key, bytes/sizeof(int)), acc) :
		upd_chks(fnm, name, chartohex(state, key, bytes), acc);
	free(fnm);
	if (err)
		FPLOG(FATAL, "Could not write key/IV/pass/salt file\n", NULL);
	return err;
}

int crypt_open(const opt_t *opt, int ilnchg, int olnchg, int ichg, int ochg,
	     unsigned int totslack_pre, unsigned int totslack_post,
	     const fstate_t *fst, void **stat)
{
	int err = 0;
	char ivsnm[32], keynm[32], saltnm[32];
	clock_t t1 = 0;
	crypt_state *state = (crypt_state*)*stat;
	state->opts = opt;

	sprintf(ivsnm, "IVS.%s", state->alg->name);
	sprintf(keynm, "KEYS.%s", state->alg->name);
	sprintf(saltnm, "SALT.%s", state->alg->name);

	if (state->bench)
		t1 = clock();
	/* Are we en- or decrypting? */
	const char* encnm = state->enc? opt->oname: opt->iname;
	size_t encln = state->enc? opt->init_opos + (opt->reverse? 0: fst->estxfer): fst->ilen;
	if (state->alg->stream->granul > 1 && state->enc && (state->pad == PAD_ALWAYS || (state->pad == PAD_ASNEEDED && (encln&(BLKSZ-1)))))
		encln += BLKSZ-(encln&(BLKSZ-1));
	else
		ddr_plug.changes_output_len = 0;	
	/* If we need to generate a salt ... */
	if (state->saltlen != (size_t)-1)
		encln = state->saltlen;

	/* Password */
	if (state->pset && state->pfnm) {
		/*
		if (write_keyfile(state, state->pfnm, encnm, state->sec->passphr, strlen((const char*)state->sec->passphr), 0600, 0, 0))
			return -1;
		 */
		if (write_file(state->sec->passphr, state->pfnm, strlen((const char*)state->sec->passphr), 0600))
			return -1;
	}

	/* 5th: Salt possibilities:
	 * (.) We may not need a salt as user opted to specify/read/generate key+IV ...
	 * (a) It's been set already via salt=, saltfd=, salthex=, saltfile= (sset is set)
	 * (b) We can read it from saltsfile (SALT.$ALG)
	 * (c) It needs to be generated via prng (sgen)
	 * (d) Nothing: Generate from file name and length
	 */
	
	char needsalt = state->pset && !((state->iset||state->igen) && (state->kset||state->kgen));

	if (needsalt && state->sgen) {
		random_bytes(state->sec->salt, 8, 0);
		state->sset = 1;
		if (!state->sfnm && !state->saltf)
			FPLOG(WARN, "Generated salt not written anywhere?\n", NULL);
	}

	/* FIXME: Need to handle saltf here! */
	if (needsalt && !state->sgen && !state->sset && state->saltf) {
		char* sfnm = keyfnm(saltnm, encnm);
		int off = get_chks(sfnm, encnm, state->sec->charbuf1);
		/* Failure is NOT fatal */
		if (off >= 0) {
			err += parse_hex(state->sec->salt, state->sec->charbuf1, 8);
			state->sset = 1;
		} else if (!opt->quiet)
			FPLOG(WARN, "Could not find salt for %s in %s\n", encnm, sfnm);

		free(sfnm);
	}

	/* 5th: salt (later: if not given: derive from outnm) */
	if (needsalt && !state->sset) {
		if (!strcmp(encnm, "-")) {
			FPLOG(FATAL, "Can't initialize salt from name -\n", NULL);
			return -1;
		}
		if (encln == 0 && !opt->quiet)
			FPLOG(WARN, "Weak salt from 0 len file\n", NULL);
		/* TODO: Check for size changing plugins */
		gensalt(state->sec->salt, 8, encnm, NULL, encln);
		if (!opt->quiet) {
			if (encln)
				FPLOG(INFO, "Derived salt from %s=%016zx\n", encnm, encln);
			else	
				FPLOG(INFO, "Derived salt from %s\n", encnm);
		}
		state->sset = 1;
	}

	if (needsalt && state->sfnm) {
		if (write_file(state->sec->salt, state->sfnm, 8, 0640))
			return -1;
	}
	if (needsalt && state->saltf) {
		if (write_keyfile(state, saltnm, encnm, state->sec->salt, 8, 0640, 1, 0))
			return -1;
	}

	/* 6th: key options
	 + (a) has been set already
	 * (b) generate from PRNG
	 * (c) generate from pass+salt -- pbkdf2
	 * (d) read from keyf
	 */
	if (!state->kset) {	/* (a) */
		if (state->kgen) {	/* (b) */
			/* Do key generation */
			random_bytes(state->sec->userkey1, state->alg->keylen/8, 1);
			/* Write to keysfile or warn ... */
			if (!state->keyf)
				FPLOG(WARN, "Generated key not written anywhere?\n", NULL);
			else 
				if (write_keyfile(state, keynm, encnm, state->sec->userkey1, state->alg->keylen/8, 0600, 1, 0))
					return -1;
		} else if (state->pset) {	/* (c) */
			if (!state->pbkdf2r) {
				FPLOG(FATAL, "Need to specify pbkdf2[=INT] to generate key/IV from pass/salt\n", NULL);
				return -1;
			}
			/* Do pbkdf2 stuff to generate key */
			hashalg_t sha256_halg = SHA256_HALG_T;
			int err = pbkdf2(&sha256_halg, state->sec->passphr, 128, state->sec->salt, 8, 
					 state->pbkdf2r, state->sec->userkey1, state->alg->keylen/8);
			if (err) {
				FPLOG(FATAL, "Key generation with pass+salt failed!\n", NULL);
				return -1;
			}
			/* Write to keysf if requested */
			if (state->keyf)
				if (write_keyfile(state, keynm, encnm, state->sec->userkey1, state->alg->keylen/8, 0600, 1, 0))
					return -1;
			
		} else if (state->keyf) {	/* (d) */
			/* Read from keyfile */
			char* kfnm = keyfnm(keynm, encnm);
			int off = get_chks(kfnm, encnm, state->sec->charbuf1);
			free(kfnm);
			/* Fatal if not successful */
			if (off < 0) {
				FPLOG(FATAL, "Can't read key for %s from KEYS file!\n", encnm);
				return -1;
			}
			//err += parse_hex_u32((unsigned int*)state->sec->userkey1, state->sec->charbuf1, state->alg->keylen/(8*sizeof(int)));
			err += parse_hex(state->sec->userkey1, state->sec->charbuf1, state->alg->keylen/8);
		} else {	/* Should not happen! */
			FPLOG(FATAL, "Need to set key\n", NULL);
			return -1;
		}
	} else {
		if (state->keyf)
			/* Write to keyfile */
			if (write_keyfile(state, keynm, encnm, state->sec->userkey1, state->alg->keylen/8, 0600, 1, 0))
				return -1;
	}
	/* 7th: iv -- same logic as for key applies (defaults to be generated from pass+salt) */
	if (!state->iset && state->alg->stream->needs_iv) {
		if (state->igen) {
			/* Generate IV */
			random_bytes(state->sec->nonce1, BLKSZ, 0);
			char iout[33];
			if (!opt->quiet)
				FPLOG(INFO, "Generated IV: %s\n", hexout(iout, state->sec->nonce1, BLKSZ)); 
			/* Save IV ... */
			if (!state->ivf)
				FPLOG(WARN, "Generated IV not saved?\n", NULL);
			else 
				if (write_keyfile(state, ivsnm, encnm, state->sec->nonce1, BLKSZ, 0640, 1, 0))
					return -1;
		} else if (state->pset) {
			assert(state->pbkdf2r);
			if (!state->kset && !state->kgen && !opt->quiet)
				FPLOG(INFO, "Generate KEY and IV from same passwd/salt\n", NULL);
			/* Do pbkdf2 stuff to generate key */
			hashalg_t sha256_halg = SHA256_HALG_T;
			/* FIXME: Should use different p/s? */
			const unsigned char* xorb = (const unsigned char*) "Hdo7DHk. 9dEaj*/B=psdGsf,yM4#q)1<tW_J%";
			memxor(state->sec->salt, xorb, BLKSZ);
			int err = pbkdf2(&sha256_halg, state->sec->passphr, 128, state->sec->salt, 8, 
					 state->pbkdf2r/3, state->sec->nonce1, BLKSZ);
			memxor(state->sec->salt, xorb, BLKSZ);
			if (err) {
				FPLOG(FATAL, "IV generation with pass+salt failed!\n", NULL);
				return -1;
			}
			/* Write to ivsfile if requested */
			if (state->ivf)
				if (write_keyfile(state, ivsnm, encnm, state->sec->nonce1, BLKSZ, 0640, 1, 0))
					return -1;
		} else if (state->ivf) {
			/* Read IV from ivsfile */
			char* ivnm = keyfnm(ivsnm, encnm);
			int off = get_chks(ivsnm, encnm, state->sec->charbuf1);
			free(ivnm);
			if (off < 0) {
				FPLOG(FATAL, "Can't read IV for %s from IVS file!\n", encnm);
				return -1;
			}
			//err += parse_hex_u32((unsigned int*)state->sec->nonce1, state->sec->charbuf1, BLKSZ/sizeof(int));
			err += parse_hex(state->sec->nonce1, state->sec->charbuf1, BLKSZ);
		} else {
			FPLOG(FATAL, "Need to determine IV\n", NULL);
			return -1;
		}
	} else if (state->ivf && state->alg->stream->needs_iv)
		/* Save to IVs file */
		if (write_keyfile(state, ivsnm, encnm, state->sec->nonce1, BLKSZ, 0640, 1, 0))
			return -1;
	
	/* OK, now we can prepare en/decryption */
	if (state->enc)
		state->alg->enc_key_setup(state->sec->userkey1, state->sec->ekeys->data, state->alg->rounds);
	else
		state->alg->dec_key_setup(state->sec->userkey1, state->sec->dkeys->data, state->alg->rounds);
	/* Prepare for hole detection */
	state->lastpos = state->enc? opt->init_opos: opt->init_ipos;
	/* IV */
	if (state->alg->stream->iv_prep)
		state->alg->stream->iv_prep(state->sec->nonce1, state->sec->iv1.data, state->lastpos/BLKSZ);
	else
		memcpy(state->sec->iv1.data, state->sec->nonce1, BLKSZ);

	/* No need to keep key/passphr in memory */
	memset(state->sec->userkey1, 0, state->alg->keylen/8);
	memset(state->sec->passphr, 0, 128);
	asm("":::"memory");
	if (state->bench)
		state->cpu += clock() - t1;
	return err;
}

char holememcpy(void* dst, const void* src, size_t ln)
{
	unsigned long *ldst = (unsigned long*)dst;
	unsigned long *lsrc = (unsigned long*)src;
	unsigned int left = ln/sizeof(long);
	if (*lsrc || ln%sizeof(long)) {
		memcpy(dst, src, ln);
		return 0;
	}
	while (left--) {
		unsigned long val = *lsrc++;
		*ldst++ = val;
		if (val) {
			memcpy(ldst, lsrc, left*sizeof(long));
			return 0;
		}
	}
	return 1;
}

unsigned char* crypt_blk_cb(fstate_t *fst, unsigned char* bf, 
			    int *towr, int eof, int *recall, void **stat)
{
	crypt_state *state = (crypt_state*)*stat;
	int i = 0;
	int err = 0;
	int skipped = 0;
	clock_t t1 = 0;
	ssize_t olen = 0;
	/* FIXME: Hack -- detect last block on decoding to be able to strip padding.
	 * Cleaner (nut more complex) aalternative would be to always buffer the last 
	 * 16 bytes and only flush them on receiving eof flag */ 
	char lastdec = state->enc? 0: (fst->ipos+*towr == fst->ilen? 1: 0);
	unsigned char* keys = state->enc? state->sec->ekeys->data: state->sec->dkeys->data;
	Crypt_IV_fn *crypt = state->enc? state->alg->encrypt: state->alg->decrypt;	
	loff_t currpos = state->enc? fst->opos: fst->ipos;
	if (state->rev)
		currpos -= *towr;
	if (state->bench)
		t1 = clock();
	/* FIXME: Can we seek with CTR? */
	if (0 && state->debug)
		FPLOG(DEBUG, "pos: %zi %zi vs %zi (%i)\n", fst->ipos, fst->opos, state->lastpos, state->lastpos/BLKSZ);
	if (currpos != state->lastpos) {
		if (state->alg->stream->seek_blk) {	/* CTR and ECB */
			if (state->alg->stream->iv_prep)
				state->alg->stream->iv_prep(state->sec->nonce1, state->sec->iv1.data, currpos/BLKSZ);
			if (state->debug)
				FPLOG(INFO, "Adjusted offset %zi -> %zi (%i)\n", state->lastpos, currpos, currpos/BLKSZ);
			state->lastpos = currpos;
		} else {
			FPLOG(FATAL, "Unexpected offset %zi\n", currpos);
			raise(SIGQUIT);
		}
	}
	if (0 && state->debug)
		FPLOG(DEBUG, "%zi: %02x %02x %02x %02x ... -> ",
			currpos, bf[0], bf[1], bf[2], bf[3]);
	if (((currpos) % BLKSZ) && state->enc) {
		FPLOG(WARN, "Enc alignment error! (%zi-%i)=%zi %i/%i\n", currpos, state->inbuf,
			currpos - state->inbuf,
			(currpos-state->inbuf)%BLKSZ, (currpos-state->inbuf)&0x0f);
		/* Can only handle in CTR mode and without buffered bytes. */
		assert(state->alg->stream->granul == 1);
		assert(state->inbuf == 0);
		memcpy(state->sec->databuf1+(currpos%BLKSZ), bf, BLKSZ-currpos%BLKSZ);
		err = crypt(keys, state->alg->rounds, state->sec->iv1.data,
			    PAD_ZERO, state->sec->databuf1, bf-(currpos%BLKSZ), BLKSZ, &olen);
		assert(!err);
		assert(olen == BLKSZ);
		i = BLKSZ-(currpos%BLKSZ);
	} else if ((currpos-state->inbuf)%BLKSZ && !state->enc) {
		FPLOG(WARN, "Dec alignment error! (%zi-%i)=%zi %i/%i\n", currpos, state->inbuf,
			currpos - state->inbuf,
			(currpos-state->inbuf)%BLKSZ, (currpos-state->inbuf)&0x0f);
		//raise(SIGQUIT);
	}
	if (!state->enc && !state->rev)
		state->lastpos += *towr;
	/* Process leftover from last block */
	if (state->inbuf && *towr >= BLKSZ-state->inbuf) {
		i = BLKSZ-state->inbuf;
		memcpy(state->sec->databuf1+state->inbuf, bf, i);
		bf -= state->inbuf;
		err = crypt(keys, state->alg->rounds, state->sec->iv1.data,
			    PAD_ZERO, state->sec->databuf1, bf, BLKSZ, &olen);
		assert(!err);
		assert(olen == BLKSZ);
		/* We moved the buffer start several bytes forward, need to correct for it */
		*towr += state->inbuf;
		i = BLKSZ;
		state->inbuf = 0;
	}
	while (i+BLKSZ <= *towr) {
		int left = MIN(512, *towr-i);
		left -= left%BLKSZ;
		//memcpy(state->sec->databuf2, bf+i, left);
		char zero = (state->skiphole? holememcpy(state->sec->databuf2, bf+i, left): (memcpy(state->sec->databuf2, bf+i, left), 0));
		unsigned int unpad = (eof || (lastdec && i+left == *towr))? state->pad: PAD_ZERO;
		if (!zero) {
			/* Fix up after skipped holes */
			if (skipped && state->alg->stream->iv_prep) {
				state->alg->stream->iv_prep(state->sec->nonce1, state->sec->iv1.data, (currpos+i)/BLKSZ);
				skipped = 0;
			}
			err = crypt(keys, state->alg->rounds, state->sec->iv1.data,
				    unpad, state->sec->databuf2, bf+i, left, &olen);
			if (err < 0 || (err > 0 && !unpad)) {
				FPLOG(FATAL, "crypt returned %i (unpad=%i)!\n", err, unpad);
				raise(SIGQUIT);
			}
			//assert(!err || (unpad != PAD_ZERO && err >= 0));
			assert(olen == left || (unpad && olen >= 0));
			if (olen < left) {
				*towr -= (left-olen);
				i -= (left-olen);
			}
		} else
			++skipped;
		i += left;
	}
	/* Fix up after skipped holes */
	if (skipped && state->alg->stream->iv_prep) {
		state->alg->stream->iv_prep(state->sec->nonce1, state->sec->iv1.data, (currpos+i)/BLKSZ);
		skipped = 0;
	}
	/* Copy remainder (incomplete block) into buffer */
	int left = *towr - i;
	if (0 && state->debug && eof)
		FPLOG(DEBUG, "EOF Block with %i bytes ...\n", *towr);
	if (left || (eof && state->inbuf) || (state->enc && state->pad)) {
		assert(left < BLKSZ-state->inbuf);
		if (left)
			memcpy(state->sec->databuf1+state->inbuf, bf+i, left);
		*towr -= left;
		left += state->inbuf;
		if (eof || state->finfirst) {
			memset(state->sec->databuf1+left, 0, BLKSZ-left);
			err = crypt(keys, state->alg->rounds, state->sec->iv1.data,
				    state->pad, state->sec->databuf1, bf+i, left, &olen);
			assert(err >= 0);	/* >0 => padding happened */
			*towr += olen;
			left = 0;
			state->finfirst = 0;
		}
	}
	state->inbuf = left;
	if (state->enc && !state->rev)
		state->lastpos += *towr;
	if (0 && state->debug)
		FPLOG(NOHDR, "%02x %02x %02x %02x ...\n",
			bf[0], bf[1], bf[2], bf[3]);

	if (state->bench)
		state->cpu += clock() - t1;
	state->processed += *towr;
	return bf;

}

int crypt_close(loff_t ooff, void **stat)
{
	crypt_state *state = (crypt_state*)*stat;
	assert(state->inbuf == 0);
	state->alg->release(state->enc? state->sec->ekeys->data: state->sec->dkeys->data, state->alg->rounds);
	/* secmem_release(state->sec) is calles in crypt_plug_release */
	if (state->bench && state->cpu/(CLOCKS_PER_SEC/20) > 0)
		FPLOG(INFO, "%.2fs CPU time, %.1fMiB/s\n",
			(double)state->cpu/CLOCKS_PER_SEC, 
			state->processed/1024 / (state->cpu/(CLOCKS_PER_SEC/1024.0)));
	return 0;	
}

ddr_plugin_t ddr_plug = {
	//.name = "crypt",
	.slack_pre = 32,
	.slack_post = 32,
	.needs_align = 32,
	.handles_sparse = 0,
	.makes_unsparse = 0,
	.changes_output = 1,
	.changes_output_len = 1,
	.supports_seek = 0,
	.init_callback  = crypt_plug_init,
	.open_callback  = crypt_open,
	.block_callback = crypt_blk_cb,
	.close_callback = crypt_close,
	.release_callback = crypt_plug_release,
};


