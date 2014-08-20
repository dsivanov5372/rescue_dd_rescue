/** checksum_file.c
 *  
 * Routines for CHECKSUMS.hash resp. KEYS.crypt file parsing and updating
 * also contains the xattr pieces that allow to store hashes or ivs
 * or even keys (bad idea!) in xattrs.
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 8/2014
 * License: GPL v2 or v3.
 */

#include "checksum_file.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_ATTR_XATTR_H
# include <attr/xattr.h>
#endif

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

#define MIN(a,b) ((a)<(b)? (a): (b))
#define MAX(a,b) ((a)<(b)? (b): (a))

/* file offset in the chksum file which has the chksum for nm, -1 = not found */
off_t find_chks(FILE* f, const char* nm, char* res)
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
			if (res && fwh-lnbf <= 2*(int)sizeof(hash_t)) {
				const int ln = MIN(129, fwh-lnbf);
				memcpy(res, lnbf, ln-1);
				res[ln] = 0;
			} else if (res)
				*res = 0;
			free(lnbf);
			return pos;
		}
	}
	if (lnbf)
		free(lnbf);
	return -1;
}

FILE* fopen_chks(const char* fnm, const char* mode)
{
	if (!fnm)
		return NULL;
	if (!strcmp("-", fnm))
		return stdin;
	else
		return fopen(fnm, mode);
}

/* get chksum */
char* get_chks(const char*cnm, const char* nm, char* chks)
{
	FILE *f = fopen_chks(cnm, "r");
	if (!f)
		return NULL;
	int err = find_chks(f, nm, chks);
	if (f != stdin)
		fclose(f);
	return err >= 0? chks: NULL;
}

/* update chksum */
int upd_chks(const char* cnm, const char *nm, const char *chks, int mode)
{
	FILE *f = fopen_chks(cnm, "r+");
	int err = 0;
	char oldchks[129];
	if (!f) {
		errno = 0;
		f = fopen_chks(cnm, "w", mode);
		if (!f)
			return -errno;
		fprintf(f, "%s *%s\n", chks, nm);
		err = -errno;
	} else {
		off_t pos = find_chks(cnm, f, nm, oldchks);
		if (pos == -1 || strlen(chks) != strlen(oldchks)) {
			fclose(f);
			f = fopen_chks(state, "a");
			fprintf(f, "%s *%s\n", chks, nm);
			err = -errno;
		} else {
			if (strcmp(chks, oldchks)) {
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

