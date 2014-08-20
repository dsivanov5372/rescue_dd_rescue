#ifndef _CHECKSUM_FILE_H
#define _CHECKSUM_FILE_H

#include <stdio.h>

// TO BE REMOVED
#include "hash.h"

//off_t find_chks(FILE* f, const char* nm, char* res);
char* get_chks(const char*cnm, const char* nm, char* chks);
int upd_chks(const char* cnm, const char *nm, const char *chks, int mode);
#ifdef HAVE_ATTR_XATTR_H
int check_xattr(hash_state* state, const char* res);
int write_xattr(hash_state* state, const char* res);
#endif

#endif
