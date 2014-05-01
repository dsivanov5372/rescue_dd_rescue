/** \file ifuzz_lzo.c
 *
 * This program produces broken LZO files to test robustness
 * of the libddr_lzo decompressor against broken files
 * as this is a potential attack vector for malicious folks.
 *
 * Overwriting random bytes is simple, but we can also be more
 * clever in fuzzing and fix checksums to see whether we can expose
 * vulnerabilities this way.
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 5/2014
 * License: GNU GPLv2 or v3.
 */

#include <lzo/lzo1x.h>
#include <stdio.h>

