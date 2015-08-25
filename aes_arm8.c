/** aes_arm8.c 
 *
 * AES implementation using the ARMv8 crypto extensions
 * to speed up AES en/decryption by (at least) an order
 * of magnitude.
 *
 * (c) Kurt Garloff <kurt@garloff.de>, 8-9/2015
 * License: GNU GPL v2 or v3 (at your option)
 *
 * Implementation based on ARMv8 architecture manual and inspired by
 * intel's AESNI implementation and openssl's aesv8-armx.S
 */

#include "aes.h"
#include "secmem.h"
#include <string.h>

#ifndef __aarch64__
# error aes_arm8 only supported in AArch64 (ARM64/ARMv8)
#endif

#define CLEAR(reg) asm volatile ("eor %0, %0, %0 \n" : "=x"(reg): "0"(reg):)




