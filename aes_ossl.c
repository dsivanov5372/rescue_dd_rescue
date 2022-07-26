/* aes_ossl.c
 * Wrapper that includes aes_ossl10.c or aes_ossl11.c
 * Depending on the openSSL version
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_OPENSSL_EVP_H
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include "aes_ossl11.c"
#else
#include "aes_ossl10.c"
#endif
#endif
