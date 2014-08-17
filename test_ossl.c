#include "aes.h"
#include <string.h>
#include <openssl/evp.h>
#include <assert.h>

void fill_pt(uchar* ptr)
{
	static const char* fillmat = "This is plaintext";
	const uint fillln = strlen(fillmat);
	int i;
	for (i = 0; i < 288+16; i += fillln) {
		if (288+16-i >= fillln)
			strcpy((char*)ptr+i, fillmat);
		else
			memcpy((char*)ptr+i, fillmat, 288+16-i);
	}
}

int encrypt(EVP_CIPHER_CTX *ctx, const uchar* in, uint iln, uchar* out)
{
	int oln, o2ln;
	EVP_EncryptInit(ctx, NULL, NULL, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 1);
	int res = EVP_EncryptUpdate(ctx, out, &oln, in, iln);
	printf("Encrypt: %i (%i -> %i", res, iln, oln);
	assert(res > 0);
	assert(oln == iln-(iln&15));
	res = EVP_EncryptFinal(ctx, out+oln, &o2ln);
	printf("+%i) %i\n", o2ln, res);
	assert(res > 0);
	assert(o2ln == 16);
	return oln+o2ln;
}

int decrypt(EVP_CIPHER_CTX *ctx, const uchar* in, uint iln, uchar* out, uint exp)
{
	int oln, o2ln;
	EVP_DecryptInit(ctx, NULL, NULL, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 1);
	int res = EVP_DecryptUpdate(ctx, out, &oln, in, iln);
	printf("Decrypt: %i (%i -> %i", res, iln, oln);
	assert(res > 0);
	assert(oln == iln-16);
	res = EVP_DecryptFinal(ctx, out+oln, &o2ln);
	printf("+%i) %i\n", o2ln, res);
	assert(res > 0);
	assert(o2ln == exp-oln);
	return oln+o2ln;
}

int main()
{
	uchar pt[288+16], ct[288+16], dc[288+2*16];
	const uchar* key = (const uchar*)"This is the key for testing de/encryption";
	int cln, dln;
	EVP_CIPHER_CTX evpctx;	
	fill_pt(pt);
	EVP_CIPHER_CTX_init(&evpctx);
	EVP_EncryptInit_ex(&evpctx, EVP_aes_128_ecb(), NULL, key, NULL);
	cln = encrypt(&evpctx, pt, 288, ct);
	cln = encrypt(&evpctx, pt, 288, ct);
	EVP_CIPHER_CTX_cleanup(&evpctx);
	EVP_CIPHER_CTX_init(&evpctx);
	EVP_DecryptInit_ex(&evpctx, EVP_aes_128_ecb(), NULL, key, NULL);
	dln = decrypt(&evpctx, ct, cln, dc, 288);	
	dln = decrypt(&evpctx, ct, cln, dc, 288);	
	assert(!memcmp(pt, dc, dln));
	printf("Compare OK\n");
	EVP_CIPHER_CTX_cleanup(&evpctx);
	/* Test with uneven sizes */
	EVP_CIPHER_CTX_init(&evpctx);
	EVP_EncryptInit_ex(&evpctx, EVP_aes_128_ecb(), NULL, key, NULL);
	cln = encrypt(&evpctx, pt, 283, ct);
	cln = encrypt(&evpctx, pt, 283, ct);
	EVP_CIPHER_CTX_cleanup(&evpctx);
	EVP_CIPHER_CTX_init(&evpctx);
	EVP_DecryptInit_ex(&evpctx, EVP_aes_128_ecb(), NULL, key, NULL);
	dln = decrypt(&evpctx, ct, cln, dc, 283);	
	dln = decrypt(&evpctx, ct, cln, dc, 283);	
	assert(!memcmp(pt, dc, dln));
	printf("Compare OK\n");
	EVP_CIPHER_CTX_cleanup(&evpctx);
	return 0;
}


