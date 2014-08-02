#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <polarssl/md.h>
#include <polarssl/pbkdf2.h>

void PBKDF2_HMAC_SHA512(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult) 
{ 
	unsigned int i; 
	unsigned char digest[outputBytes]; 
	md_context_t mdctx;
	md_init_ctx(&mdctx, md_info_from_string("sha512"));
	pbkdf2_hmac(&mdctx, (const unsigned char*)pass, strlen(pass), salt, strlen((const char*)salt), 
		    iterations, outputBytes, digest);
	for (i = 0; i < sizeof(digest); i++) 
		sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
	md_free(&mdctx);
}

void PBKDF2_HMAC_SHA1(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult) 
{ 
	unsigned int i; 
	unsigned char digest[outputBytes]; 
	md_context_t mdctx;
	md_init_ctx(&mdctx, md_info_from_string("sha1"));
	pbkdf2_hmac(&mdctx, (const unsigned char*)pass, strlen(pass), salt, strlen((const char*)salt), 
		    iterations, outputBytes, digest);
	for (i = 0; i < sizeof(digest); i++) 
		sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
	md_free(&mdctx);
}
void usage()
{
	fprintf(stderr, "Usage: pbkdf2 pwd salt iter olen\n");
	exit(1);
}


int main(int argc, char *argv[])
{
	if (argc != 5)
		usage();
	int olen = atol(argv[4])/8;
	char* obuf = malloc(1+2*olen);
	PBKDF2_HMAC_SHA1(argv[1], (unsigned char*)argv[2], atol(argv[3]), olen, obuf);
	printf("PBKDF2(SHA1  , ...) = %s\n", obuf);
	PBKDF2_HMAC_SHA512(argv[1], (unsigned char*)argv[2], atol(argv[3]), olen, obuf);
	printf("PBKDF2(SHA512, ...) = %s\n", obuf);
	free(obuf);
	return 0;
}
