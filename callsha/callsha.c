#include <string.h>
#include <stdio.h>
#include "hashes.h"



int SHA256_sodium(unsigned char *in, unsigned char *out,
						unsigned long long inlen)
{
	return crypto_hash_sha256(out, in, inlen);
}

int SHA256_VST(unsigned char *in, unsigned char *out, unsigned long long inlen)
{
	SHA256(in, inlen, out);
	return 1;
}

int SHA256_NSS(unsigned char *in, unsigned char *out, unsigned long long inlen)
{
	return SHA256_HashBuf(out, in, inlen);			   
}