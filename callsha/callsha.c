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

void print_result(unsigned char *out, int length)
{
	int i;
	for (i=0;i<length;i++)
	{
		printf("%02x",out[i]);
	}
}
/*
int compare_results(unsigned char *res1, unsigned char *res2, int length)
{
	int i;
	for(i=0; i<length; i++)
	{
		if(res1[i]!=res2[i]){
			return 0;
		}
	}
	return 1;
}
*/
int try_SHA(unsigned char *input){
	printf ("Running SHA256 on input %s \n\n", input);
	unsigned char sodium_result[crypto_hash_sha256_BYTES] = "";
	unsigned char VST_result[crypto_hash_sha256_BYTES] = "";
	unsigned char NSS_result[crypto_hash_sha256_BYTES] = "";
	
	SHA256_sodium(input, sodium_result, strlen(input));
	printf ("sodium : ");
	print_result (sodium_result, crypto_hash_sha256_BYTES);
	printf ("\n");
	
	
	SHA256_VST(input, VST_result, strlen(input));
	printf ("VST    : ");
	print_result (VST_result, crypto_hash_sha256_BYTES);
	printf ("\n");
	
	SHA256_NSS(input, NSS_result, strlen(input));
	printf ("NSS    : ");
	print_result (NSS_result, crypto_hash_sha256_BYTES);
	printf ("\n");
	
	if(compare_results(sodium_result, VST_result, crypto_hash_sha256_BYTES) && compare_results(sodium_result, NSS_result, crypto_hash_sha256_BYTES))
	{
		printf ("results match\n");
		return 1;
	}
	else
	{
		printf ("results don't match\n");
		return 0;
	}
}
	
/*
main()
{	
	unsigned char input[] = "The quick brown fox jumps over the lazy dog";
	sodium_init();
	try_SHA(input); 
	
  return 0;
}
*/
