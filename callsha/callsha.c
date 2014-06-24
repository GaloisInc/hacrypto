#include <sodium.h>
#include <string.h>

int sha256_sodium(unsigned char *in, unsigned char *out,
						unsigned long long inlen)
{
	return crypto_hash_sha256(out, in, inlen);
}

main()
{	
	int i;
	unsigned char result[crypto_hash_sha256_BYTES] = "";
	unsigned char input[] = "The quick brown fox jumps over the lazy dog";

	sodium_init();
	sha256_sodium(input, result, strlen(input));

	for (i=0;i<crypto_hash_sha256_BYTES;i++)
	{
		printf("%02x",result[i]);
	}

  return 0;
}
