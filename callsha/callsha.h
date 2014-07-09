int sha256_sodium(unsigned char *in, unsigned char *out, unsigned long long inlen);

int sha256_VST(unsigned char *in, unsigned char *out, unsigned long long inlen);

int sha256_NSS(unsigned char *in, unsigned char *out, unsigned long long inlen);

int compare_results(unsigned char *res1, unsigned char *res2, int length);
