#ifndef MQDSS_FIPS202_H
#define MQDSS_FIPS202_H

#include <stdint.h>

#define SHAKE256_RATE 136

#define SHAKE256_STREAM_KEYBYTES 32
#define SHAKE256_STREAM_NONCEBYTES 8

void shake256_absorb(uint64_t *s, const unsigned char *input, unsigned long long inputByteLen);
void shake256_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s);
void shake256_squeezebytes(unsigned char *output, unsigned long long outputByteLen, uint64_t *s);
void shake256(unsigned char *output, unsigned long long outputByteLen, const unsigned char *input, unsigned long long inputByteLen);

void shake256_partial_absorb(uint64_t *s,
                             const unsigned char *m, unsigned long long int mlen,
                             unsigned long long *absorbed_bytes);
void shake256_close_absorb(uint64_t *s, unsigned long long *absorbed_bytes);

void cshake256_simple(unsigned char *output, unsigned long long outlen, unsigned char *custom, unsigned long long customlen, const unsigned char *in, unsigned long long inlen);
void cshake256_256simple(unsigned char *output, const char *custom, const unsigned char *in, unsigned long long inlen);

int crypto_stream_shake256(unsigned char *output, unsigned long long outlen, const unsigned char *nonce, const unsigned char *key);

#endif
