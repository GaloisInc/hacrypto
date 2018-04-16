#ifndef FIPS202_H
#define FIPS202_H

#include <stdint.h>
#include "params.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

void shake128(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);
void shake256(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);


#if KINDI_KEM_SHAKEMODE == 128
#define crypto_hash shake128
#endif
#if KINDI_KEM_SHAKEMODE == 256
#define crypto_hash shake256
#endif
#endif
