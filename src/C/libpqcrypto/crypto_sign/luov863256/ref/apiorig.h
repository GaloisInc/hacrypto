#ifndef API_H
#define API_H

#include "parameters.h"

/* Number of bytes it takes to encode the secret key */
#define CRYPTO_SECRETKEYBYTES ( 32 )                                   
/* Number of bytes it takes to encode the public key */
#define CRYPTO_PUBLICKEYBYTES ( 32 + (((STORED_COLS_OF_P*OIL_VARS)+7)/8) )  
/* Number of bytes it takes to encode a signature */
#define CRYPTO_BYTES ( VARS*(FIELD_SIZE/8) )                           

#define CRYPTO_ALGNAME "LUOV"

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);

#endif 
