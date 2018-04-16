#ifndef RAMSTAKE_H
#define RAMSTAKE_H

#include <stdint.h>
#include <gmp.h>

#define RAMSTAKE_SEED_LENGTH 32
#define RAMSTAKE_KEY_LENGTH 32
#define RAMSTAKE_ULONG_LENGTH 4

#define RAMSTAKE_CODEWORD_NUMBER 6
#define RAMSTAKE_ADDITIVE_MASS 128
#define RAMSTAKE_MULTIPLICATIVE_MASS 128
#define RAMSTAKE_KEYGEN_RANDOM_BYTES (RAMSTAKE_ULONG_LENGTH*(RAMSTAKE_ADDITIVE_MASS + RAMSTAKE_MULTIPLICATIVE_MASS) + RAMSTAKE_SEED_LENGTH)
#define RAMSTAKE_ENCAPS_RANDOM_BYTES (RAMSTAKE_ULONG_LENGTH*(RAMSTAKE_ADDITIVE_MASS + RAMSTAKE_MULTIPLICATIVE_MASS))
#define RAMSTAKE_MODULUS_BITSIZE 756839

#define RAMSTAKE_CODEWORD_LENGTH 255
#define RAMSTAKE_SEEDENC_LENGTH (RAMSTAKE_CODEWORD_NUMBER * RAMSTAKE_CODEWORD_LENGTH)


#define RAMSTAKE_DECODING_FAILURE -1
#define RAMSTAKE_INTEGRITY_FAILURE -2

#define RAMSTAKE_SECRET_KEY_LENGTH (RAMSTAKE_SEED_LENGTH + (RAMSTAKE_MODULUS_BITSIZE+7)/8 + (RAMSTAKE_MODULUS_BITSIZE+7)/8)
#define RAMSTAKE_PUBLIC_KEY_LENGTH (RAMSTAKE_SEED_LENGTH + (RAMSTAKE_MODULUS_BITSIZE+7)/8)
#define RAMSTAKE_CIPHERTEXT_LENGTH ((RAMSTAKE_MODULUS_BITSIZE+7)/8 + RAMSTAKE_SEEDENC_LENGTH + RAMSTAKE_SEED_LENGTH)

typedef struct
{
    unsigned char seed[RAMSTAKE_SEED_LENGTH];
    mpz_t a, b;
} ramstake_secret_key;

typedef struct
{
    unsigned char seed[RAMSTAKE_SEED_LENGTH];
    mpz_t c;
} ramstake_public_key;

typedef struct
{
    mpz_t d;
    unsigned char e[RAMSTAKE_SEEDENC_LENGTH];
    unsigned char h[RAMSTAKE_SEED_LENGTH];
} ramstake_ciphertext;

int ramstake_keygen( ramstake_secret_key * sk, ramstake_public_key * pk, unsigned char * random_seed, int kat );
int ramstake_encaps( ramstake_ciphertext * c, unsigned char * key, ramstake_public_key pk, unsigned char * randomness, int kat );
int ramstake_decaps( unsigned char * key, ramstake_ciphertext c, ramstake_secret_key sk, int kat );

void ramstake_sample_sparse_integer( mpz_t integer, unsigned char * random_seed, int mass );
void ramstake_generate_g( mpz_t integer, mpz_t p, unsigned char * random_seed );

void ramstake_modulus_init( mpz_t p );
void ramstake_modulus_destroy( mpz_t );
void ramstake_secret_key_init( ramstake_secret_key * sk );
void ramstake_secret_key_destroy( ramstake_secret_key sk );
void ramstake_public_key_init( ramstake_public_key * pk );
void ramstake_public_key_destroy( ramstake_public_key pk );
void ramstake_ciphertext_init( ramstake_ciphertext * c );
void ramstake_ciphertext_destroy( ramstake_ciphertext c );

void ramstake_export_secret_key( unsigned char * data, ramstake_secret_key sk );
void ramstake_import_secret_key( ramstake_secret_key * sk, const unsigned char * data );
void ramstake_export_public_key( unsigned char * data, ramstake_public_key sk );
void ramstake_import_public_key( ramstake_public_key * sk, const unsigned char * data );
void ramstake_export_ciphertext( unsigned char * data, ramstake_ciphertext sk );
void ramstake_import_ciphertext( ramstake_ciphertext * sk, const unsigned char * data );


#endif

