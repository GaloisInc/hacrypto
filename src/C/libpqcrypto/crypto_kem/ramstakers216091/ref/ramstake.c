#include <stdio.h>
#include <stdlib.h>
#include <libkeccak.a.headers/SimpleFIPS202.h>
#include "ramstake.h"
#include "codec_rs.h"

/**
 * ramstake_keygen
 * Generate a key pair from the given seed.
 */
int ramstake_keygen( ramstake_secret_key * sk, ramstake_public_key * pk, unsigned char * random_seed, int kat )
{
    int i;
    mpz_t g, p;
    unsigned char * randomness_buffer;
    unsigned int randomness_index;

    mpz_init(p);
    mpz_init(g);

    if( kat >= 1 )
    {
        printf("\n# ramstake_keygen\n");
        printf("seed: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", random_seed[i]);
        }
        printf("\n");
    }

    /* expand randomness */
    randomness_buffer = malloc(RAMSTAKE_KEYGEN_RANDOM_BYTES);
    randomness_index = 0;
    SHAKE256(randomness_buffer, RAMSTAKE_KEYGEN_RANDOM_BYTES, random_seed, RAMSTAKE_SEED_LENGTH);

    /* record random seed into secret key */
    /* (In theory, the secret key need not contain any other data
     * because it can be generated from this seed. Nevertheless, we
     * include the other data directly for faster computations.) */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        sk->seed[i] = random_seed[i];
    }

    /* init modulus */
    ramstake_modulus_init(p);

    /* generate randomness for g */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        pk->seed[i] = randomness_buffer[randomness_index+i];
    }
    randomness_index += RAMSTAKE_SEED_LENGTH;


    /* generate g from seed */
    ramstake_generate_g(g, p, pk->seed);

    if( kat >= 2 )
    {
        printf("seed for generating g: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", pk->seed[i]);
        }
        printf("\n");
    }
    if( kat >= 3 )
    {
        printf("g: ");
        printf("\n");
        mpz_out_str(stdout, 10, g);
        printf("\n");
    }

    /* sample sk integers a and b */
    ramstake_sample_sparse_integer(sk->a, randomness_buffer + randomness_index, RAMSTAKE_MULTIPLICATIVE_MASS);
    randomness_index += RAMSTAKE_ULONG_LENGTH * RAMSTAKE_MULTIPLICATIVE_MASS;

    ramstake_sample_sparse_integer(sk->b, randomness_buffer + randomness_index, RAMSTAKE_ADDITIVE_MASS);
    randomness_index += RAMSTAKE_ULONG_LENGTH * RAMSTAKE_ADDITIVE_MASS;

    if( kat >= 3 )
    {
        printf("Sampled short and sparse integers a and b.\n");
        printf("a: ");
        mpz_out_str(stdout, 10, sk->a);
        printf("\nb: ");
        mpz_out_str(stdout, 10, sk->b);
        printf("\n");
    }

    /* compute pk integer c = ag + b mod p */
    mpz_mul(pk->c, g, sk->a);
    mpz_add(pk->c, pk->c, sk->b);
    mpz_mod(pk->c, pk->c, p);

    if( kat >= 3 )
    {
        printf("Computed c = ag + b mod p.\n");
        printf("c: ");
        mpz_out_str(stdout, 10, pk->c);
        printf("\n");
    }

    /* free remaining unfreed variables */
    mpz_clear(p);
    mpz_clear(g);
    free(randomness_buffer);

    return 0;
}

/**
 * ramstake_encaps
 * Encapsulate a symmetric key under a ramstake public key.
 */
int ramstake_encaps( ramstake_ciphertext * c, unsigned char * key, ramstake_public_key pk, unsigned char * randomness, int kat )
{
    mpz_t a, b;
    mpz_t p;
    mpz_t g;
    mpz_t s;
    int i;
    unsigned char * data;
    unsigned char * randomness_buffer;
    int randomness_index;
    codec_rs codec;

    mpz_init(p);
    ramstake_modulus_init(p);

    /* expand randomness */
    randomness_buffer = malloc(RAMSTAKE_ENCAPS_RANDOM_BYTES);
    SHAKE256(randomness_buffer, RAMSTAKE_ENCAPS_RANDOM_BYTES, randomness, RAMSTAKE_SEED_LENGTH);
    randomness_index = 0;

    if( kat >= 1 )
    {
        printf("\n# ramstake_encaps\n");
        printf("seed: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", randomness[i]);
        }
        printf("\n");
    }

    /* sample integers a, b */
    mpz_init(a);
    ramstake_sample_sparse_integer(a, randomness_buffer + randomness_index, RAMSTAKE_MULTIPLICATIVE_MASS);
    randomness_index += RAMSTAKE_MULTIPLICATIVE_MASS * RAMSTAKE_ULONG_LENGTH;

    mpz_init(b);
    ramstake_sample_sparse_integer(b, randomness_buffer + randomness_index, RAMSTAKE_ADDITIVE_MASS);
    randomness_index += RAMSTAKE_ADDITIVE_MASS * RAMSTAKE_ULONG_LENGTH;

    if( kat >= 3 )
    {
        printf("Sampled short and sparse integers a and b.\n");
        printf("a: ");
        mpz_out_str(stdout, 10, a);
        printf("\nb: ");
        mpz_out_str(stdout, 10, b);
        printf("\n");
    }

    /* re-generate g from pk seed */
    mpz_init(g);
    ramstake_generate_g(g, p, pk.seed);

    if( kat >= 2 )
    {
        printf("Recreated g from public key seed: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", pk.seed[i]);
        }
        printf("\n");
    }
    if( kat >= 3 )
    {
        printf("g: ");
        mpz_out_str(stdout, 10, g);
        printf("\n");
    }

    /* compute d = ag + b mod p */
    mpz_mul(c->d, a, g);
    mpz_add(c->d, c->d, b);
    mpz_mod(c->d, c->d, p);
    if( kat >= 3 )
    {
        printf("Computed d = ag + b mod p.\n");
        printf("d: ");
        mpz_out_str(stdout, 10, c->d);
        printf("\n");
    }

    /* compute local data stream integer s = ca mod p */
    mpz_init(s);
    mpz_mul(s, pk.c, a);
    mpz_mod(s, s, p);
    if( kat >= 3 )
    {
        printf("Computed noisy shared secret integer s = ac mod p.\n");
        printf("pk.c: ");
        mpz_out_str(stdout, 10, pk.c);
        printf("\n");
        printf("p: ");
        mpz_out_str(stdout, 10, p);
        printf("\n");
        printf("s: ");
        mpz_out_str(stdout, 10, s);
        printf("\n");
    }

    /* draw pseudorandom stream from integer */
    data = malloc((RAMSTAKE_MODULUS_BITSIZE+7)/8 + 1);
    for( i = 0 ; i < (RAMSTAKE_MODULUS_BITSIZE+7)/8 + 1 ; ++i )
    {
        data[i] = 0;
    }
    mpz_setbit(s, RAMSTAKE_MODULUS_BITSIZE);
    mpz_export(data, NULL, -1, 1, 1, 0, s);
    /* we only care about the first (least significant) SEEDENC_LENGTH bytes. */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        c->e[i] = data[i];
    }
    free(data);
    if( kat >= 3 )
    {
        printf("Drew most significant %i bytes from s: ", RAMSTAKE_SEEDENC_LENGTH);
        for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
        {
            printf("%02x", c->e[i]);
        }
        printf("\n");
    }

    /* encode seed using reed-solomon ecc */
    codec_rs_init(&codec, 256, RAMSTAKE_CODEWORD_LENGTH*8*RAMSTAKE_CODEWORD_NUMBER, RAMSTAKE_CODEWORD_LENGTH*8, RAMSTAKE_CODEWORD_NUMBER);
    data = malloc((codec.n+7)/8);
    codec_rs_encode(data, codec, randomness);
    codec_rs_destroy(codec);
    if( kat >= 1 )
    {
        printf("Encoded randomness using repetition of %i codewords of length %i\n", RAMSTAKE_CODEWORD_NUMBER, RAMSTAKE_CODEWORD_LENGTH*8);
    }
    if( kat >= 3 )
    {
        printf("Encoded randomness using ECC: ");
        for( i = 0 ; i < RAMSTAKE_CODEWORD_LENGTH * RAMSTAKE_CODEWORD_NUMBER ; ++i )
        {
            printf("%02x", data[i]);
        }
        printf("\n");
    }

    /* put hash of seed into plaintext too */
    SHA3_256(c->h, randomness, RAMSTAKE_SEED_LENGTH);
    if( kat >= 1 )
    {
        printf("Hash of seed in ciphertext: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", c->h[i]);
        }
        printf("\n");
    }

    /* xor encoded seed into pseudorandom data stream and loop until
     * no more stream left; seed is protected by one-time pad */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        c->e[i] ^= data[i];
    }
    free(data);
    if( kat >= 3 )
    {
        printf("Applied one-time pad to sequence of %i repetitions of the codeword.\ndata: ", RAMSTAKE_CODEWORD_NUMBER);
        for( i = 0  ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
        {
            printf("%02x", c->e[i]);
        }
        printf("\n");
    }

    /* grab key by completing s and hashing it */
    /* s = a c + b mod p */
    data = malloc(RAMSTAKE_PUBLIC_KEY_LENGTH + RAMSTAKE_ENCAPS_RANDOM_BYTES);
    ramstake_export_public_key(data, pk);
    for( i = 0 ; i < RAMSTAKE_ENCAPS_RANDOM_BYTES ; ++i )
    {
        data[RAMSTAKE_PUBLIC_KEY_LENGTH + i] = randomness_buffer[i];
    }
    if( kat >= 3 )
    {
        printf("Hash input: ");
        for( i = 0 ; i < RAMSTAKE_PUBLIC_KEY_LENGTH + RAMSTAKE_ENCAPS_RANDOM_BYTES ; ++i )
        {
            printf("%02x", data[i]);
        }
        printf("\n");
    }
    SHA3_256(key, data, RAMSTAKE_PUBLIC_KEY_LENGTH + RAMSTAKE_ENCAPS_RANDOM_BYTES);
    if( kat >= 1 )
    {
        printf("Hashed s into key: ");
        for( i = 0 ; i < RAMSTAKE_KEY_LENGTH ; ++i )
        {
            printf("%02x", key[i]);
        }
        printf("\n");
        if( kat >= 3 )
        {
            printf("From s: ");
            mpz_out_str(stdout, 10, s);
            printf("\n");
        }
    }

    /* free unfreed variables */
    free(data);
    free(randomness_buffer);
    mpz_clear(p);
    mpz_clear(s);
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(g);

    return 0;
}

/**
 * ramstake_decaps
 * Decapsulate symmetric key from ramstake ciphertext, and check for
 * manipulation.
 */
int ramstake_decaps( unsigned char * key, ramstake_ciphertext c, ramstake_secret_key sk, int kat )
{
    int i, j;
    int decoding_success;
    codec_rs codec;
    mpz_t g, p;
    mpz_t s;
    unsigned char * data;
    unsigned char word[RAMSTAKE_SEEDENC_LENGTH];
    unsigned char decoded[RAMSTAKE_SEED_LENGTH];
    ramstake_public_key pk;
    ramstake_ciphertext rec;

    /* initialize pk object */
    ramstake_public_key_init(&pk);

    /* recreate the csprng from keygen */
    SHAKE256(pk.seed, RAMSTAKE_SEED_LENGTH, sk.seed, RAMSTAKE_SEED_LENGTH);

    if( kat >= 1 )
    {
        printf("\n# ramstake_decaps\n");
        printf("secret key seed: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", sk.seed[i]);
        }
        printf("\n");
        printf("Recreated public key seed for g: ");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
        {
            printf("%02x", pk.seed[i]);
        }
        printf("\n");
    }

    /* initialize modulus */
    mpz_init(p);
    ramstake_modulus_init(p);

    /* re-generate g from pk seed */
    mpz_init(g);
    ramstake_generate_g(g, p, pk.seed);

    /* generate data stream integer s = da mod p */
    mpz_init(s);
    mpz_mul(s, c.d, sk.a);
    mpz_mod(s, s, p);
    if( kat >= 3 )
    {
        printf("Computed noisy shared secret integer s = da mod p.\n");
        printf("s: ");
        mpz_out_str(stdout, 10, s);
        printf("\n");
        printf("from sk.a: ");
        mpz_out_str(stdout, 10, sk.a);
        printf("\n");
    }
    
    /* turn noisy-shared integer s into noisy-shared data stream */
    data = malloc((RAMSTAKE_MODULUS_BITSIZE+7)/8 + 1);
    for( i = 0 ; i < (RAMSTAKE_MODULUS_BITSIZE+7)/8 + 1; ++i )
    {
        data[i] = 0;
    }
    mpz_setbit(s, RAMSTAKE_MODULUS_BITSIZE);
    mpz_export(data, NULL, -1, 1, 1, 0, s);

    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        word[i] = data[i];
    }
    free(data);
    if( kat >= 3 )
    {
        printf("Drew most significant %i bytes from s: ", RAMSTAKE_SEEDENC_LENGTH);
        for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
        {
            printf("%02x", word[i]);
        }
        printf("\n");
    }

    /* xor encoded string e into our noisy codeword */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        word[i] ^= c.e[i];
    }
    if( kat >= 3 )
    {
        printf("Undid one-time pad: ");
        for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
        {
            printf("%02x", word[i]);
        }
        printf("\n");
    }

    /* decode the sequence of codewords */
    codec_rs_init(&codec, 256, 255*8*RAMSTAKE_CODEWORD_NUMBER, 255*8, RAMSTAKE_CODEWORD_NUMBER);
    decoding_success = codec_rs_decode(decoded, codec, word, c.h);
    codec_rs_destroy(codec);

    if( decoding_success == 0 )
    {
        mpz_clear(g);
        mpz_clear(p);
        mpz_clear(s);
        ramstake_public_key_destroy(pk);
        if( kat >= 1 )
        {
            printf("None of the received words were decodable.\n");
        }
        return RAMSTAKE_DECODING_FAILURE; /* decapsulation failure */
    }

    /* now we have the seed that generated the ciphertext, let's see
     * if we can recreate the entire thing */
    ramstake_ciphertext_init(&rec);
    mpz_mul(pk.c, g, sk.a);
    mpz_add(pk.c, pk.c, sk.b);
    mpz_mod(pk.c, pk.c, p);
    ramstake_encaps(&rec, key, pk, decoded, 0);

    if( kat >= 1 )
    {
        printf("Re-encapsulating ciphertext from transmitted seed.\n");
        printf("seed: ");
        for( j = 0 ; j < RAMSTAKE_SEED_LENGTH ; ++j )
        {
            printf("%02x", decoded[j]);
        }
        printf("\n");
    }
    if( kat >= 3 )
    {
        printf("d: ");
        mpz_out_str(stdout, 10, rec.d);
        printf("\n");
        printf("e: ");
        for( j = 0 ; j < RAMSTAKE_SEEDENC_LENGTH ; ++j )
        {
            printf("%02x", rec.e[j]);
        }
        printf("\n");
    }

    /* decide whether the entire recreated ciphertext is identical */
    if( mpz_cmp(rec.d, c.d) == 0 && strncmp((const char *)rec.e, (const char *)c.e, RAMSTAKE_SEEDENC_LENGTH) == 0 && strncmp((const char *)rec.h, (const char *)c.h, RAMSTAKE_SEED_LENGTH) == 0 )
    {
        mpz_clear(g);
        mpz_clear(p);
        mpz_clear(s);
        ramstake_public_key_destroy(pk);
        ramstake_ciphertext_destroy(rec);
        return 0; /* success */
    }
    if( mpz_cmp(rec.d, c.d) != 0 )
    {
        printf("recovered d =/= ciphertext d\n");
        if( kat >= 3 )
        {
            printf("recovered: "); mpz_out_str(stdout, 10, rec.d); printf("\n");
            printf("ciphertext: "); mpz_out_str(stdout, 10, c.d); printf("\n");
        }
    }
    if( strncmp((const char*)rec.e, (const char*)c.e, RAMSTAKE_SEEDENC_LENGTH) != 0 )
    {
        printf("recovered e =/= ciphertext e\n");
    }
    if( strncmp((const char*)rec.h, (const char*)c.h, RAMSTAKE_SEED_LENGTH) != 0 )
    {
        printf("recovered h =/= ciphertext h\n");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
            printf("%02x", rec.h[i]);
        printf("\n");
        for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
            printf("%02x", c.h[i]);
        printf("\n");
    }
    printf("received seed: ");
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        printf("%02x", decoded[i]);
    }
    printf("\n");

    mpz_clear(g);
    mpz_clear(p);
    mpz_clear(s);
    ramstake_public_key_destroy(pk);
    ramstake_ciphertext_destroy(rec);
    return RAMSTAKE_INTEGRITY_FAILURE; /* integrity failure */
}

/**
 * ramstake_sample_sparse_integer
 * Sample a small-and-sparse integer at random using the given seed.
 * @params:
 *  * integer : the sparse integer (return value)
 *  * buffer : buffer from which to draw the integers
 *  * int mass : the number of nonzero bits in the sparse integer
 */
void ramstake_sample_sparse_integer( mpz_t integer, unsigned char * buffer, int mass )
{
    int i, j;
    unsigned long int uli;
    mpz_t difference;

    mpz_init(difference);

    mpz_set_ui(integer, 0);

    for( i = 0 ; i < mass ; ++i )
    {
        uli = 0;
        for( j = 0 ; j < RAMSTAKE_ULONG_LENGTH ; ++j )
        {
            uli = uli*256;
            uli = uli + buffer[i*RAMSTAKE_ULONG_LENGTH + j];
        }
        mpz_set_ui(difference, 1);
        mpz_mul_2exp(difference, difference, uli  % RAMSTAKE_MODULUS_BITSIZE);
        mpz_add(integer, integer, difference);
    }

    mpz_clear(difference);
}

/**
 * ramstake_generate_g
 * Extract randomness from a short seed and turn it into an integer.
 */
void ramstake_generate_g( mpz_t g, mpz_t p, unsigned char * random_seed )
{
    unsigned char * data;
    data = malloc((RAMSTAKE_MODULUS_BITSIZE+7)/8+2);
    SHAKE256(data, (RAMSTAKE_MODULUS_BITSIZE+7)/8+2, random_seed, RAMSTAKE_SEED_LENGTH);
    mpz_import(g, (RAMSTAKE_MODULUS_BITSIZE+7)/8+2, 1, sizeof(unsigned char), 1, 0, data);
    mpz_mod(g, g, p);
    free(data);
}

/**
 * ramstake_modulus_init
 * Initialize modulus to fixed value
 */
void ramstake_modulus_init( mpz_t p )
{
    mpz_t difference;

    mpz_init(difference);

    /* set modulus p to p = 2^bitsize - difference */
    /* for Mersenne primes, difference = 1 */
    mpz_set_ui(difference, 1);
    mpz_set_ui(p, 1);
    mpz_mul_2exp(p, p, RAMSTAKE_MODULUS_BITSIZE);
    mpz_sub(p, p, difference);

    mpz_clear(difference);
}
void ramstake_modulus_destroy( mpz_t p )
{
    mpz_clear(p);
};

/**
 * ramstake_secret_key_init
 * Initialize ramstake secret key object.
 */
void ramstake_secret_key_init( ramstake_secret_key * sk )
{
    mpz_init(sk->a);
    mpz_init(sk->b);
}
/**
 * ramstake_secret_key_destroy
 * Deallocate space occupied by the given secret key.
 */
void ramstake_secret_key_destroy( ramstake_secret_key sk )
{
    mpz_clear(sk.a);
    mpz_clear(sk.b);
}

/**
 * ramstake_public_key_init
 * Initialize a ramstake public key object.
 */
void ramstake_public_key_init( ramstake_public_key * pk )
{
    mpz_init(pk->c);
}
/**
 * ramstake_public_key_destroy
 * Deallocate space occupied by the given public key object.
 */
void ramstake_public_key_destroy( ramstake_public_key pk )
{
    mpz_clear(pk.c);
}

/**
 * ramstake_ciphertext_init
 * Initialize a ramstake ciphertext object.
 */
void ramstake_ciphertext_init( ramstake_ciphertext * c )
{
    mpz_init(c->d);
}

/**
 * ramstake_ciphertext_destroy
 * Deallocate space occupied by a ramstake ciphertet object.
 */
void ramstake_ciphertext_destroy( ramstake_ciphertext c )
{
    mpz_clear(c.d);
}

/**
 * ramstake_export_secret_key
 * Turn the ramstake secret key into a string of bytes. The
 * destination buffer "data" should be at least
 * RAMSTAKE_SECRET_KEY_LENGTH bytes long.
 */
void ramstake_export_secret_key( unsigned char * data, ramstake_secret_key sk )
{
   int i;

   /* copy seed */
   for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
   {
       data[i] = sk.seed[i];
   }

   /* put zeros in the place of integers */
   for( i = 0 ; i < 2*((RAMSTAKE_MODULUS_BITSIZE+7)/8) ; ++i )
   {
       data[i+RAMSTAKE_SEED_LENGTH] = 0;
   }

   /* copy integers */
   mpz_export(data + RAMSTAKE_SEED_LENGTH, NULL, -1, 1, 1, 0, sk.a);
   mpz_export(data + RAMSTAKE_SEED_LENGTH + (RAMSTAKE_MODULUS_BITSIZE+7)/8, NULL, -1, 1, 1, 0, sk.b);
}

/**
 * ramstake_import_secret_key
 * Turn a string of bytes into a ramstake secret key.
 */
void ramstake_import_secret_key( ramstake_secret_key * sk, const unsigned char * data )
{
    int i;

    /* copy seed */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        sk->seed[i] = data[i];
    }

    /* copy integers */
    mpz_import(sk->a, (RAMSTAKE_MODULUS_BITSIZE+7)/8, -1, 1, 1, 0, data + RAMSTAKE_SEED_LENGTH);
    mpz_import(sk->b, (RAMSTAKE_MODULUS_BITSIZE+7)/8, -1, 1, 1, 0, data + RAMSTAKE_SEED_LENGTH + (RAMSTAKE_MODULUS_BITSIZE+7)/8);
}

/**
 * ramstake_export_public_key
 * Turn a ramstake public key object into a string of bytes. The
 * destination buffer "data" should be at least
 * RAMSTAKE_PUBLIC_KEY_LENGTH bytes long.
 */
void ramstake_export_public_key( unsigned char * data, ramstake_public_key pk )
{
    int i;

    /* copy seed */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        data[i] = pk.seed[i];
    }

    /* put zeros in the place of the integer */
    for( i = 0 ; i < (RAMSTAKE_MODULUS_BITSIZE+7)/8 ; ++i )
    {
        data[i+RAMSTAKE_SEED_LENGTH] = 0;
    }

    /* copy integer */
    mpz_export(data + RAMSTAKE_SEED_LENGTH, NULL, -1, 1, 1, 0, pk.c);

}

/**
 * ramstake_import_public_key
 * Turn a string of bytes into a ramstake public key.
 */
void ramstake_import_public_key( ramstake_public_key * pk, const unsigned char * data )
{
    int i;

    /* copy seed */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        pk->seed[i] = data[i];
    }

    /* copy integer */
    mpz_import(pk->c, (RAMSTAKE_MODULUS_BITSIZE+7)/8, -1, 1, 1, 0, data + RAMSTAKE_SEED_LENGTH);
}

/**
 * ramstake_export_ciphertext
 * Turn a ramstake ciphertext object into a string of bytes. The
 * destination buffer "data" should be at least
 * RAMSTAKE_CIPHERTEXT_LENGTH bytes long.
 */
void ramstake_export_ciphertext( unsigned char * data, ramstake_ciphertext c )
{
    int i;

    /* put zeros in the place of the integer */
    for( i = 0 ; i < (RAMSTAKE_MODULUS_BITSIZE+7)/8 ; ++i )
    {
        data[i] = 0;
    }

    /* copy integer */
    mpz_export(data, NULL, -1, 1, 1, 0, c.d);

    /* copy seed encoding */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        data[i + (RAMSTAKE_MODULUS_BITSIZE+7)/8] = c.e[i];
    }

    /* copy hash */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        data[i + (RAMSTAKE_MODULUS_BITSIZE+7)/8 + RAMSTAKE_SEEDENC_LENGTH] = c.h[i];
    }
}

/**
 * ramstake_import_ciphertext
 * Turn a string of bytes into a ramstake ciphertext object.
 */
void ramstake_import_ciphertext( ramstake_ciphertext * c, const unsigned char * data )
{
    int i;

    /* copy integer */
    mpz_import(c->d, (RAMSTAKE_MODULUS_BITSIZE+7)/8, -1, 1, 1, 0, data);

    /* copy seed encoding */
    for( i = 0 ; i < RAMSTAKE_SEEDENC_LENGTH ; ++i )
    {
        c->e[i] = data[i + (RAMSTAKE_MODULUS_BITSIZE+7)/8];
    }

    /* copy hash */
    for( i = 0 ; i < RAMSTAKE_SEED_LENGTH ; ++i )
    {
        c->h[i] = data[i + (RAMSTAKE_MODULUS_BITSIZE+7)/8 + RAMSTAKE_SEEDENC_LENGTH];
    }
}

