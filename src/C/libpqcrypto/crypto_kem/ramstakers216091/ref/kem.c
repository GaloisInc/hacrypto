#include "crypto_kem.h"
#include "apiorig.h"
#include "ramstake.h"
#include "randombytes.h"

#if CRYPTO_SECRETKEYBYTES != RAMSTAKE_SECRET_KEY_LENGTH
#error "CRYPTO_SECRETKEYBYTES must be RAMSTAKE_SECRET_KEY_LENGTH"
#endif

#if CRYPTO_PUBLICKEYBYTES != RAMSTAKE_PUBLIC_KEY_LENGTH
#error "CRYPTO_PUBLICKEYBYTES must be RAMSTAKE_PUBLIC_KEY_LENGTH"
#endif

#if CRYPTO_CIPHERTEXTBYTES != RAMSTAKE_CIPHERTEXT_LENGTH
#error "CRYPTO_CIPHERTEXTBYTES must be RAMSTAKE_CIPHERTEXT_LENGTH"
#endif

#if CRYPTO_BYTES != RAMSTAKE_KEY_LENGTH
#error "CRYPTO_BYTES must be RAMSTAKE_KEY_LENGTH"
#endif

/* key gen */
int crypto_kem_keypair( unsigned char *pk, unsigned char *sk )
{
    ramstake_secret_key skey;
    ramstake_public_key pkey;
    unsigned char seed[RAMSTAKE_SEED_LENGTH];

    randombytes(seed, RAMSTAKE_SEED_LENGTH);

    ramstake_secret_key_init(&skey);
    ramstake_public_key_init(&pkey);

#ifdef KAT
    ramstake_keygen(&skey, &pkey, seed, 2);
#else
    ramstake_keygen(&skey, &pkey, seed, 0);
#endif

    ramstake_export_secret_key(sk, skey);
    ramstake_export_public_key(pk, pkey);

    ramstake_secret_key_destroy(skey);
    ramstake_public_key_destroy(pkey);

    return 0;
}

/* encapsulate */
int crypto_kem_enc( unsigned char *ct, unsigned char *ss, const unsigned char *pk )
{
    ramstake_public_key pkey;
    ramstake_ciphertext ctext;
    unsigned char seed[RAMSTAKE_SEED_LENGTH];

    randombytes(seed, RAMSTAKE_SEED_LENGTH);

    ramstake_public_key_init(&pkey);
    ramstake_ciphertext_init(&ctext);

    ramstake_import_public_key(&pkey, pk);

#ifdef KAT
    ramstake_encaps(&ctext, ss, pkey, seed, 2);
#else
    ramstake_encaps(&ctext, ss, pkey, seed, 0);
#endif

    ramstake_export_ciphertext(ct, ctext);
    
    ramstake_ciphertext_destroy(ctext);
    ramstake_public_key_destroy(pkey);

    return 0;
}

/* decapsulate */
int crypto_kem_dec( unsigned char *ss, const unsigned char *ct, const unsigned char *sk )
{
    int return_value;
    ramstake_secret_key skey;
    ramstake_ciphertext ctext;

    ramstake_secret_key_init(&skey);
    ramstake_ciphertext_init(&ctext);

    ramstake_import_ciphertext(&ctext, ct);
    ramstake_import_secret_key(&skey, sk);

#ifdef KAT
    return_value = ramstake_decaps(ss, ctext, skey, 2);
#else
    return_value = ramstake_decaps(ss, ctext, skey, 0);
#endif

    ramstake_secret_key_destroy(skey);
    ramstake_ciphertext_destroy(ctext);

    return return_value;
}

