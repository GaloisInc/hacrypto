#define CRYPTO_SECRETKEYBYTES 54056
#define CRYPTO_PUBLICKEYBYTES 27044
#define CRYPTO_BYTES 32
#define CRYPTO_CIPHERTEXTBYTES 28064

#define CRYPTO_ALGNAME "Ramstake RS 216091"

int crypto_kem_keypair( unsigned char *pk, unsigned char *sk );
int crypto_kem_enc( unsigned char *ct, unsigned char *ss, const unsigned char *pk );
int crypto_kem_dec( unsigned char *ss, const unsigned char *ct, const unsigned char *sk );
