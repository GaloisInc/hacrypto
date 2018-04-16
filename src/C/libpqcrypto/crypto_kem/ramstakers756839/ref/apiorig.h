#define CRYPTO_SECRETKEYBYTES 189242
#define CRYPTO_PUBLICKEYBYTES 94637
#define CRYPTO_BYTES 32
#define CRYPTO_CIPHERTEXTBYTES 96167

#define CRYPTO_ALGNAME "Ramstake RS 756839"

int crypto_kem_keypair( unsigned char *pk, unsigned char *sk );
int crypto_kem_enc( unsigned char *ct, unsigned char *ss, const unsigned char *pk );
int crypto_kem_dec( unsigned char *ss, const unsigned char *ct, const unsigned char *sk );
