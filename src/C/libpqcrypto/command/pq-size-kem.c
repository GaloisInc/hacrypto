#include <stdio.h>
#include "pqcrypto_kem_PRIMITIVE.h"
#include "limits.h"

int main()
{
  limits();

  printf("PRIMITIVE size publickey %lld secretkey %lld ciphertext %lld sessionkey %lld\n"
    ,(long long) pqcrypto_kem_PRIMITIVE_PUBLICKEYBYTES
    ,(long long) pqcrypto_kem_PRIMITIVE_SECRETKEYBYTES
    ,(long long) pqcrypto_kem_PRIMITIVE_CIPHERTEXTBYTES
    ,(long long) pqcrypto_kem_PRIMITIVE_BYTES
    );
  return 0;
}
