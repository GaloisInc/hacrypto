#include <stdio.h>
#include "pqcrypto_sign_PRIMITIVE.h"
#include "limits.h"

int main()
{
  limits();

  printf("PRIMITIVE size publickey %lld secretkey %lld signature %lld\n"
    ,(long long) pqcrypto_sign_PRIMITIVE_PUBLICKEYBYTES
    ,(long long) pqcrypto_sign_PRIMITIVE_SECRETKEYBYTES
    ,(long long) pqcrypto_sign_PRIMITIVE_BYTES
    );
  return 0;
}
