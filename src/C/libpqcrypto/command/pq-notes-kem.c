#include <stdio.h>
#include "pqcrypto_kem_PRIMITIVE.h"
#include "limits.h"

int main()
{
  limits();

  printf("PRIMITIVE implementation %s\n",pqcrypto_kem_PRIMITIVE_implementation);
  printf("PRIMITIVE version %s\n",pqcrypto_kem_PRIMITIVE_version);
  printf("PRIMITIVE compiler %s\n",pqcrypto_kem_PRIMITIVE_compiler);

  return 0;
}
