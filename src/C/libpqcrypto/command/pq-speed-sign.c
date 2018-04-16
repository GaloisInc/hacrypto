#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pqcrypto_sign_PRIMITIVE.h"
#include "pqcpucycles.h"
#include "limits.h"

static unsigned char pk[pqcrypto_sign_PRIMITIVE_PUBLICKEYBYTES];
static unsigned char sk[pqcrypto_sign_PRIMITIVE_SECRETKEYBYTES];
static unsigned char m[59];
static unsigned long long mlen = 59;
static unsigned char sm[59 + pqcrypto_sign_PRIMITIVE_BYTES];
static unsigned long long smlen;
static unsigned char m2[59 + pqcrypto_sign_PRIMITIVE_BYTES];
static unsigned long long m2len;

#define TIMINGS4 8
#define TIMINGS (4*(TIMINGS4) - 1)

static unsigned long long t[TIMINGS + 1];
static unsigned long long result[TIMINGS + 1];

int cmp(const void *av,const void *bv)
{
  const unsigned long long *a = av;
  const unsigned long long *b = bv;
  if (*a < *b) return -1;
  if (*a > *b) return 1;
  return 0;
}

static void printquartiles(const char *name)
{
  long long i, q1, q2, q3;

  for (i = 0;i < TIMINGS;++i) t[i] = t[i + 1] - t[i];
  qsort(t,TIMINGS,sizeof(t[0]),cmp);
  q1 = t[TIMINGS4 - 1];
  q2 = t[2 * TIMINGS4 - 1];
  q3 = t[3 * TIMINGS4 - 1];
  for (i = 0;i < TIMINGS;++i) if (result[i] != 0) q1 = q2 = q3 = -1;
  printf(" %s %lld %lld %lld",name,q1,q2,q3);
}

int main()
{
  long long i;

  limits();

  printf("PRIMITIVE speed");

  for (i = 0;i <= TIMINGS;++i) {
    t[i] = pqcpucycles();
    result[i] = pqcrypto_sign_PRIMITIVE_keypair(pk,sk);
  }
  printquartiles("keypair");

  for (i = 0;i <= TIMINGS;++i) {
    t[i] = pqcpucycles();
    result[i] = pqcrypto_sign_PRIMITIVE(sm,&smlen,m,mlen,sk);
  }
  printquartiles("sign");

  for (i = 0;i <= TIMINGS;++i) {
    t[i] = pqcpucycles();
    result[i] = pqcrypto_sign_PRIMITIVE_open(m2,&m2len,sm,smlen,pk);
  }
  if (m2len != mlen) result[0] = -1;
  if (memcmp(m2,m,mlen)) result[0] = -1;
  printquartiles("open");

  printf("\n");
  return 0;
}
