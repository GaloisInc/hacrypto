#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "pqcrypto_kem_PRIMITIVE.h"
#include "limits.h"

static unsigned char pk[pqcrypto_kem_PRIMITIVE_PUBLICKEYBYTES];
static unsigned char sk[pqcrypto_kem_PRIMITIVE_SECRETKEYBYTES];

static void die_temp(const char *why,const char *why2)
{
  if (why2)
    fprintf(stderr,"pq-keypair-PRIMITIVE: fatal: %s: %s\n",why,why2);
  else
    fprintf(stderr,"pq-keypair-PRIMITIVE: fatal: %s\n",why);
  exit(111);
}

int main()
{
  FILE *fipk;
  FILE *fisk;

  limits();

  fipk = fdopen(5,"w");
  if (!fipk) {
    fprintf(stderr,"pq-keypair-PRIMITIVE: usage: keypair 5>publickey 9>secretkey\n");
    die_temp("fdopen 5 failed",strerror(errno));
  }

  fisk = fdopen(9,"w");
  if (!fisk) {
    fprintf(stderr,"pq-keypair-PRIMITIVE: usage: keypair 5>publickey 9>secretkey\n");
    die_temp("fdopen 9 failed",strerror(errno));
  }

  if (pqcrypto_kem_PRIMITIVE_keypair(pk,sk))
    die_temp("keypair failed",0);

  if (fwrite(pk,1,sizeof pk,fipk) < sizeof pk)
    die_temp("write publickey failed",strerror(errno));
  if (fflush(fipk))
    die_temp("write publickey failed",strerror(errno));
  fclose(fipk);

  if (fwrite(sk,1,sizeof sk,fisk) < sizeof sk)
    die_temp("write secretkey failed",strerror(errno));
  if (fflush(fisk))
    die_temp("write secretkey failed",strerror(errno));
  fclose(fisk);

  return 0;
}
