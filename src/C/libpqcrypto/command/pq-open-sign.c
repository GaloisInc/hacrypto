#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "pqcrypto_sign_PRIMITIVE.h"
#include "limits.h"
#include "freadall.h"

static unsigned char pk[pqcrypto_sign_PRIMITIVE_PUBLICKEYBYTES];

static void die_perm(const char *why)
{
  fprintf(stderr,"pq-open-PRIMITIVE: fatal: %s\n",why);
  exit(100);
}

static void die_temp(const char *why,const char *why2)
{
  if (why2)
    fprintf(stderr,"pq-open-PRIMITIVE: fatal: %s: %s\n",why,why2);
  else
    fprintf(stderr,"pq-open-PRIMITIVE: fatal: %s\n",why);
  exit(111);
}

int main()
{
  FILE *fipk;
  unsigned char *buf;
  unsigned long long inputlen;
  unsigned long long outputlen;

  limits();

  fipk = fdopen(4,"r");
  if (!fipk) {
    fprintf(stderr,"pq-open-PRIMITIVE: usage: open <signedmessage 4<publickey >message\n");
    die_temp("fdopen 4 failed",strerror(errno));
  }
  if (fread(pk,1,sizeof pk,fipk) < sizeof pk) {
    if (ferror(fipk))
      die_temp("read publickey failed",strerror(errno));
    die_temp("read publickey failed","end of file");
  }
  fclose(fipk);

  buf = freadall(&inputlen,0,0,stdin);
  if (!buf) die_temp("out of memory",0);
  if (ferror(stdin))
    die_temp("read signedmessage failed",strerror(errno));

  if (pqcrypto_sign_PRIMITIVE_open(buf,&outputlen,buf,inputlen,pk))
    die_perm("open failed");
    /* XXX: this exit code assumes no malloc failures */

  if (fwrite(buf,1,outputlen,stdout) < outputlen)
    die_temp("write message failed",strerror(errno));
  if (fflush(stdout))
    die_temp("write message failed",strerror(errno));
  free(buf);

  return 0;
}
