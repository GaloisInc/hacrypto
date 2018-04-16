#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "pqcrypto_sign_PRIMITIVE.h"
#include "limits.h"
#include "freadall.h"

static unsigned char sk[pqcrypto_sign_PRIMITIVE_SECRETKEYBYTES];

static void die_temp(const char *why,const char *why2)
{
  if (why2)
    fprintf(stderr,"pq-sign-PRIMITIVE: fatal: %s: %s\n",why,why2);
  else
    fprintf(stderr,"pq-sign-PRIMITIVE: fatal: %s\n",why);
  exit(111);
}

int main()
{
  FILE *fisk;
  unsigned char *buf;
  unsigned long long inputlen;
  unsigned long long outputlen;

  limits();

  fisk = fdopen(8,"r");
  if (!fisk) {
    fprintf(stderr,"pq-sign-PRIMITIVE: usage: sign <message 8<secretkey >signedmessage\n");
    die_temp("fdopen 8 failed",strerror(errno));
  }
  if (fread(sk,1,sizeof sk,fisk) < sizeof sk) {
    if (ferror(fisk))
      die_temp("read secretkey failed",strerror(errno));
    die_temp("read secretkey failed","end of file");
  }
  fclose(fisk);

  buf = freadall(&inputlen,0,pqcrypto_sign_PRIMITIVE_BYTES,stdin);
  if (!buf) die_temp("out of memory",0);
  if (ferror(stdin))
    die_temp("read message failed",strerror(errno));

  if (pqcrypto_sign_PRIMITIVE(buf,&outputlen,buf,inputlen,sk))
    die_temp("sign failed",0);

  if (fwrite(buf,1,outputlen,stdout) < outputlen)
    die_temp("write signedmessage failed",strerror(errno));
  if (fflush(stdout))
    die_temp("write signedmessage failed",strerror(errno));
  free(buf);

  return 0;
}
