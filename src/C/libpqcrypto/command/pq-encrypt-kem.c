#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "pqcrypto_kem_PRIMITIVE.h"
#include "pqcrypto_hash_shake256.h"
#include "pqcrypto_stream_salsa20.h"
#include "pqcrypto_onetimeauth_poly1305.h"
#include "limits.h"
#include "freadall.h"

#if pqcrypto_hash_shake256_BYTES < pqcrypto_stream_salsa20_KEYBYTES + pqcrypto_onetimeauth_poly1305_KEYBYTES
#error "pqcrypto_hash_shake256_BYTES < pqcrypto_stream_salsa20_KEYBYTES + pqcrypto_onetimeauth_poly1305_KEYBYTES"
#endif

#define MACLEN pqcrypto_onetimeauth_poly1305_BYTES

static unsigned char pk[pqcrypto_kem_PRIMITIVE_PUBLICKEYBYTES];
static unsigned char c[pqcrypto_kem_PRIMITIVE_CIPHERTEXTBYTES];
static unsigned char k[pqcrypto_kem_PRIMITIVE_BYTES];
static unsigned char hk[pqcrypto_hash_shake256_BYTES];
static unsigned char kenc[pqcrypto_stream_salsa20_KEYBYTES];
static unsigned char kauth[pqcrypto_onetimeauth_poly1305_KEYBYTES];
static unsigned char nonce[pqcrypto_stream_salsa20_NONCEBYTES];

static void die_temp(const char *why,const char *why2)
{
  if (why2)
    fprintf(stderr,"pq-encrypt-PRIMITIVE: fatal: %s: %s\n",why,why2);
  else
    fprintf(stderr,"pq-encrypt-PRIMITIVE: fatal: %s\n",why);
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
    fprintf(stderr,"pq-encrypt-PRIMITIVE: usage: encrypt <message 4<publickey >ciphertext\n");
    die_temp("fdopen 4 failed",strerror(errno));
  }
  if (fread(pk,1,sizeof pk,fipk) < sizeof pk) {
    if (ferror(fipk))
      die_temp("read publickey failed",strerror(errno));
    die_temp("read publickey failed","end of file");
  }
  fclose(fipk);

  if (pqcrypto_kem_PRIMITIVE_enc(c,k,pk)) die_temp("encapsulation failed",0);

  buf = freadall(&inputlen,MACLEN,sizeof c,stdin);
  if (!buf) die_temp("out of memory",0);
  if (ferror(stdin))
    die_temp("read message failed",strerror(errno));

  pqcrypto_hash_shake256(hk,k,sizeof k);
  memcpy(kenc,hk,sizeof kenc);
  memcpy(kauth,hk + sizeof kenc,sizeof kauth);

  pqcrypto_stream_salsa20_xor(buf + MACLEN,buf + MACLEN,inputlen,nonce,kenc);
  pqcrypto_onetimeauth_poly1305(buf,buf + MACLEN,inputlen,kauth);
  memcpy(buf + MACLEN + inputlen,c,sizeof c);
  /* this order helps encourage people not to release unverified plaintexts */

  outputlen = MACLEN + inputlen + sizeof c;
  if (fwrite(buf,1,outputlen,stdout) < outputlen)
    die_temp("write ciphertext failed",strerror(errno));
  if (fflush(stdout))
    die_temp("write ciphertext failed",strerror(errno));
  free(buf);

  return 0;
}
