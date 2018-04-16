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

static unsigned char sk[pqcrypto_kem_PRIMITIVE_SECRETKEYBYTES];
static unsigned char k[pqcrypto_kem_PRIMITIVE_BYTES];
static unsigned char hk[pqcrypto_hash_shake256_BYTES];
static unsigned char kenc[pqcrypto_stream_salsa20_KEYBYTES];
static unsigned char kauth[pqcrypto_onetimeauth_poly1305_KEYBYTES];
static unsigned char nonce[pqcrypto_stream_salsa20_NONCEBYTES];

static void die_perm(const char *why)
{
  fprintf(stderr,"pq-decrypt-PRIMITIVE: fatal: %s\n",why);
  exit(100);
}

static void die_temp(const char *why,const char *why2)
{
  if (why2)
    fprintf(stderr,"pq-decrypt-PRIMITIVE: fatal: %s: %s\n",why,why2);
  else
    fprintf(stderr,"pq-decrypt-PRIMITIVE: fatal: %s\n",why);
  exit(111);
}

int main()
{
  FILE *fisk;
  unsigned char *buf;
  unsigned long long inputlen;

  limits();

  fisk = fdopen(8,"r");
  if (!fisk) {
    fprintf(stderr,"pq-decrypt-PRIMITIVE: usage: decrypt <ciphertext 8<secretkey >message\n");
    die_temp("fdopen 8 failed",strerror(errno));
  }

  buf = freadall(&inputlen,0,0,stdin);
  if (!buf) die_temp("out of memory",0);
  if (ferror(stdin))
    die_temp("read message failed",strerror(errno));

  if (fread(sk,1,sizeof sk,fisk) < sizeof sk) {
    if (ferror(fisk))
      die_temp("read secretkey failed",strerror(errno));
    die_temp("read secretkey failed","end of file");
  }
  fclose(fisk);

  if (inputlen < MACLEN + pqcrypto_kem_PRIMITIVE_CIPHERTEXTBYTES)
    die_perm("short ciphertext");

  inputlen -= pqcrypto_kem_PRIMITIVE_CIPHERTEXTBYTES;

  if (pqcrypto_kem_PRIMITIVE_dec(k,buf + inputlen,sk))
    die_perm("decapsulation failed");
    /* XXX: this exit code assumes no malloc failures */

  pqcrypto_hash_shake256(hk,k,sizeof k);
  memcpy(kenc,hk,sizeof kenc);
  memcpy(kauth,hk + sizeof kenc,sizeof kauth);

  inputlen -= MACLEN;

  if (pqcrypto_onetimeauth_poly1305_verify(buf,buf + MACLEN,inputlen,kauth) != 0)
    die_perm("decryption failed");

  pqcrypto_stream_salsa20_xor(buf + MACLEN,buf + MACLEN,inputlen,nonce,kenc);

  if (fwrite(buf + MACLEN,1,inputlen,stdout) < inputlen)
    die_temp("write message failed",strerror(errno));
  if (fflush(stdout))
    die_temp("write message failed",strerror(errno));
  free(buf);

  return 0;
}
