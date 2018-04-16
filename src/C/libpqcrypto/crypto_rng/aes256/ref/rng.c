#include <string.h>
#include "crypto_stream_aes256ctr.h"
#include "crypto_rng.h"

#define crypto_stream crypto_stream_aes256ctr
#define KEYBYTES crypto_stream_aes256ctr_KEYBYTES
#define NONCEBYTES crypto_stream_aes256ctr_NONCEBYTES
#define OUTPUTBYTES crypto_rng_OUTPUTBYTES

#if KEYBYTES != crypto_rng_KEYBYTES
  KEYBYTES mismatch!
#endif

static const unsigned char nonce[NONCEBYTES] = {0};

int crypto_rng(
        unsigned char *r, /* random output */
        unsigned char *n, /* new key */
  const unsigned char *g  /* old key */
)
{
  unsigned char x[KEYBYTES + OUTPUTBYTES];
  crypto_stream(x,sizeof x,nonce,g);
  memcpy(n,x,KEYBYTES);
  memcpy(r,x + KEYBYTES,OUTPUTBYTES);
  return 0;
}
