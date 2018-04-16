#include <libkeccak.a.headers/KeccakSpongeWidth1600.h>
#include "crypto_hash.h"

int crypto_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  return KeccakWidth1600_Sponge(1088, 512, in, inlen, 0x1F, out, crypto_hash_BYTES);
}
