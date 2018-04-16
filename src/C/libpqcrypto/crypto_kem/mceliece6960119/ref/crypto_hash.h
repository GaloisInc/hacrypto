#include <libkeccak.a.headers/KeccakSpongeWidth1600.h>

#define crypto_hash_32b(out,in,inlen) \
  KeccakWidth1600_Sponge(1088,512,in,inlen,0x1F,out,32)
