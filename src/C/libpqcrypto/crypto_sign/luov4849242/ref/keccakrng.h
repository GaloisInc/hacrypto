#ifndef RNG_H
#define RNG_H

#include <stdlib.h>
#include <libkeccak.a.headers/KeccakHash.h>
#include "buffer.h"
#include "LinearAlgebra.h"

#define Sponge Keccak_HashInstance 

#define squeezeBytes(S,D,L) Keccak_HashSqueeze (S,D,L * 8)

void initializeAndAbsorb(Sponge *sponge, const unsigned char * seed, int len);
void squeezeVector(Sponge *sponge, FELT *vector , int length);
uint64_t squeezeuint64_t(Sponge *sponge, int bytes);

#endif
