/*
	Nothing fancy here, just an implementation of a container that stores OIL_VARS bits and supports basic functionalities such as xoring, reading bits and flipping a bit
*/

#ifndef BITCONTAINER128_H
#define BITCONTAINER128_H

#include <stdint.h>
#include <libkeccak.a.headers/KeccakSpongeWidth1600.h>
#include "buffer.h"
#include "keccakrng.h"
#include "parameters.h"

#if OIL_VARS > 64

#define BITCONTAINER_COMPONENTS ((OIL_VARS+63)/64)

typedef struct {
	uint64_t components[BITCONTAINER_COMPONENTS];
} bitcontainer;

static const bitcontainer empty = {{0}};

void serialize_bitcontainer(writer * Buff, bitcontainer b);
bitcontainer deserialize_bitcontainer(reader *Buff);
bitcontainer xor(bitcontainer a, bitcontainer b);
bitcontainer randomBitcontainer(Sponge *sponge);
uint64_t getBit(bitcontainer container, uint64_t bit);
void flipBit(bitcontainer *container, uint64_t bit);

#else 

#define bitcontainer uint64_t
#define empty ((uint64_t) 0)
#define xor(a,b) a^b
#define getBit(container,bit) (container & ((uint64_t)1) << bit)
#define flipBit(container,bit) (*container ^= ((uint64_t)1) << bit)
#define randomBitcontainer(sponge) squeezeuint64_t(sponge,((OIL_VARS+7)/8))
#define serialize_bitcontainer(W,container) serialize_uint64_t(W, container , OIL_VARS)
#define deserialize_bitcontainer(R) deserialize_uint64_t(R,OIL_VARS)

#endif

void squeezeBitcontainerArray(Sponge *sponge, bitcontainer *arr, int size);

#endif
