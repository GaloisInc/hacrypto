#include "keccakrng.h"

/* 
	Initializes a Sponge object, absorbs a seed and finalizes the absorbing phase

	 sponge  : The sponge object
	 seed    : The seed to absorb
	 len     : The length of the seed
*/
void initializeAndAbsorb(Sponge *sponge ,const unsigned char * seed , int len ) {
	Keccak_HashInitialize_SHAKE(sponge);
	Keccak_HashUpdate(sponge, seed, len*8 );
	Keccak_HashFinal(sponge, 0 );
}

/* 
	Squeezes a uint64_t from the sponge object

	sponge : The sponge object
	bytes  : The number of bytes to squeeze from the sponge (should be between 1 and 8)
*/
uint64_t squeezeuint64_t(Sponge *sponge, int bytes){
	unsigned char randombits[8];
	Keccak_HashSqueeze(sponge,randombits, bytes*8);
	return  ((uint64_t) randombits[0])         | (((uint64_t) randombits[1]) << 8  ) |
	       (((uint64_t) randombits[2]) << 16 ) | (((uint64_t) randombits[3]) << 24 ) |
	       (((uint64_t) randombits[4]) << 32 ) | (((uint64_t) randombits[5]) << 40 ) |
	       (((uint64_t) randombits[6]) << 48 ) | (((uint64_t) randombits[7]) << 56 );
}

/* 
	Squeeze a list of Field elements from the sponge

	sponge : The sponge object
	vector : receives the list of field elements
	length : The length of the list of elements
*/
void squeezeVector(Sponge *sponge, FELT *vector, int length) {
	int i;
	// Squeeze the appropriate number of bytes from the sponge
	unsigned char *randombits = malloc(sizeof(FELT)*length);
	Keccak_HashSqueeze(sponge ,randombits,sizeof(FELT)*length*8);
	// Interpret the bytes as field elements
	reader R = newReader(randombits);
	for (i = 0; i < length ; i++) {
		vector[i] = deserialize_FELT(&R);
	}
	free(randombits);
}
