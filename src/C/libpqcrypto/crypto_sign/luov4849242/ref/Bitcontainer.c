#include "Bitcontainer.h"

#if OIL_VARS>64 

/*
	Write a bitcontainer to a char array
*/
void serialize_bitcontainer(writer * W, bitcontainer b) {
	int a = 0;
	int bits = OIL_VARS;
	while (bits >64 ){
		serialize_uint64_t(W, b.components[a++]  , 64);
		bits -= 64;
	}
	serialize_uint64_t(W, b.components[a], bits);
}

/*
	Read a bitcontainer from a char array
*/
bitcontainer deserialize_bitcontainer(reader * R) {
	bitcontainer out;
	int a = 0;
	int bits = OIL_VARS;
	while (bits >64 ){
		out.components[a++] = deserialize_uint64_t(R, 64);
		bits -= 64;
	}
	out.components[a] = deserialize_uint64_t(R, bits);
	return out;
}

/*
	xor two bitcontainers
*/
bitcontainer xor(bitcontainer a, bitcontainer b) {
	int i;
	bitcontainer BC;
	for(i=0 ; i<BITCONTAINER_COMPONENTS ; i++){
		BC.components[i] = a.components[i] ^ b.components[i];
	}
	return BC;
}

/*
	Randomize bitcontainer with Keccak Sponge
*/
bitcontainer randomBitcontainer(Sponge *sponge) {
	bitcontainer BC;
	int i;
	for(i=0 ; i<BITCONTAINER_COMPONENTS-1 ; i++){
		BC.components[i] = squeezeuint64_t(sponge,8);
	}
	BC.components[BITCONTAINER_COMPONENTS-1] = squeezeuint64_t(sponge,((OIL_VARS%64)+7)/8); 
	return BC;
}

/*
	Get a bit from the bitcontainer
*/
uint64_t getBit(bitcontainer container, uint64_t bit) {
	return (container.components[bit/64] & ((uint64_t)1) << (bit%64) );
}

/*
	Flip a bit from the bitcontainer
*/
void flipBit(bitcontainer *container, uint64_t bit) {
	container->components[bit/64] ^= ((uint64_t)1) << (bit%64);
}

#endif

/*
	Generates an array of bitcontainers

	sponge : pointer to a Sponge object
	arr    : the array that will receive the generated bitcontainers
	size   : the number of bitcontainers that is generated
*/
void squeezeBitcontainerArray(Sponge *sponge, bitcontainer *arr, int size) {
	int i;
	for (i = 0; i < size; i++) {
		arr[i] = randomBitcontainer(sponge);
	}
}