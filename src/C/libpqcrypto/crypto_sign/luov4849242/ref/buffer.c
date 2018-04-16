#include "buffer.h" 
/* 
	writes a single bit

	W : The writer object to write to
	b : The bit to write, should be 0 or 1
*/
void writeBit(writer* W, unsigned char b) {
	if (W->bitsUsed == 0){
		W->data[W->next] = 0;
	}
	W->data[W->next] ^= (-b^ W->data[W->next]) & (1 << W->bitsUsed);
	W->bitsUsed++;
	if (W->bitsUsed == 8) {
		W->bitsUsed = 0;
		W->next++;
	}
}

/*
	Reads a single bit

	R : The reader object to read from

	returns: 0 or 1
*/
unsigned char readBit(reader* R) {
	unsigned char out = (R->data[R->next] & (1 << R->bitsUsed)) != 0;
	R->bitsUsed++;
	if (R->bitsUsed == 8) {
		R->bitsUsed = 0;
		R->next++;
	}
	return out;
}

/*
	Writes a uint64_t

	W : The writer object to write to
    a : the uint64_t to write
	bits : the number of bits to write, the least significant bits of a will be written
*/
void serialize_uint64_t(writer* W, uint64_t a , int bits) {
	while (bits > 0)
	{
		writeBit(W, a & 1);
		a >>= 1;
		bits--;
	}
	return;
}

/*
	Reads a uint64_t

	R : The reader object to read from
	bits : the number of bits to read

	returns : a uint64_t value that is read from the char array
*/
uint64_t deserialize_uint64_t(reader* R , int bits) {
	uint64_t out = 0;
	int pos = 0;
	while (pos < bits)
	{
		out |= (((uint64_t) readBit(R)) << pos);
		pos++;
	}
	return out;
}

/*
	Initializes a new writer object

	buf : The char array to write to

	Returns : A writer object, initialized to the start of buf
*/
writer newWriter(unsigned char* buf) {
	writer W;
	W.data = buf;
	W.next = 0;
	W.bitsUsed = 0;
	return W;
}

/*
	Initializes a new reader object

	buf : The char array to read from

	returns : A reader object, initialized to the start of bud
*/
reader newReader(const unsigned char* buf) {
	reader R;
	R.data = buf;
	R.next = 0;
	R.bitsUsed = 0;
	return R;
}

/*
	Copies a number of bytes from a reader object to a writer object

	W : The writer object
	R : The reader object
	bytes : The number of bytes to copy
*/
void transcribe(writer *W, reader *R, int bytes) {
	serialize_uint64_t(W, 0, (8 - W->bitsUsed) % 8);
	deserialize_uint64_t(R, (8 - R->bitsUsed) % 8);
	
	memmove(W->data + W->next, R->data + R->next, bytes);
	W->next += bytes;
	R->next += bytes;
}
