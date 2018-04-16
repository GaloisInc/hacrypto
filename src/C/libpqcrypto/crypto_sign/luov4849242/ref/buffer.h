/*
	Defines reader and writer structs. These structs are wrappers for unsigned char arrays and keep track of how much has been written/read.
*/

#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <string.h>

/* writer , used for writing to a unsigned char array */
typedef struct {
	unsigned char *data;
	uint64_t next;
	int bitsUsed;
} writer;

writer newWriter(unsigned char* buf);

/* reader , used for reading from an unsigned char array */
typedef struct {
	const unsigned char *data;
	uint64_t next;
	int bitsUsed;
} reader;

reader newReader(const unsigned char* buf);

void transcribe(writer *W, reader *R, int bytes);

void serialize_uint64_t(writer* W, uint64_t a, int bits);
uint64_t deserialize_uint64_t(reader* R , int bits);

#endif
