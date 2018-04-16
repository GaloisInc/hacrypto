/*
	Finite field of order 2^16 implemented as polynomial ring F_2[x] mod x^16+x^12 + x^3 + 1
*/

#ifndef F8FIELD_H
#define F8FIELD_H

#include <stdint.h>
#include <stdio.h>
#include "buffer.h"
#include "parameters.h"

enum { twoPow8 = 256, f8units = twoPow8 - 1 };
typedef uint8_t f8FELT;

/* Field operations */

void f8printFELT(f8FELT a);
f8FELT f8multiply(f8FELT a, f8FELT b);
f8FELT f8inverse(f8FELT a); 
uint8_t f8log(f8FELT);
f8FELT f8antilog(uint8_t);

/* serialization/deserialization */

void f8serialize_FELT(writer *W, f8FELT a);
f8FELT f8deserialize_FELT(reader *R);

#define f8ZERO 0
#define f8ONE 1
#define f8add(A,B) (A^B)
#define f8isEqual(A,B) (A==B)

#endif