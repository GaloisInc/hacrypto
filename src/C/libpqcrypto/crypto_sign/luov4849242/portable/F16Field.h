/*
	Finite field of order 2^16 implemented as polynomial ring F_2[x] mod x^16+x^12 + x^3 + 1
*/

#ifndef F16FIELD_H
#define F16FIELD_H

#include <stdint.h>
#include "buffer.h"
#include "parameters.h"

enum { twoPow16 = 65536, f16units = twoPow16 - 1 };
typedef uint16_t f16FELT;

/* Field operations */

void f16printFELT(f16FELT a);
f16FELT f16multiply(f16FELT a, f16FELT b);
f16FELT f16inverse(f16FELT a); 
uint32_t f16log(f16FELT);
f16FELT f16antilog(uint32_t);

/* serialization/deserialization */

void f16serialize_FELT(writer *W, f16FELT a);
f16FELT f16deserialize_FELT(reader *R);

/*
Extended Euclidean Algorithm , used for calculating inverses in an extension field of F_2^16.
Given polynomials a and b this calculates the gcd of a and b and polynomials x and y such that a*x + b*y = gcd.
*/
void f16ExtendedEuclideanAlgorithm(f16FELT *a, const f16FELT *b, f16FELT *x, f16FELT *y, f16FELT *gcd);

#define f16ZERO 0
#define f16ONE 1
#define f16add(A,B) (A^B)
#define f16addInPlace(A,B) *A ^= *B
#define f16isEqual(A,B) (A==B)

#define __DEFINE_OPERATION(FS,OPERATION) f##FS##OPERATION
#define _DEFINE_OPERATION(FS,OPERATION) __DEFINE_OPERATION(FS,OPERATION)
#define DEFINE_OPERATION(OPERATION) _DEFINE_OPERATION(FIELD_SIZE,OPERATION)

#define FELT DEFINE_OPERATION(FELT)
#define serialize_FELT DEFINE_OPERATION(serialize_FELT)
#define deserialize_FELT DEFINE_OPERATION(deserialize_FELT)
#define printFELT DEFINE_OPERATION(printFELT)
#define isEqual DEFINE_OPERATION(isEqual)
#define multiply DEFINE_OPERATION(multiply)
#define minus(x) (x)
#define add DEFINE_OPERATION(add)
#define subtract(x,y) add(x,y)
#define inverse DEFINE_OPERATION(inverse)
#define ZERO DEFINE_OPERATION(ZERO)
#define ONE DEFINE_OPERATION(ONE)
#define scalarMultiply DEFINE_OPERATION(scalarMultiply)
#define addInPlace DEFINE_OPERATION(addInPlace)

#endif
