/* 
	Finite field of order 2^64 implemented as a degree-4 field extension of F_2^16 with minimal polynomial X^4 + X^2 + 2X + 1 
*/

#ifndef F64FIELD_H
#define F64FIELD_H

#include <stdint.h>
#include "F16Field.h"
#include "parameters.h"

typedef struct {
	f16FELT coef[4];
} f64FELT;

static const f64FELT f64ONE = { { 1,0,0,0 } };
static const f64FELT f64ZERO = { { 0,0,0,0 } };

void f64printFELT(f64FELT a);

f64FELT f64add(f64FELT a, f64FELT b);
f64FELT f64multiply(f64FELT a, f64FELT b);
void f64scalarMultiply(f64FELT* a, f16FELT b);
f64FELT f64inverse(f64FELT a);
int f64isEqual(f64FELT a, f64FELT b);

void f64serialize_FELT(writer *W, f64FELT a);
f64FELT f64deserialize_FELT(reader *R);

#endif

