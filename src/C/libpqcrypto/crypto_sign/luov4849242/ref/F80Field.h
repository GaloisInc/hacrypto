/* 
	Finite field of order 2^80 implemented as a degree-5 field extension of F_2^16 with minimal polynomial X^5 + X^2 + 1 
*/

#ifndef F80FIELD_H
#define F80FIELD_H

#include <stdint.h>
#include "F16Field.h"
#include "parameters.h"

typedef struct {
	f16FELT coef[5];
} f80FELT;

static const f80FELT f80ONE = { { 1,0,0,0,0 } };
static const f80FELT f80ZERO = { { 0,0,0,0,0 } };

void f80printFELT(f80FELT a);

f80FELT f80add(f80FELT a, f80FELT b);
f80FELT f80multiply(f80FELT a, f80FELT b);
void f80scalarMultiply(f80FELT* a, f16FELT b);
f80FELT f80inverse(f80FELT a);
int f80isEqual(f80FELT a, f80FELT b);

void f80serialize_FELT(writer *W, f80FELT a);
f80FELT f80deserialize_FELT(reader *R);

#endif
