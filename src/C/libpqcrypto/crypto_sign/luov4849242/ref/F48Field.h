/* 
	Finite field of order 2^48 implemented as a cubic field extension of F_2^16 with minimal polynomial X^3 + X + 1 
*/

#ifndef F48FIELD_H
#define F48FIELD_H

#include <stdint.h>
#include "F16Field.h"
#include "parameters.h"

typedef struct {
	f16FELT coef[3];
} f48FELT;


static const f48FELT f48ONE = { { 1,0,0 } };
static const f48FELT f48ZERO = { { 0,0,0 } };

void f48printFELT(f48FELT a);
f48FELT f48add(f48FELT a, f48FELT b);
f48FELT f48multiply(f48FELT a, f48FELT b);
void f48scalarMultiply(f48FELT* a, f16FELT b);
f48FELT f48inverse(f48FELT a);
int f48isEqual(f48FELT a, f48FELT b);

void f48serialize_FELT(writer *W, f48FELT a);
f48FELT f48deserialize_FELT(reader *R);

#endif
