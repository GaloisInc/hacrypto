/*
	Finite field of order 2^32 implemented as quadratic field extension of F_2^16 with minimal polynomial X^2 + X + 8192
*/

#ifndef F32FIELD_H
#define F32FIELD_H

#include <stdint.h>
#include "F16Field.h"
#include "parameters.h"

typedef struct {
	f16FELT c0, c1;
} f32FELT;

static const f32FELT f32ONE = { 1 , 0 };
static const f32FELT f32ZERO = { 0 , 0 };

void f32printFELT(f32FELT a);
f32FELT f32add(f32FELT a, f32FELT b);
void f32addInPlace(f32FELT *a, f32FELT *b);
f32FELT f32multiply(f32FELT a, f32FELT b);
void f32scalarMultiply(f32FELT* a, f16FELT b);
f32FELT f32inverse(f32FELT a);
int f32isEqual(f32FELT a, f32FELT b);

void f32serialize_FELT(writer *W, f32FELT a);
f32FELT f32deserialize_FELT(reader *R);

#endif
