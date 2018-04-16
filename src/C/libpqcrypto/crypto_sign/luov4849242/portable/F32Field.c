#include <stdio.h>
#include <stdlib.h>

#include "F32Field.h"

/*
	Makes a new field element, given its coeficients
*/
f32FELT newF32FELT(f16FELT c0, f16FELT c1) {
	f32FELT new;
	new.c0 = c0;
	new.c1 = c1;
	return new;
}

/*
	Write a field element to a char array

	W : writer object
	a : field element to write
*/
void f32serialize_FELT(writer *W, f32FELT a) {
	f16serialize_FELT(W, a.c1);
	f16serialize_FELT(W, a.c0);
}

/*
	Read a field element from a char array

	R : reader object

	returns : a field element
*/
f32FELT f32deserialize_FELT(reader *R) {
	f32FELT new;
	new.c1 = f16deserialize_FELT(R);
	new.c0 = f16deserialize_FELT(R);
	return new;
}

/*
	prints a field element, mainly used for debugging
*/
void f32printFELT(f32FELT a) {
	printf("%.5uX + %.5u ", a.c1, a.c0);
}

/*
	Adds two field elements

	a,b : field element to add

	return : the sum of a and b
*/
f32FELT f32add(f32FELT a, f32FELT b) {
	return newF32FELT(f16add(a.c0, b.c0), f16add(a.c1, b.c1));
}

/*
	Adds a field element to a field element

	a : pointer to field element
	b : pointer to field element to add to a
*/
void f32addInPlace(f32FELT *a, f32FELT *b) {
	a->c0 ^= b->c0;
	a->c1 ^= b->c1;
}

/*
	Multiplies two field elements

	a,b : field element to multiply

	return : the product of a and b
*/
f32FELT f32multiplyOld(f32FELT a, f32FELT b) {
	f16FELT c0 = f16multiply(a.c0, b.c0);
	f16FELT c1 = f16multiply(a.c1, b.c0) ^ f16multiply(a.c0, b.c1);
	f16FELT c2 = f16multiply(a.c1, b.c1);

	return newF32FELT(c0 ^ f16multiply(c2, 8192), c1 ^ c2);
}

/*
	Scalar multiplication

	a : an element in the field extension, which is muliplied by 2^b
	b : an integer
*/
void f32scalarMultiply(f32FELT* a, f16FELT b) {
	if (a->c0 != 0) {
		a->c0 = f16antilog((f16log(a->c0) + b) % f16units);
	}
	if (a->c1 != 0) {
		a->c1 = f16antilog((f16log(a->c1) + b) % f16units);
	}
}

/*
	Multiplies two field elements, optimized in 
	the case the coefficients of a and b are nonzero

	a,b : field element to multiply

	return : the product of a and b
*/
f32FELT f32multiply(f32FELT a, f32FELT b) {
	if (a.c0 == 0 || a.c1 == 0 || b.c0 == 0 || b.c1 == 0) {
		return f32multiplyOld(a, b);
	}
	uint16_t A, B, C, E;
	A = f16log(a.c0);
	B = f16log(a.c1);
	C = f16log(b.c0);
	E = f16log(b.c1);

	return newF32FELT(f16antilog((A+C)%f16units) ^ f16antilog((B+E+13)%f16units) , f16antilog((B+C)%f16units) ^ f16antilog((A+E)%f16units) ^ f16antilog((B + E) % f16units) );
}

/*
	Inverts a field element

	a : field element to invert

	return : the inverse of a, if a is nonzero
*/
f32FELT f32inverse(f32FELT a) {
	f16FELT a1inv,temp2;
	f32FELT temp;

	if (a.c1 == 0)
		return newF32FELT(f16inverse(a.c0), 0);

	a1inv = f16inverse(a.c1);
	temp = newF32FELT(f16multiply(a1inv, f16add(1, f16multiply(a1inv, a.c0))), a1inv);
	temp2 = f16inverse(f32multiply(a, temp).c0);

	return newF32FELT(f16multiply(temp.c0, temp2), f16multiply(temp.c1, temp2));
}

/*
	Checks if two field elements are equal
*/
int f32isEqual(f32FELT a, f32FELT b) {
	return (a.c0 == b.c0) && (a.c1 == b.c1);
}