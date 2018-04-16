#include <stdio.h>
#include <stdlib.h>

#include "F48Field.h"

/*
	Makes a new field element, given its coeficients
*/
f48FELT newF48FELT(f16FELT c0, f16FELT c1, f16FELT c2) {
	f48FELT new;
	new.coef[0] = c0;
	new.coef[1] = c1;
	new.coef[2] = c2;
	return new;
}

/*
	Write a field element to a char array

	W : writer object
	a : field element to write
*/
void f48serialize_FELT(writer *W, f48FELT a) {
	f16serialize_FELT(W, a.coef[2]);
	f16serialize_FELT(W, a.coef[1]);
	f16serialize_FELT(W, a.coef[0]);
}

/*
	Read a field element from a char array

	R : reader object

	returns : a field element
*/
f48FELT f48deserialize_FELT(reader *R) {
	f48FELT new;
	new.coef[2] = f16deserialize_FELT(R);
	new.coef[1] = f16deserialize_FELT(R);
	new.coef[0] = f16deserialize_FELT(R);
	return new;
}

/*
	Irreducible polynomial over F_16
*/
static f16FELT f48IrredPoly[6] = { 1,1,0,1,0,0 };

/*
	prints a field element, mainly used for debugging
*/
void f48printFELT(f48FELT a) {
	printf("%.5uX^2 + %.5uX + %.5u ", a.coef[2], a.coef[1], a.coef[0]);
}

/*
	Adds two field elements

	a,b : field element to add

	return : the sum of a and b
*/
f48FELT f48add(f48FELT a, f48FELT b) {
	return newF48FELT(a.coef[0] ^ b.coef[0], a.coef[1] ^ b.coef[1], a.coef[2] ^ b.coef[2]);
}

/*
	Multiplies two field elements

	a,b : field element to multiply

	return : the product of a and b
*/
f48FELT f48multiply(f48FELT a, f48FELT b) {
	f16FELT c0 = f16multiply(a.coef[0], b.coef[0]);
	f16FELT c1 = f16multiply(a.coef[1], b.coef[0]) ^ f16multiply(a.coef[0], b.coef[1]);
	f16FELT c2 = f16multiply(a.coef[2], b.coef[0]) ^ f16multiply(a.coef[1], b.coef[1]) ^ f16multiply(a.coef[0], b.coef[2]);
	f16FELT c3 = f16multiply(a.coef[2], b.coef[1]) ^ f16multiply(a.coef[1], b.coef[2]);
	f16FELT c4 = f16multiply(a.coef[2], b.coef[2]);

	return newF48FELT(c0 ^ c3, c1 ^ c3 ^ c4, c2 ^ c4);
}

/*
	Scalar multiplication

	a : an element in the field extension, which is muliplied by 2^b
	b : an integer
*/
void f48scalarMultiply(f48FELT* a, f16FELT b) {
	if (a->coef[0] != 0) {
		a->coef[0] = f16antilog((f16log(a->coef[0]) + b) % f16units);
	}
	if (a->coef[1] != 0) {
		a->coef[1] = f16antilog((f16log(a->coef[1]) + b) % f16units);
	}
	if (a->coef[2] != 0) {
		a->coef[2] = f16antilog((f16log(a->coef[2]) + b) % f16units);
	}
}

/*
	Inverts a field element

	a : field element to invert

	return : the inverse of a, if a is nonzero
*/
f48FELT f48inverse(f48FELT a) {
	f16FELT aPoly[6];
	f16FELT gcd[6], x[6], y[6];
	f16FELT gcdinv;
	aPoly[0] = a.coef[0];
	aPoly[1] = a.coef[1];
	aPoly[2] = a.coef[2];
	aPoly[3] = 0;
	aPoly[4] = 0;
	aPoly[5] = 0;

	f16ExtendedEuclideanAlgorithm(aPoly, f48IrredPoly, x, y, gcd);
	gcdinv = f16inverse(gcd[0]);
	return newF48FELT(f16multiply(gcdinv, x[0]), f16multiply(gcdinv, x[1]), f16multiply(gcdinv, x[2]));
}

/*
	Checks if two field elements are equal
*/
int f48isEqual(f48FELT a, f48FELT b) {
	return (a.coef[0] == b.coef[0]) && (a.coef[1] == b.coef[1]) && (a.coef[2] == b.coef[2]);
}