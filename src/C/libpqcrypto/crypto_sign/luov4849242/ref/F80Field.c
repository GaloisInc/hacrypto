#include <stdio.h>
#include <stdlib.h>

#include "F80Field.h"

/*
	Makes a new field element, given its coeficients
*/
f80FELT newF80FELT(f16FELT c0, f16FELT c1, f16FELT c2, f16FELT c3 , f16FELT c4) {
	f80FELT new;
	new.coef[0] = c0;
	new.coef[1] = c1;
	new.coef[2] = c2;
	new.coef[3] = c3;
	new.coef[4] = c4;
	return new;
}

/*
	Irreducible polynomial over F_16
*/
static f16FELT f80IrredPoly[6] = { 1,0,1,0,0,1 };

/*
	prints a field element, mainly used for debugging
*/
void f80printFELT(f80FELT a) {
	/*printf("%.5uX^4 + %.5uX^3 + %.5uX^2 + %.5uX + %.5u ", a.coef[4], a.coef[3], a.coef[2], a.coef[1], a.coef[0]); */
	if (f80isEqual(f80ZERO, a)) {
		printf(".");
	}
	else {
		printf("x");
	}
}

/*
	Adds two field elements

	a,b : field element to add

	return : the sum of a and b
*/
f80FELT f80add(f80FELT a, f80FELT b) {
	return newF80FELT(a.coef[0] ^ b.coef[0], a.coef[1] ^ b.coef[1], a.coef[2] ^ b.coef[2], a.coef[3] ^ b.coef[3], a.coef[4] ^ b.coef[4]);
}

/*
	Multiplies two field elements

	a,b : field element to multiply

	return : the product of a and b
*/
f80FELT f80multiply(f80FELT a, f80FELT b) {
	int i, j;
	/* should be possible with much less table lookups */

	f16FELT temp[9];
	for (i = 0; i < 9; i++) {
		temp[i] = 0;
		for (j = ((0 > i-4)? 0: i - 4) ; j <= ((4<i)?4:i) ; j++) {
			temp[i] ^= f16multiply(a.coef[j], b.coef[i - j]);
		}
	}

	return newF80FELT(temp[0] ^ temp[5] ^ temp[8], temp[1] ^ temp[6], temp[2] ^ temp[5] ^ temp[7] ^ temp[8], temp[3] ^ temp[6] ^ temp[8], temp[4] ^ temp[7]);
}

/*
	Scalar multiplication

	a : an element in the field extension, which is muliplied by 2^b
	b : an integer
*/
void f80Scalarmultiply(f80FELT* a, f16FELT b) {
	if (a->coef[0] != 0) {
		a->coef[0] = f16antilog((f16log(a->coef[0]) + b) % f16units);
	}
	if (a->coef[1] != 0) {
		a->coef[1] = f16antilog((f16log(a->coef[1]) + b) % f16units);
	}
	if (a->coef[2] != 0) {
		a->coef[2] = f16antilog((f16log(a->coef[2]) + b) % f16units);
	}
	if (a->coef[3] != 0) {
		a->coef[3] = f16antilog((f16log(a->coef[3]) + b) % f16units);
	}
	if (a->coef[4] != 0) {
		a->coef[4] = f16antilog((f16log(a->coef[4]) + b) % f16units);
	}
}

/*
	Inverts a field element

	a : field element to invert

	return : the inverse of a, if a is nonzero
*/
f80FELT f80inverse(f80FELT a) {
	f16FELT aPoly[6];
	f16FELT gcd[6], x[6], y[6];
	f16FELT gcdinv;

	aPoly[0] = a.coef[0];
	aPoly[1] = a.coef[1];
	aPoly[2] = a.coef[2];
	aPoly[3] = a.coef[3];
	aPoly[4] = a.coef[4];
	aPoly[5] = 0;

	f16ExtendedEuclideanAlgorithm(aPoly, f80IrredPoly, x, y, gcd);
	gcdinv = f16inverse(gcd[0]);

	return  newF80FELT(f16multiply(gcdinv, x[0]), f16multiply(gcdinv, x[1]), f16multiply(gcdinv, x[2]), f16multiply(gcdinv, x[3]), f16multiply(gcdinv, x[4]));
}

/*
	Checks if two field elements are equal
*/
int f80isEqual(f80FELT a, f80FELT b) {
	return (a.coef[0] == b.coef[0]) && (a.coef[1] == b.coef[1]) && (a.coef[2] == b.coef[2]) && (a.coef[3] == b.coef[3]) && (a.coef[4] == b.coef[4]);
}

/*
	Write a field element to a char array

	W : writer object
	a : field element to write
*/
void f80serialize_FELT(writer *W, f80FELT a) {
	f16serialize_FELT(W, a.coef[4]);
	f16serialize_FELT(W, a.coef[3]);
	f16serialize_FELT(W, a.coef[2]);
	f16serialize_FELT(W, a.coef[1]);
	f16serialize_FELT(W, a.coef[0]);
}

/*
	Read a field element from a char array

	R : reader object

	returns : a field element
*/
f80FELT f80deserialize_FELT(reader *R) {
	f80FELT new;
	new.coef[4] = f16deserialize_FELT(R);
	new.coef[3] = f16deserialize_FELT(R);
	new.coef[2] = f16deserialize_FELT(R);
	new.coef[1] = f16deserialize_FELT(R);
	new.coef[0] = f16deserialize_FELT(R);
	return new;
}