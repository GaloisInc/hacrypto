#ifndef LINEARALGEBRA_H
#define LINEARALGEBRA_H

#include "F8Field.h"
#include "F16Field.h"
#include "F32Field.h"
#include "F48Field.h"
#include "F64Field.h"
#include "F80Field.h"

#define PRINTMATRIX(M) printf(#M " = \n"); printMatrix(M);

/*Matrix over F_Q*/
typedef struct {
	int rows;
	int cols;
	FELT** array;
} Matrix;

Matrix zeroMatrix(unsigned int rows, unsigned int cols);
void destroy_matrix(Matrix mat);
void printMatrix(Matrix Mat);
int getUniqueSolution(Matrix A, FELT *solution);

#endif
