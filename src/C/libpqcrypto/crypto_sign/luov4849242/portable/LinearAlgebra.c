#include <stdio.h>
#include <stdlib.h>

#include "LinearAlgebra.h"
#include "buffer.h"

/*
	Creates a new matrix

	rows : the number of rows of the new matrix
	cols : the number of columns of the new matrix

	returns : The new matrix
*/
Matrix newMatrix(unsigned int rows, unsigned int cols) {
	unsigned int i;
	Matrix new;
	new.rows = rows;
	new.cols = cols;
	new.array = malloc(rows * sizeof(FELT*));
	for (i = 0; i < rows; i++) {
		new.array[i] = malloc(cols * sizeof(FELT));
	}
	return new;
}

/*
	Creates a new matrix whose entries are zero

	rows : the number of rows of the new matrix
	cols : the number of columns of the new matrix

	returns : The new matrix
*/
Matrix zeroMatrix(unsigned int rows, unsigned int cols) {
	unsigned int i, j;
	Matrix newMat = newMatrix(rows, cols);
	for (i = 0; i < rows; i++) {
		for (j = 0; j < cols; j++) {
			newMat.array[i][j] = ZERO;
		}
	}
	return newMat;
}

/*
	Free the memory of a matrix

	mat : the matrix to destroy
*/
void destroy_matrix(Matrix mat) {
	int i;
	for (i = 0; i < mat.rows; i++) {
		free(mat.array[i]);
	}
	free(mat.array);
}

/*
	Prints a matrix
*/
void printMatrix(Matrix Mat) {
	int i, j;
	for (i = 0; i < Mat.rows; i++) {
		for (j = 0; j < Mat.cols; j++) {
			printFELT(Mat.array[i][j]);
		}
		printf("\n");
	}
	printf("\n");
}

/*
	Swaps two rows of a matrix

	A : A matrix
	row1 , row2 : The rows of A that have to be swapped
*/
void swapRows(Matrix A, int row1, int row2) {
	FELT *temp = A.array[row1];
	A.array[row1] = A.array[row2];
	A.array[row2] = temp;
}

/*
	Multiplies all the entries of a row of a matrix by a scalar

	A : A matrix
	row : the index of the row that has to be rescaled
	a : A field element
*/
void scaleRow(Matrix A, int row, FELT a) {
	int i;
	for (i = 0; i < A.cols; i++) {
		A.array[row][i] = multiply(a,A.array[row][i]);
	}
}

/*
	Add a part of the scalar multiple of one row of a matrix to another row of that matrix

	A : A matrix
	destrow : The row to add to
	sourcerow  : The row that is multiplied by a scalar and added to destrow
	constant : The contant that sourcerow is multiplied with
	offset : Only the entries in columns with index larger than or equal to offset are affected
*/
void rowOp(Matrix A, int destrow, int sourcerow, FELT constant, int offset)
{
	int j;
	FELT T;
	if (isEqual(constant, ZERO))
		return;

	for (j = offset; j < A.cols; ++j)
	{
		T = multiply(constant,A.array[sourcerow][j]);
		addInPlace(&A.array[destrow][j],&T);
	}
}

/* 
	Puts the first part of an augmented matrix in row echelon form.
	
	A : A matrix

	returns : The rank ok the first part of the row echelon form of A
*/
int rowEchelonAugmented(Matrix A)
{
	int i,col;
	int row = 0;
	for (col = 0; col < A.cols - 1; ++col)
	{
		for (i = row; i < A.rows; ++i)
		{
			if (!isEqual(A.array[i][col], ZERO))
			{
				if (i != row)
				{
					swapRows(A, i, row);
				}
				break;
			}
		}

		if (i == A.rows)
		{
			continue;
		}

		scaleRow(A, row, inverse(A.array[row][col]));

		for (i++; i < A.rows; ++i)
		{
			rowOp(A, i, row, minus(A.array[i][col]), col);
		}

		row++;

		if (row == A.rows)
		{
			break;
		}
	}
	return row;
}

/* 
	Calculates the unique solution to a linear system described by an augmented matrix

	A : The augmented matrix of some linear system of equations
	solution : Receives the unique solution if it exists 

	returns : 1 if a unique solution exists, 0 otherwise 
*/
int getUniqueSolution(Matrix A, FELT *solution) {
	int i,j,col,row;
	FELT T;
	int rank = rowEchelonAugmented(A);

	if (rank != A.rows) {
		return 0;
	}

	/* clear memory for solution */
    for (i = 0 ; i< A.cols-1 ; i++){
    	solution[i] = ZERO;
    }

	for (row = A.rows - 1; row >= 0; row--) {
		col = row;
		while (isEqual(A.array[row][col], ZERO))
		{
			col++;
		}

		solution[col] = A.array[row][A.cols - 1];
		for (j = col + 1; j < A.cols - 1; j++) {
			T = multiply(solution[j], A.array[row][j]);
			solution[col] = subtract(solution[col],T);
		}
	}
	return 1;
}