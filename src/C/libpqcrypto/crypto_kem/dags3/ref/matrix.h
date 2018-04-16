#ifndef _MATRIX_H
#define _MATRIX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "randombytes.h"
#include "gf.h"
#include "param.h"

typedef struct matrix
{
	unsigned int rown;
	unsigned int coln;
	gf **coeff;
} binmat_t;

#define mat_coeff(A, i, j) ((coeffe[i][j]))

binmat_t matrix_init(int rown, int coln);
binmat_t matrix_copy(binmat_t A);
binmat_t mat_Into_base(binmat_t H);
binmat_t matrix_init_identity(int rown);
binmat_t matrix_pivot_inversion(binmat_t A);
binmat_t matrix_transpose(binmat_t A);
binmat_t matrix_multiplication(binmat_t A, binmat_t B);
binmat_t matrix_multiplicaion_subfield(binmat_t A, binmat_t B);
binmat_t matrix_permutation(int *P);
int matrix_inverse(binmat_t A, binmat_t S);


int *test_mat(binmat_t A);
void mat_free(binmat_t A);
void mat_rowxor(binmat_t A, int i, int j);
void mat_swaprow(binmat_t A, int i, int j);
void mat_swapcol(binmat_t A, int i, int j);
void mat_random_swapcol(binmat_t A);
void mat_line_mult_by_gf(binmat_t A, gf a, int i);
void mat_rowxor_with_another(binmat_t A, int i, gf *Line);
void G_mat(binmat_t G, binmat_t H_syst);
void aff_mat(binmat_t mat);
void affiche_vecteur(gf *P, int taille);
void vector_permutation(int *P, gf *v, int taille);
void secret_matrix(binmat_t H, gf *u, gf *v, gf *z);
void quasi_dyadic_bloc_mat(int s, binmat_t M, gf *sig, int ind_col, int ind_rown);



int syst(binmat_t H);
int syst_mat(binmat_t H);


//int syst(binmat_t H, binmat_t P);


gf *mult_matrix_vector_subfield(binmat_t A, gf *v);
gf *mult_vector_matrix_subfield(gf *v, binmat_t A);
gf *mult_matrix_vector(binmat_t A, gf *v);
gf *mult_vector_matrix(gf *v, binmat_t A);
gf *mult_vector_matrix_Sf(gf *v, binmat_t A);
gf *mult_matrix_vector(binmat_t A, gf *v);
gf eltseq(gf a, int k);



#endif
