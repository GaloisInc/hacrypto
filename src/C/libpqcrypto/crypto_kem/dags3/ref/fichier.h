#include "gf.h"
#include "matrix.h"
#include "poly.h"


void cfile_vec_F12(char *file, int n, gf *L);
void cfile_vec_F12_int(char *file, int n, int *L);
void cfile_vec_F6(char *file, int n, gf_t *L);
void cfile_matrix_F6(char *file, int dimension, int longueur, binmat_t M);
void cfile_vec_char(char *file, int n, unsigned char *L);

void cfile_matrix_F12(char *file, int dimension, int longueur, binmat_t M);
void Lecture_cfile_vec_F12(char *file, int n, gf *L);
void Lecture_cfile_vec_F12_int(char *file, int n, int *L);
void Lecture_cfile_vecF6(char *file, int n, gf_t *L);
void Lecture_cfile_matrix_F6(char *file, int dimension, int longueur, binmat_t M);
void Lecture_cfile_matrix_F12(char *file, int dimension, int longueur, binmat_t M);
void Lecture_cfile_vec_F6_int(char *file, int n, int *L);

void Lecture_cfile_vec_char(char *file, int n, unsigned char *L);
