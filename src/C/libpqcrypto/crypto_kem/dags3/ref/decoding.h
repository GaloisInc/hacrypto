#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <math.h>
#include "matrix.h"
#include "poly.h"
#include "fichier.h"
#include "param.h"

/**
 * @brief  function compute the syndrome S in polynomial form with inputs a short IV and a Parity matrix H
 * @param H - parity check matrix
 * @param mot - short IV
 * @param S the polynomial syndrome.
 */
void polynome_syndrome_1(binmat_t H, const unsigned char *mot, poly_t S);
/**
 * @brief function transform a Generalized Srivastava matrix in  alternant form
 * @param H generalized Srivastava matrix
 * @param u
 *
 * @return the alternant matrix if it is possible to compute
 */
binmat_t alternant_matrix(binmat_t H, gf *u);

/**
 * @brief function to decode H in the alternant form
 * @param H  alternant form matrix
 * @param c code word
 * @param e
 * @param mot short IV
 *
 * @return -1 if it is not possible to compute and 1 if it is possible to compute
 */
int decoding_H(binmat_t H_alt, const unsigned char *c, unsigned char *e, unsigned char *mot);
