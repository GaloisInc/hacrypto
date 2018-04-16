
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "decoding.h"
#include "decoding.h"
#include "matrix.h"
#include "fichier.h"
#include "poly.h"
#include "param.h"
#include "util.h"
#include "randombytes.h"

/**
 * @file key_gen.h
 * @brief File that contains the key pair generation.
 *
 *The file contains the key generation elements, i.e,
 *The quasi-dyadic-signature and cauchy support  generation.
 */

/**
 * @brief check if the vectors are disjoint
 * @param u - input vector.
 * @param v - the other vector to check.
 *
 * @return @result if it is disjoint it will be 0 if not wil return -1.
 */
int disjoint_test(gf *u, gf *v);

/**
 * @brief Method to generate a random vector.
 * @param m size of random bits.
 * @param vect pointer that will be written the bits.
 */
void generate_random_vector(int m, gf *vect);

/**
 * @brief Method to initialize a vector.
 * @param U vector that will be initialize.
 *
 */
void init_random_element(gf *U);

/**
 * @brief Binary quasi dyadic signature
 * @param m size of code word.
 * @param n value to check when stop at the first non-zero element of V.
 * @param t
 * @param b auxiliar.
 * @param h_sig element that will receive the signature.
 * @param w element to be signed.
 *
 */
void binary_quasi_dyadic_sig(int m, int n, int t, int *b, gf *h_sig, gf *w);

/**
 * @brief Binary Cauchy support
 * @param support element to be the support
 * @param u input vector to be used
 * @param w input vector to be used
 *
 */
void cauchy_support(gf *support, gf *u, gf *w);

/**
 * @brief Key pair generation
 * @param pk string that will be stored the public key
 * @param sk string that will be sotred the secret key
 *
 * @return It will back 0 if it was possible to generate both keys
 * and it will return != 0 if it wasn't possible to generate keys.
 *
 */
int key_pair(unsigned char *pk, unsigned char *sk);
