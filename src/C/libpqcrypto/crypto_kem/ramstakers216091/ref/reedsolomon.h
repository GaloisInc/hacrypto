#ifndef REEDSOLOMON_H
#define REEDSOLOMON_H

#include "gf256x.h"

#define RS_N 255
#define RS_DELTA 224
#define RS_K 32
#define RS_T 111

extern unsigned char generator_data[RS_DELTA];
extern int generator_degree;

int rs_encode( unsigned char * dest, unsigned char * source );
int rs_decode( unsigned char * dest, unsigned char * source );
int rs_syndrome( unsigned char * syndrome, unsigned char * word );
int rs_decode_error_free( unsigned char * dest, unsigned char * source );

int rs_interrupted_euclidean( gf256x * a, gf256x * b, gf256x x, gf256x y );
int rs_formal_derivative( gf256x * Df, gf256x f );
int rs_errors( unsigned char * errors, gf256x sigma, gf256x sigma_deriv, gf256x omega );
int rs_decode_polynomial( gf256x * dest, gf256x codeword );
#endif

