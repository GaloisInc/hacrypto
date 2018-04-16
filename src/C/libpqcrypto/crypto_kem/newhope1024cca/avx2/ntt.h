#ifndef NTT_H
#define NTT_H

#include "inttypes.h"

extern const uint32_t psis_bitrev[];
extern const uint32_t psis_inv[];

extern const double omegas_double[];
extern const double omegas_inv_double[];


void bitrev_vector(uint32_t* poly);
void mul_coefficients(uint32_t* poly, const uint32_t* poly1, const uint32_t* factors);
void ntt(uint32_t* poly, const double* omegas);

#endif
