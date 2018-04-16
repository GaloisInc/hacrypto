#ifndef GF_H
#define GF_H

#include <stdint.h>

typedef uint16_t gf;

gf gf_mul(gf, gf);
uint64_t gf_mul2(gf, gf, gf);
void gf_dump(gf);
gf gf_frac(gf, gf);
gf gf_inv(gf);
gf gf_iszero(gf);

void GF_mul(gf *, gf *, gf *);
void GF_dump(gf *);

#endif

