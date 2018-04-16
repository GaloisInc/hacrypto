#ifndef FE_H
#define FE_H

#include "crypto_int32.h"

typedef crypto_int32 fe[10];

/*
fe means field element.
Here the field is \Z/(2^255-19).
An element t, entries t[0]...t[9], represents the integer
t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
Bounds on each t[i] vary depending on context.
*/

extern void fe_frombytes(fe,const unsigned char *);
extern void fe_tobytes(unsigned char *,fe);

extern void fe_copy(fe,fe);
extern void fe_0(fe);
extern void fe_1(fe);
extern void fe_cswap(fe,fe,unsigned int);

extern void fe_add(fe,fe,fe);
extern void fe_sub(fe,fe,fe);
extern void fe_mul(fe,fe,fe);
extern void fe_sq(fe,fe);
extern void fe_mul121666(fe,fe);
extern void fe_invert(fe,fe);

#endif
