#ifndef small_h
#define small_h

#include "crypto_int8.h"

typedef crypto_int8 small;

extern void small_encode(unsigned char *,const small *);

extern void small_decode(small *,const unsigned char *);

extern void small_random(small *);

extern void small_random_weightw(small *);

#endif
