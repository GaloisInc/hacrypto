#ifndef TRANSPOSE_H
#define TRANSPOSE_H

#include "vec128.h"

void transpose_64x128_sp(vec128 *);
void transpose_64x64(uint64_t *, uint64_t *);

#endif

