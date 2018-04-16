#ifndef ORACLE_H
#define ORACLE_H

#include "params.h"
#include "poly.h"

void random_oracle(unsigned char *c_bin, int64_t *v, const unsigned char *m, unsigned long long mlen);

#endif
