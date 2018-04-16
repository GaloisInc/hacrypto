#ifndef UTIL_H
#define UTIL_H

#include "vec128.h"

#include <stdint.h>

void store2(unsigned char *, uint16_t);
uint16_t load2(const unsigned char *);

void irr_load(vec128 *, const unsigned char *);

void store8(unsigned char *, uint64_t);
uint64_t load8(const unsigned char *);

void store16(unsigned char *, vec128);
vec128 load16(const unsigned char *);

#endif

