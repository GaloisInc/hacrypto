#ifndef FFT_H
#define FFT_H

#include <stdint.h>
#include "params.h"
#include "vec128.h"

void fft(vec128 [][GFBITS], vec128 *);

#endif

