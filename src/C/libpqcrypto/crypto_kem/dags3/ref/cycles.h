/*
 * cycles.h
 *
 *  Created on: Nov 8, 2017
 *      Author: vader
 */

#ifndef SRC_CYCLES_H_
#define SRC_CYCLES_H_

#include <stdint.h>
uint64_t rdtsc()
{
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

#endif /* SRC_CYCLES_H_ */
