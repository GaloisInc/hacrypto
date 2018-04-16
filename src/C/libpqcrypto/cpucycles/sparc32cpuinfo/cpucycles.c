#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "osfreq.c"
#include "cpucycles.h"

long long cpucycles(void)
{
  long long result;
  asm volatile(".word 2202075136; .word 2570088480; srl %%g1,0,%L0; mov %%o4,%H0"
    : "=r" (result) : : "g1","o4");
  return result;
}

long long cpucycles_persecond(void)
{
  return osfreq();
}
