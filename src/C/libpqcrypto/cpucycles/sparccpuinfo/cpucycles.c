#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "osfreq.c"
#include "cpucycles.h"

long long cpucycles(void)
{
  long long result;
  asm volatile("rd %%tick,%0" : "=r" (result));
  return result;
}

long long cpucycles_persecond(void)
{
  return osfreq();
}
