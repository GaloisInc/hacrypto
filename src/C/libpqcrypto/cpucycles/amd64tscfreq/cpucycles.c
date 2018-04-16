#include <stdio.h>
#include <sys/types.h>
#include "cpucycles.h"

long long cpucycles(void)
{
  unsigned long long result;
  asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");
  return result;
}

long long cpucycles_persecond(void)
{
  long result = 0;
  size_t resultlen = sizeof(long);
  sysctlbyname("machdep.tsc_freq",&result,&resultlen,0,0);
  return result;
}
