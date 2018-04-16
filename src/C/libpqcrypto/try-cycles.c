#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include "kernelrandombytes.h"
#include "cpucycles.h"
#include "try.h"

void fail(const char *why)
{
  fprintf(stderr,"%s\n",why);
  exit(111);
}

unsigned char *alignedcalloc(unsigned long long len)
{
  unsigned char *x = (unsigned char *) calloc(1,len + 256);
  long long i;
  if (!x) fail("out of memory");
  /* will never deallocate so shifting is ok */
  for (i = 0;i < len + 256;++i) x[i] = random();
  x += 64;
  x += 63 & (-(unsigned long) x);
  for (i = 0;i < len;++i) x[i] = 0;
  return x;
}

#define TIMINGS 63
static long long cycles[TIMINGS + 1];

void limits()
{
#ifdef RLIM_INFINITY
  struct rlimit r;
  r.rlim_cur = 0;
  r.rlim_max = 0;
#ifdef RLIMIT_NOFILE
  setrlimit(RLIMIT_NOFILE,&r);
#endif
#ifdef RLIMIT_NPROC
  setrlimit(RLIMIT_NPROC,&r);
#endif
#ifdef RLIMIT_CORE
  setrlimit(RLIMIT_CORE,&r);
#endif
#endif
}

static unsigned char randombyte[1];

int main()
{
  long long i;
  long long j;
  long long abovej;
  long long belowj;
  long long timings;

  alarm(3600);

  kernelrandombytes(randombyte,1);
  preallocate();
  limits();

  allocate();
  srandom(getpid());

  predoit();

  timings = 3;
  for (;;) {

    for (i = 0;i <= timings;++i) {
      cycles[i] = cpucycles();
    }
    for (i = 0;i < timings;++i) {
      cycles[i] = cpucycles();
      doit();
    }
    cycles[timings] = cpucycles();

    for (i = 0;i < timings;++i) cycles[i] = cycles[i + 1] - cycles[i];

    for (j = 0;j < timings;++j) {
      belowj = 0;
      for (i = 0;i < timings;++i) if (cycles[i] < cycles[j]) ++belowj;
      abovej = 0;
      for (i = 0;i < timings;++i) if (cycles[i] > cycles[j]) ++abovej;
      if (belowj * 2 < timings && abovej * 2 < timings) break;
    }

    if (timings == 3) {
      if (cycles[j] < 100000) { timings = TIMINGS; continue; }
      if (cycles[j] < 1000000) { timings = 15; continue; }
    }

    printf("%lld\n",cycles[j]);
    return 0;

  }
}
