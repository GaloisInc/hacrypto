#include <stdio.h>
#include <unistd.h>
#include "cpucycles.h"
#include "randombytes.h"

#define TESTS 100
#define TIMINGS 21
unsigned long long t[TIMINGS + 1];
unsigned char x[16384];
unsigned long long freq[256];

int main()
{
  int i;
  int j;
  int abovej;
  int belowj;

  alarm(300);

  for (j = 0;j < TESTS;++j) {
    randombytes(x,sizeof x);
    for (i = 0;i < 256;++i) freq[i] = 0;
    for (i = 0;i < sizeof x;++i) ++freq[255 & (int) x[i]];
    for (i = 0;i < 256;++i) if (!freq[i]) return 111;
  }

  for (i = 0;i <= TIMINGS;++i) {
    randombytes(x,sizeof x);
    t[i] = cpucycles();
  }

  for (i = 0;i < TIMINGS;++i) t[i] = t[i + 1] - t[i];

  for (j = 0;j + 1 < TIMINGS;++j) { 
    belowj = 0;
    for (i = 0;i < TIMINGS;++i) if (t[i] < t[j]) ++belowj;
    abovej = 0;
    for (i = 0;i < TIMINGS;++i) if (t[i] > t[j]) ++abovej;
    if (belowj * 2 < TIMINGS && abovej * 2 < TIMINGS) break;
  } 

  printf("%llu\n",t[j]);
  return 0;
}
