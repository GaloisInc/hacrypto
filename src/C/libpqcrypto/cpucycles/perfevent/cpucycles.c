#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include "osfreq.c"
#include "cpucycles.h"

static int fddev = -1;

long long cpucycles(void)
{
  long long result;

  if (fddev == -1) {
    static struct perf_event_attr attr;
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    fddev = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
  }

  if (read(fddev,&result,sizeof result) < sizeof result) return 0;
  return result;
}

long long cpucycles_persecond(void)
{
  return osfreq();
}
