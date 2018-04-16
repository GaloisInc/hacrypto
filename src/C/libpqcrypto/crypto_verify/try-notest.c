/*
 * crypto_verify/try-notest.c version 20180223
 * D. J. Bernstein
 * Public domain.
 */

#include "crypto_verify.h"
#include "kernelrandombytes.h"
#include "try.h"

#ifdef SMALL
#define LOOPS 10000
#else
#define LOOPS 1000000
#endif

const char *primitiveimplementation = crypto_verify_implementation;

static unsigned char *x;
static unsigned char *y;

void preallocate(void)
{
}

void allocate(void)
{
  x = alignedcalloc(crypto_verify_BYTES);
  y = alignedcalloc(crypto_verify_BYTES);
}

void predoit(void)
{
}

void doit(void)
{
  crypto_verify(x,y);
}
