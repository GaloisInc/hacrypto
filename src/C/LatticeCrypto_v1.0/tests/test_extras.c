/****************************************************************************************
* LatticeCrypto: an efficient post-quantum Ring-Learning With Errors cryptography library
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: additional functions for testing
*
*****************************************************************************************/


#include "../LatticeCrypto_priv.h"
#include "test_extras.h"
#if (OS_TARGET == OS_WIN)
    #include <windows.h>
    #include <intrin.h>
#endif
#if (OS_TARGET == OS_LINUX) && (TARGET == TARGET_ARM)
    #include <time.h>
#endif
#include <stdlib.h> 


int64_t cpucycles(void)
{ // Access system counter for benchmarking
#if (OS_TARGET == OS_WIN) && (TARGET == TARGET_AMD64 || TARGET == TARGET_x86)
    return __rdtsc();
#elif (OS_TARGET == OS_WIN) && (TARGET == TARGET_ARM)
    return __rdpmccntr64();
#elif (OS_TARGET == OS_LINUX) && (TARGET == TARGET_AMD64 || TARGET == TARGET_x86)
    unsigned int hi, lo;

    asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
    return ((int64_t)lo) | (((int64_t)hi) << 32);
#elif (OS_TARGET == OS_LINUX) && (TARGET == TARGET_ARM)
    struct timespec time;

    clock_gettime(CLOCK_REALTIME, &time);
    return (int64_t)(time.tv_sec*1e9 + time.tv_nsec);
#else
    return 0;            
#endif
}


CRYPTO_STATUS random_bytes_test(unsigned int nbytes, unsigned char* random_array)
{ // Generate "nbytes" of random values and output the result to random_array.
  // SECURITY NOTE: TO BE USED FOR TESTING ONLY.
    unsigned int i;

    for (i = 0; i < nbytes; i++) {
        *(random_array + i) = (unsigned char)rand();    // nbytes of random values
    }

    return CRYPTO_SUCCESS;
}


CRYPTO_STATUS extendable_output_test(const unsigned char* seed, unsigned int seed_nbytes, unsigned int array_ndigits, uint32_t* extended_array)
{ // Generate "array_ndigits" of 32-bit values and output the result to extended_array.
  // SECURITY NOTE: TO BE USED FOR TESTING ONLY.
    unsigned int count = 0;
    uint32_t digit;

    UNREFERENCED_PARAMETER(seed);
    UNREFERENCED_PARAMETER(seed_nbytes);
    UNREFERENCED_PARAMETER(array_ndigits);

    srand((unsigned int)seed[0]);

    while (count < array_ndigits) {
        random_bytes_test(2, (unsigned char*)&digit);   // Pull 2 bytes to get a 14-bit value
        digit &= 0x3FFF;
        if (digit < PARAMETER_Q) {                      // Take it if it is in [0, q-1]
            extended_array[count] = digit;
            count++;
        }
    }

    return CRYPTO_SUCCESS;
}


CRYPTO_STATUS stream_output_test(const unsigned char* seed, unsigned int seed_nbytes, unsigned char* nonce, unsigned int nonce_nbytes, unsigned int array_nbytes, unsigned char* stream_array)
{ // Generate "array_nbytes" of values and output the result to stream_array.
  // SECURITY NOTE: TO BE USED FOR TESTING ONLY.
    
    UNREFERENCED_PARAMETER(seed);
    UNREFERENCED_PARAMETER(seed_nbytes);
    UNREFERENCED_PARAMETER(nonce);
    UNREFERENCED_PARAMETER(nonce_nbytes);

    random_bytes_test(array_nbytes, stream_array); 

    return CRYPTO_SUCCESS;
}


void random_poly_test(int32_t* a, unsigned int p, unsigned int pbits, unsigned int N)
{ // Generating a pseudo-random polynomial a[x] over GF(p) 
  // SECURITY NOTE: TO BE USED FOR TESTING ONLY.
    unsigned int i, mask = ((unsigned int)1 << pbits) - 1;
    unsigned char* string = (unsigned char*)a;

    for (i = 0; i < N; i++) {
        do {
            *(string + 4*i)     = (unsigned char)rand();      // Obtain GF(p) coefficient
            *(string + 4*i + 1) = (unsigned char)rand();
            a[i] &= mask;
        } while (a[i] >= (int32_t)p);
    }
}


int compare_poly(int32_t* a, int32_t* b, unsigned int N)
{ // Comparing two polynomials over GF(p), a[x]=b[x]? : (0) a=b, (1) a!=b
  // SECURITY NOTE: TO BE USED FOR TESTING ONLY.
    unsigned int i;

    for (i = 0; i < N; i++)
    {
        if (a[i] != b[i]) 
            return 1;
    }

    return 0; 
}


int reduce(int a, int p)
{ // Modular reduction
  // SECURITY NOTE: TO BE USED FOR TESTING ONLY.
    a %= p;
    if (a < 0) a += p;

    return a;
}


void mul_test(int32_t* a, int32_t* b, int32_t* c, uint32_t p, unsigned int N)                  
{ // Polynomial multiplication using the schoolbook method, c[x] = a[x]*b[x] 
  // SECURITY NOTE: TO BE USED FOR TESTING ONLY.  
    unsigned int i, j, index, mask = N - 1;

     for (i = 0; i < N; i++) c[i] = 0;

     for (i = 0; i < N; i++) {
          for (j = 0; j < N; j++) {
              index = (i+j) & mask;
              if (i+j >= N) {
                  c[index] = reduce(c[index] - (a[i]*b[j]), p);                
              } else {
                  c[index] = reduce(c[index] + (a[i]*b[j]), p); 
              }
          }
     }
}


void add_test(int32_t* a, int32_t* b, int32_t* c, uint32_t p, unsigned int N)                  
{ // Polynomial addition, c[x] = a[x] + b[x] 
  // SECURITY NOTE: TO BE USED FOR TESTING ONLY.    
    unsigned int i;

     for (i = 0; i < N; i++) {
          c[i] = reduce(a[i] + b[i], p); 
     }
}