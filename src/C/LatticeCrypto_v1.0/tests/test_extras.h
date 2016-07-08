/****************************************************************************************
* LatticeCrypto: an efficient post-quantum Ring-Learning With Errors cryptography library
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: utility header file for tests
*
*****************************************************************************************/  

#ifndef __TEST_EXTRAS_H__
#define __TEST_EXTRAS_H__


// For C++
#ifdef __cplusplus
extern "C" {
#endif


#include "../LatticeCrypto_priv.h"

    
// Access system counter for benchmarking
int64_t cpucycles(void);

// Generate "nbytes" of random values and output the result to random_array.
// SECURITY NOTE: TO BE USED FOR TESTING ONLY.
CRYPTO_STATUS random_bytes_test(unsigned int nbytes, unsigned char* random_array); 

// Generate "array_ndigits" of 32-bit values and output the result to extended_array.
// SECURITY NOTE: TO BE USED FOR TESTING ONLY.
CRYPTO_STATUS extendable_output_test(const unsigned char* seed, unsigned int seed_nbytes, unsigned int array_ndigits, uint32_t* extended_array);
    
// Generate "array_nbytes" of values and output the result to stream_array.
// SECURITY NOTE: TO BE USED FOR TESTING ONLY.
CRYPTO_STATUS stream_output_test(const unsigned char* seed, unsigned int seed_nbytes, unsigned char* nonce, unsigned int nonce_nbytes, unsigned int array_nbytes, unsigned char* stream_array);

// Generating a pseudo-random polynomial a[x] over GF(p) 
// SECURITY NOTE: TO BE USED FOR TESTING ONLY.
void random_poly_test(int32_t* a, unsigned int p, unsigned int pbits, unsigned int N);

// Comparing two polynomials over GF(p), a[x]=b[x]? : (0) a=b, (1) a!=b
// NOTE: TO BE USED FOR TESTING ONLY.
int compare_poly(int32_t* a, int32_t* b, unsigned int N); 
    
// Modular reduction
// NOTE: TO BE USED FOR TESTING ONLY.
int reduce(int a, int p);

// Polynomial multiplication using the schoolbook method, c[x] = a[x]*b[x]
// NOTE: TO BE USED FOR TESTING ONLY.
void mul_test(int32_t* a, int32_t* b, int32_t* c, uint32_t p, unsigned int N);                  

// Polynomial addition, c[x] = a[x] + b[x]  
// NOTE: TO BE USED FOR TESTING ONLY.
void add_test(int32_t* a, int32_t* b, int32_t* c, uint32_t p, unsigned int N);


#ifdef __cplusplus
}
#endif


#endif