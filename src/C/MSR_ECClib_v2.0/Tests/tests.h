/**************************************************************************
* Benchmarking/testing suite for MSR ECClib
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*    MIT License
*
*    Permission is hereby granted, free of charge, to any person obtaining 
*    a copy of this software and associated documentation files (the 
*    ""Software""), to deal in the Software without restriction, including
*    without limitation the rights to use, copy, modify, merge, publish,
*    distribute, sublicense, and/or sell copies of the Software, and to
*    permit persons to whom the Software is furnished to do so, subject to
*    the following conditions:
*
*    The above copyright notice and this permission notice shall
*    be included in all copies or substantial portions of the Software.
*
*    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND,
*    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
*    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
*    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
*    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
*    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
*    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*
* Abstract: header file for benchmarking/testing suite
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
***************************************************************************/    

#include "msr_ecclib.h"


// Benchmark and test parameters  
#if TARGET == TARGET_AMD64
    #define ML_BENCH_LOOPS       100000     // Number of iterations per bench
    #define ML_SHORT_BENCH_LOOPS 10000      // Number of iterations per bench (for expensive operations)
    #define ML_TEST_LOOPS        10         // Number of iterations per test
    #define ML_SHORT_TEST_LOOPS  1          // Number of iterations per test (for expensive operations)
#else
    #define ML_BENCH_LOOPS       10000      
    #define ML_SHORT_BENCH_LOOPS 100       
    #define ML_TEST_LOOPS        1          
    #define ML_SHORT_TEST_LOOPS  1          
#endif
#define MAIN_TESTS_ONLY                     // Select if tests need to be performed on "main functions" only

// Select function to be used to generate random bytes for nonces and private keys (e.g., nonce "k" in ECDSA signing)
// NOTE: USERS SHOULD SELECT HERE THEIR OWN RANDOM_BYTES FUNCTION
#define RANDOM_BYTES_FUNCTION    random_bytes_test      // This function is based on the C function rand() (see extras.c).

// This instruction queries the processor for information about the supported features and CPU type
#define cpuid(cpuinfo, infotype)    __cpuidex(cpuinfo, infotype, 0)


/********** Prototypes of utility functions ***********/

// Access system counter for benchmarking
int64_t cpucycles(void);

// Print benchmarking result with the corresponding unit
void bench_print(char* label, unsigned long long count, unsigned long long num_runs);

// Detecting support for AVX instructions
BOOL is_avx_supported(void);

// Compare two field elements, a = b? (1) a>b, (0) a=b, (-1) a<b 
// SECURITY NOTE: this function does not have constant-time execution. TO BE USED FOR TESTING ONLY.
int fpcompare256(dig256 a, dig256 b);
int fpcompare384(dig384 a, dig384 b);
int fpcompare512(dig512 a, dig512 b);

// Get prime value p
void fp_prime256(dig256 p, PCurveStruct PCurve);
void fp_prime384(dig384 p, PCurveStruct PCurve);
void fp_prime512(dig512 p, PCurveStruct PCurve);

// Generate a pseudo-random element in [0, modulus-1]
// SECURITY NOTE: distribution is not fully uniform. TO BE USED FOR TESTING ONLY.
void random256_test(dig256 a, dig256 modulus);
void random384_test(dig384 a, dig384 modulus);
void random512_test(dig512 a, dig512 modulus);

// Subtraction without borrow, c = a-b where a>b
// SECURITY NOTE: this function does not have constant-time execution. TO BE USED FOR TESTING ONLY.
void sub256_test(dig256 a, dig256 b, dig256 c);
void sub384_test(dig384 a, dig384 b, dig384 c);
void sub512_test(dig512 a, dig512 b, dig512 c);

// Point doubling P = 2P using affine coordinates, Weierstrass curve, generic "a"
// SECURITY NOTE: this function does not have constant-time execution. TO BE USED FOR TESTING ONLY.
void eccdouble_waff_256(point_numsp256d1 P, PCurveStruct PCurve);
void eccdouble_waff_384(point_numsp384d1 P, PCurveStruct PCurve);
void eccdouble_waff_512(point_numsp512d1 P, PCurveStruct PCurve);

// Point addition P = P+Q using affine coordinates, Weierstrass a=-3 curve
// SECURITY NOTE: this function does not have constant-time execution. TO BE USED FOR TESTING ONLY.
void eccadd_waff_256(point_numsp256d1 Q, point_numsp256d1 P, PCurveStruct PCurve);
void eccadd_waff_384(point_numsp384d1 Q, point_numsp384d1 P, PCurveStruct PCurve);
void eccadd_waff_512(point_numsp512d1 Q, point_numsp512d1 P, PCurveStruct PCurve);

// Variable-base scalar multiplication Q = k.P using affine coordinates and the binary representation, Weierstrass a=-3 curve
// SECURITY NOTE: this function does not have constant-time execution. TO BE USED FOR TESTING ONLY.
void ecc_mul_waff_256(point_numsp256d1 P, dig *k, point_numsp256d1 Q, PCurveStruct PCurve);
void ecc_mul_waff_384(point_numsp384d1 P, dig *k, point_numsp384d1 Q, PCurveStruct PCurve);
void ecc_mul_waff_512(point_numsp512d1 P, dig *k, point_numsp512d1 Q, PCurveStruct PCurve);

// Convert point on one of the NUMS twisted Edwards curves to its corresponding isomorphic Weierstrass curve
void ecc_numsp256t1_to_weierstrass(point_numsp256t1 Q, point_numsp256d1 P, PCurveStruct TedCurve);
void ecc_numsp384t1_to_weierstrass(point_numsp384t1 Q, point_numsp384d1 P, PCurveStruct TedCurve);
void ecc_numsp512t1_to_weierstrass(point_numsp512t1 Q, point_numsp512d1 P, PCurveStruct TedCurve);

// Convert point on isomorphic Weierstrass curve to its corresponding NUMS twisted Edwards curve
void ecc_weierstrass_to_numsp256t1(point_numsp256d1 Q, point_numsp256t1 P, PCurveStruct TedCurve);
void ecc_weierstrass_to_numsp384t1(point_numsp384d1 Q, point_numsp384t1 P, PCurveStruct TedCurve);
void ecc_weierstrass_to_numsp512t1(point_numsp512d1 Q, point_numsp512t1 P, PCurveStruct TedCurve);


// Other testing functions used for verifying correctness of recoding algorithms

BOOL verify_mLSB_recoding(dig *scalar, int *digits, unsigned int nbits, unsigned int l, unsigned int d);
BOOL verify_recoding(dig *scalar, int *digits, unsigned int nbits);


// Generate "nbytes" random bytes and output the result to random_array
// Returns ECCRYPTO_SUCCESS (=1) on success, ECCRYPTO_ERROR (=0) otherwise.
// SECURITY NOTE: TO BE USED FOR TESTING ONLY. USERS SHOULD PROVIDE THEIR OWN RANDOM_BYTES FUNCTION BASED ON THIS PROTOTYPE
ECCRYPTO_STATUS random_bytes_test(unsigned int nbytes, unsigned char* random_array);
