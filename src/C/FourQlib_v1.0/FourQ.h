/***********************************************************************************
* FourQ: 4-dimensional decomposition on a Q-curve with CM in twisted Edwards form
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
* Abstract: main header file
*
* This code is based on the paper "FourQ: four-dimensional decompositions on a 
* Q-curve over the Mersenne prime" by Craig Costello and Patrick Longa, in Advances 
* in Cryptology - ASIACRYPT, 2015.
* Preprint available at http://eprint.iacr.org/2015/565.
************************************************************************************/  

#ifndef __MSR_FourQ_H__
#define __MSR_FourQ_H__


// For C++
#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>
#include <stdbool.h>


// Definition of operating system

#define OS_WIN       1
#define OS_LINUX     2

#if defined(__WINDOWS__)        // Microsoft Windows OS
    #define OS_TARGET OS_WIN
#elif defined(__LINUX__)        // Linux OS
    #define OS_TARGET OS_LINUX 
#else
    #error -- "Unsupported OS"
#endif


// Definition of compiler

#define COMPILER_VC      1
#define COMPILER_GCC     2

#if defined(_MSC_VER)           // Microsoft Visual C compiler
    #define COMPILER COMPILER_VC
#elif defined(__GNUC__)         // GNU GCC compiler
    #define COMPILER COMPILER_GCC   
#else
    #error -- "Unsupported COMPILER"
#endif


// Definition of the targeted architecture and basic data types
    
#define TARGET_AMD64        1
#define TARGET_x86          2
#define TARGET_ARM          3

#if defined(_AMD64_)
    #define TARGET TARGET_AMD64
    #define RADIX           64
    typedef uint64_t        digit_t;      // Unsigned 64-bit digit
    typedef int64_t         sdigit_t;     // Signed 64-bit digit
    #define NWORDS_FIELD    2             // Number of words of a field element
    #define NWORDS_ORDER    4             // Number of words of an element in Z_r 
#elif defined(_X86_)
    #define TARGET TARGET_x86
    #define RADIX           32
    typedef uint32_t        digit_t;      // Unsigned 32-bit digit
    typedef int32_t         sdigit_t;     // Signed 32-bit digit
    #define NWORDS_FIELD    4             
    #define NWORDS_ORDER    8 
#elif defined(_ARM_)
    #define TARGET TARGET_ARM
    #define RADIX           32
    typedef uint32_t        digit_t;      // Unsigned 32-bit digit
    typedef int32_t         sdigit_t;     // Signed 32-bit digit
    #define NWORDS_FIELD    4             
    #define NWORDS_ORDER    8 
#else
    #error -- "Unsupported ARCHITECTURE"
#endif

#define RADIX64         64
#define NWORDS64_FIELD  2                 // Number of 64-bit words of a field element 
#define NWORDS64_ORDER  4                 // Number of 64-bit words of an element in Z_r 


// Instruction support

#define NO_SIMD_SUPPORT 0
#define AVX_SUPPORT     1
#define AVX2_SUPPORT    2

#if defined(_AVX2_)
    #define SIMD_SUPPORT AVX2_SUPPORT       // AVX2 support selection 
#elif defined(_AVX_)
    #define SIMD_SUPPORT AVX_SUPPORT        // AVX support selection 
#else
    #define SIMD_SUPPORT NO_SIMD_SUPPORT
#endif

#if defined(_ASM_)                          // Assembly support selection
    #define ASM_SUPPORT
#endif

#if defined(_GENERIC_)                      // Selection of generic, portable implementation
    #define GENERIC_IMPLEMENTATION
#endif


// Unsupported configurations
                         
#if defined(ASM_SUPPORT) && (OS_TARGET == OS_WIN)
    #error -- "Assembly is not supported on this platform"
#endif        

#if defined(ASM_SUPPORT) && defined(GENERIC_IMPLEMENTATION)
    #error -- "Unsupported configuration"
#endif        

#if (SIMD_SUPPORT != NO_SIMD_SUPPORT) && defined(GENERIC_IMPLEMENTATION)
    #error -- "Unsupported configuration"
#endif

#if (TARGET != TARGET_AMD64) && !defined(GENERIC_IMPLEMENTATION)
    #error -- "Unsupported configuration"
#endif


// Extended datatype support
 
#if defined(GENERIC_IMPLEMENTATION)                       
    typedef uint64_t uint128_t[2];
#elif (TARGET == TARGET_AMD64) && (OS_TARGET == OS_LINUX && COMPILER == COMPILER_GCC)
    #define UINT128_SUPPORT
    typedef unsigned uint128_t __attribute__((mode(TI))); 
#elif (TARGET == TARGET_AMD64) && (OS_TARGET == OS_WIN && COMPILER == COMPILER_VC)
    #define SCALAR_INTRIN_SUPPORT   
    typedef uint64_t uint128_t[2];
#else
    #error -- "Unsupported configuration"
#endif


// Define if zeroing of temporaries in low-level functions is required
//#define TEMP_ZEROING


// Basic parameters for variable-base scalar multiplication (without using endomorphisms)
#define W_VARBASE             5 
#define NPOINTS_VARBASE       (1 << (W_VARBASE-2)) 
#define NBITS_ORDER_PLUS_ONE  246+1 
#define t_VARBASE             ((NBITS_ORDER_PLUS_ONE+W_VARBASE-2)/(W_VARBASE-1))
 

// Enable if use of fixed-base scalar multiplication is required 
#define USE_FIXED_BASE_SM		

// Basic parameters for fixed-base scalar multiplication
#ifdef USE_FIXED_BASE_SM
    #define W_FIXEDBASE       5                  // Memory requirement: 7.5KB (storage for 80 points).
    #define V_FIXEDBASE       5                  // W_FIXEDBASE and V_FIXEDBASE must be positive integers in the range [1, 10].  
    #define E_FIXEDBASE       (NBITS_ORDER_PLUS_ONE + W_FIXEDBASE*V_FIXEDBASE - 1)/(W_FIXEDBASE*V_FIXEDBASE)
    #define D_FIXEDBASE       E_FIXEDBASE*V_FIXEDBASE
    #define L_FIXEDBASE       D_FIXEDBASE*W_FIXEDBASE  
    #define NPOINTS_FIXEDBASE V_FIXEDBASE*(1 << (W_FIXEDBASE-1))  
    #define VPOINTS_FIXEDBASE (1 << (W_FIXEDBASE-1)) 
    #if (NBITS_ORDER_PLUS_ONE-L_FIXEDBASE == 0)  // This parameter selection is not supported  
        #error -- "Unsupported parameter selection for fixed-base scalar multiplication"
    #endif 
#endif
   

// FourQ's basic element definitions and point representations

typedef digit_t felm_t[NWORDS_FIELD];             // Datatype for representing 128-bit field elements 
typedef digit_t digit256_t[NWORDS_ORDER];         // Datatype for representing 256-bit elements in Z_r 
typedef felm_t f2elm_t[2];                        // Datatype for representing quadratic extension field elements
typedef uint64_t digit64_256_t[NWORDS64_ORDER];   // Datatype for representing 256-bit elements in Z_r with uint64_t type
        
typedef struct { f2elm_t x; f2elm_t y; } point_affine;                                      // Point representation in affine coordinates.
typedef point_affine point_t[1]; 
typedef struct { f2elm_t x; f2elm_t y; f2elm_t z; f2elm_t ta; f2elm_t tb; } point_extproj;  // Point representation in extended coordinates.
typedef point_extproj point_extproj_t[1];                                                              
typedef struct { f2elm_t xy; f2elm_t yx; f2elm_t z2; f2elm_t t2; } point_extproj_precomp;   // Point representation in extended coordinates (for precomputed points).
typedef point_extproj_precomp point_extproj_precomp_t[1];  
typedef struct { f2elm_t xy; f2elm_t yx; f2elm_t t2; } point_precomp;                       // Point representation in extended affine coordinates (for precomputed points).
typedef point_precomp point_precomp_t[1];


// FourQ's data structure
typedef struct
{    
    unsigned int     nbits;                            // 2 x targeted security level
    unsigned int     rbits;                            // Bitlength of the prime order subgroup
    uint64_t         prime[NWORDS64_FIELD];            // Prime
    uint64_t         a[NWORDS64_ORDER];                // Curve parameter "a"
    uint64_t         d[NWORDS64_ORDER];                // Curve parameter "d"
    uint64_t         order[NWORDS64_ORDER];            // Prime order of the curve subgroup 
    uint64_t         generator_x[NWORDS64_ORDER];      // x-coordinate of the generator
    uint64_t         generator_y[NWORDS64_ORDER];      // y-coordinate of the generator
    unsigned int     cofactor;                         // Co-factor of the curve group
} CurveStruct, *PCurveStruct;                                                                             


// FourQ's structure definition
extern CurveStruct curve4Q;


/********************** Constant-time unsigned comparisons ***********************/

// The following functions return 1 (TRUE) if condition is true, 0 (FALSE) otherwise

static __inline unsigned int is_digit_nonzero_ct(digit_t x)
{ // Is x != 0?
    return (unsigned int)((x | (0-x)) >> (RADIX-1));
}

static __inline unsigned int is_digit_zero_ct(digit_t x)
{ // Is x = 0?
    return (unsigned int)(1 ^ is_digit_nonzero_ct(x));
}

static __inline unsigned int is_digit_lessthan_ct(digit_t x, digit_t y)
{ // Is x < y?
    return (unsigned int)((x ^ ((x ^ y) | ((x - y) ^ y))) >> (RADIX-1)); 
}


/********************** Macros for platform-dependent operations **********************/

#if defined(GENERIC_IMPLEMENTATION)

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                                                     \
    digit_x_digit((multiplier), (multiplicand), &(lo));
    
// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                         \
    { digit_t tempReg = (addend1) + (digit_t)(carryIn);                                           \
    (sumOut) = (addend2) + tempReg;                                                               \
    (carryOut) = (is_digit_lessthan_ct(tempReg, (digit_t)(carryIn)) | is_digit_lessthan_ct((sumOut), tempReg)); }

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                             \
    { digit_t tempReg = (minuend) - (subtrahend);                                                 \
    unsigned int borrowReg = (is_digit_lessthan_ct((minuend), (subtrahend)) | ((borrowIn) & is_digit_zero_ct(tempReg)));  \
    (differenceOut) = tempReg - (digit_t)(borrowIn);                                              \
    (borrowOut) = borrowReg; }
    
// Shift right with flexible datatype
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (DigitSize - (shift)));

// 64x64-bit multiplication
#define MUL128(multiplier, multiplicand, product)                                                 \
    mp_mul((digit_t*)&(multiplier), (digit_t*)&(multiplicand), (digit_t*)&(product), NWORDS_FIELD/2);

// 128-bit addition, inputs < 2^127
#define ADD128(addend1, addend2, addition)                                                        \
    mp_add((digit_t*)(addend1), (digit_t*)(addend2), (digit_t*)(addition), NWORDS_FIELD);

// 128-bit addition with output carry
#define ADC128(addend1, addend2, carry, addition)                                                 \
    (carry) = mp_add((digit_t*)(addend1), (digit_t*)(addend2), (digit_t*)(addition), NWORDS_FIELD);

#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_WIN)

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                                                     \
    (lo) = _umul128((multiplier), (multiplicand), (hi));                

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                         \
    (carryOut) = _addcarry_u64((carryIn), (addend1), (addend2), &(sumOut));

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                             \
    (borrowOut) = _subborrow_u64((borrowIn), (minuend), (subtrahend), &(differenceOut));

// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = __shiftright128((lowIn), (highIn), (shift));

// 64x64-bit multiplication
#define MUL128(multiplier, multiplicand, product)                                                 \
    (product)[0] = _umul128((multiplier), (multiplicand), &(product)[1]);

// 128-bit addition, inputs < 2^127
#define ADD128(addend1, addend2, addition)                                                        \
    { unsigned char carry = _addcarry_u64(0, (addend1)[0], (addend2)[0], &(addition)[0]);         \
    _addcarry_u64(carry, (addend1)[1], (addend2)[1], &(addition)[1]); }

// 128-bit addition with output carry
#define ADC128(addend1, addend2, carry, addition)                                                 \
    (carry) = _addcarry_u64(0, (addend1)[0], (addend2)[0], &(addition)[0]);                       \
    (carry) = _addcarry_u64((carry), (addend1)[1], (addend2)[1], &(addition)[1]); 

// 128-bit subtraction, subtrahend < 2^127
#define SUB128(minuend, subtrahend, difference)                                                   \
    { unsigned char borrow = _subborrow_u64(0, (minuend)[0], (subtrahend)[0], &(difference)[0]);  \
    _subborrow_u64(borrow, (minuend)[1], (subtrahend)[1], &(difference)[1]); }

// 128-bit right shift, max. shift value is 64
#define SHIFTR128(Input, shift, shiftOut)                                                         \
    (shiftOut)[0]  = __shiftright128((Input)[0], (Input)[1], (shift));                            \
    (shiftOut)[1] = (Input)[1] >> (shift);    

// 128-bit left shift, max. shift value is 64
#define SHIFTL128(Input, shift, shiftOut)                                                         \
    (shiftOut)[1]  = __shiftleft128((Input)[0], (Input)[1], (shift));                             \
    (shiftOut)[0] = (Input)[0] << (shift);  

#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_LINUX)

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                                                     \
    { uint128_t tempReg = (uint128_t)(multiplier) * (uint128_t)(multiplicand);                    \
    *(hi) = (digit_t)(tempReg >> RADIX);                                                          \
    (lo) = (digit_t)tempReg; }

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                                         \
    { uint128_t tempReg = (uint128_t)(addend1) + (uint128_t)(addend2) + (uint128_t)(carryIn);     \
    (carryOut) = (digit_t)(tempReg >> RADIX);                                                     \
    (sumOut) = (digit_t)tempReg; }  
    
// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                             \
    { uint128_t tempReg = (uint128_t)(minuend) - (uint128_t)(subtrahend) - (uint128_t)(borrowIn); \
    (borrowOut) = (digit_t)(tempReg >> (sizeof(uint128_t)*8 - 1));                                \
    (differenceOut) = (digit_t)tempReg; }

// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut, DigitSize)                                         \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (RADIX - (shift)));

#endif


/**************** Function prototypes ****************/

/************* Multiprecision functions **************/

// Multiprecision addition, c = a+b. Returns the carry bit
unsigned int mp_add(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords);          

// Schoolbook multiprecision multiply, c = a*b
void mp_mul(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords);  

// Multiprecision subtraction, c = a-b. Returns the borrow bit
#if defined (GENERIC_IMPLEMENTATION)
unsigned int subtract(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords);
#else
unsigned char subtract(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords);
#endif

// 256-bit Montgomery multiplication
void Montgomery_multiply(digit256_t ma, digit256_t mb, digit256_t mc, digit256_t modulus);

// Clear "nwords" integer-size digits from memory
__inline void clear_words(void* mem, unsigned int nwords);

/************ Field arithmetic functions *************/
   
// Field negation, a = -a mod p
__inline void fpneg1271(felm_t a);

// Modular correction, a = a mod p
void mod1271(felm_t a); 

// Field squaring, c = a^2 mod p
void fpsqr1271(felm_t a, felm_t c);

// Field inversion, af = a^-1 = a^(p-2) mod p
void fpinv1271(felm_t a);

/************ Quadratic extension field arithmetic functions *************/

// Zeroing a quadratic extension field element, a=0 
void fp2zero1271(f2elm_t a);

// Copy quadratic extension field element, c = a
void fp2copy1271(f2elm_t a, f2elm_t c); 

// Quadratic extension field negation, a = -a in GF((2^127-1)^2)
void fp2neg1271(f2elm_t a);

// Quadratic extension field addition, c = a+b in GF((2^127-1)^2)
__inline void fp2add1271(f2elm_t a, f2elm_t b, f2elm_t c);

// Quadratic extension field subtraction, c = a-b in GF((2^127-1)^2)
__inline void fp2sub1271(f2elm_t a, f2elm_t b, f2elm_t c);

// Quadratic extension field multiplication, c = a*b in GF((2^127-1)^2)
void fp2mul1271(f2elm_t a, f2elm_t b, f2elm_t c);

// Quadratic extension field squaring, c = a^2 in GF((2^127-1)^2)
void fp2sqr1271(f2elm_t a, f2elm_t c);

// Quadratic extension field inversion, af = a^-1 = a^(p-2) in GF((2^127-1)^2)
void fp2inv1271(f2elm_t a);

/************ Curve and recoding functions *************/

// Set generator (x,y)
void eccset(point_t P, PCurveStruct curve);

// Normalize projective twisted Edwards point Q = (X,Y,Z) -> P = (x,y)
void eccnorm(point_extproj_t P, point_t Q);

// Conversion from representation (X,Y,Z,Ta,Tb) to (X+Y,Y-X,2Z,2dT), where T = Ta*Tb
__inline void R1_to_R2(point_extproj_t P, point_extproj_precomp_t Q, PCurveStruct curve);

// Conversion from representation (X,Y,Z,Ta,Tb) to (X+Y,Y-X,Z,T), where T = Ta*Tb 
__inline void R1_to_R3(point_extproj_t P, point_extproj_precomp_t Q);  
 
// Conversion from representation (X+Y,Y-X,2Z,2dT) to (2X,2Y,2Z,2dT)
void R2_to_R4(point_extproj_precomp_t P, point_extproj_t Q);     

// Point doubling 2P
void eccdouble_ni(point_extproj_t P);
__inline void eccdouble(point_extproj_t P);

// Complete point addition P = P+Q or P = P+P
void eccadd_ni(point_extproj_precomp_t Q, point_extproj_t P);
__inline void eccadd(point_extproj_precomp_t Q, point_extproj_t P);
__inline void eccadd_core(point_extproj_precomp_t P, point_extproj_precomp_t Q, point_extproj_t R); 

// Psi mapping of a point, P = psi(P)
void ecc_psi(point_extproj_t P); 

// Phi mapping of a point, P = phi(P)
void ecc_phi(point_extproj_t P);

// Scalar decomposition
void decompose(digit64_256_t k, digit64_256_t scalars);

// Recoding sub-scalars for use in the variable-base scalar multiplication
void recode(digit64_256_t scalars, unsigned int* digits, unsigned int* sign_masks);

// Computes the fixed window representation of scalar
void fixed_window_recode(digit64_256_t scalar, unsigned int* digits, unsigned int* sign_masks);

// Convert scalar to odd if even using the prime subgroup order r
void conversion_to_odd(digit256_t k, digit256_t k_odd, PCurveStruct curve);

// Co-factor clearing
void cofactor_clearing(point_extproj_t P, PCurveStruct curve);

// Reduction modulo the order using Montgomery arithmetic
void modulo_order(digit256_t a, digit256_t c, PCurveStruct curve);

// Precomputation function
void ecc_precomp(point_extproj_t P, point_extproj_precomp_t *T, PCurveStruct curve);

// Constant-time table lookup to extract an extended twisted Edwards point (X+Y:Y-X:2Z:2T) from the precomputed table
void table_lookup_1x8(point_extproj_precomp_t* table, point_extproj_precomp_t P, unsigned int digit, unsigned int sign_mask);

// Modular correction of input coordinates and conversion to representation (X,Y,Z,Ta,Tb) 
__inline void point_setup(point_t P, point_extproj_t Q);
void point_setup_ni(point_t P, point_extproj_t Q);
    
// Point validation: check if point lies on the curve     
__inline bool ecc_point_validate(point_extproj_t P, PCurveStruct curve);

// Variable-base scalar multiplication Q = k*P using a 4-dimensional decomposition
bool ecc_mul(point_t P, digit64_256_t k, point_t Q, bool clear_cofactor, PCurveStruct curve);

#if defined(USE_FIXED_BASE_SM)

// Mixed point addition P = P+Q or P = P+P
void eccmadd_ni(point_precomp_t Q, point_extproj_t P);

// Constant-time table lookup to extract a point represented as (x+y,y-x,2t)
void table_lookup_fixed_base(point_precomp_t* table, point_precomp_t P, unsigned int digit, unsigned int sign);

//  Computes the modified LSB-set representation of scalar
void mLSB_set_recode(digit64_256_t scalar, unsigned int *digits);

// Fixed-base scalar multiplication Q = k*P using the modified LSB-set comb method 
bool ecc_mul_fixed(point_precomp_t *T_fixed, digit64_256_t k, point_t Q, PCurveStruct curve);

// Allocate memory dynamically for precomputation table "T_fixed" used during fixed-base scalar multiplications
// This function must be called before using ecc_precomp_fixed() to generate a precomputed table 
point_precomp_t* ecc_allocate_precomp(void);

// Precomputation function for fixed-base scalar multiplication using affine coordinates with representation (x+y,y-x,2dt) 
bool ecc_precomp_fixed(point_t P, point_precomp_t* T_fixed, bool clear_cofactor, PCurveStruct curve);

#endif


/************ Functions based on macros *************/

// Copy extended projective point Q = (X:Y:Z:Ta:Tb) to P
#define ecccopy(Q, P); fp2copy1271((Q)->x,  (P)->x);  \
                       fp2copy1271((Q)->y,  (P)->y);  \
                       fp2copy1271((Q)->z,  (P)->z);  \
                       fp2copy1271((Q)->ta, (P)->ta); \
                       fp2copy1271((Q)->tb, (P)->tb);

// Copy extended projective point Q = (X+Y,Y-X,2Z,2dT) to P
#define ecccopy_precomp(Q, P); fp2copy1271((Q)->xy, (P)->xy); \
                               fp2copy1271((Q)->yx, (P)->yx); \
                               fp2copy1271((Q)->z2, (P)->z2); \
                               fp2copy1271((Q)->t2, (P)->t2); 

// Copy extended affine point Q = (x+y,y-x,2dt) to P
#define ecccopy_precomp_fixed_base(Q, P); fp2copy1271((Q)->xy, (P)->xy); \
                                          fp2copy1271((Q)->yx, (P)->yx); \
                                          fp2copy1271((Q)->t2, (P)->t2);


#ifdef __cplusplus
}
#endif


#endif
