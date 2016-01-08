/*******************************************************************************
* MSR ECClib v2.0, an efficient and secure elliptic curve cryptographic library
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
* Abstract: internal declarations for MSR ECClib
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
******************************************************************************/  

#ifndef __MSR_ECCLIB_PRIV_H__
#define __MSR_ECCLIB_PRIV_H__

// For C++
#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>
#include "msr_ecclib.h"


// OS and compiler-dependent macros

#if (COMPILER == COMPILER_VC)
    #define STATIC_INLINE static __inline
    #define INLINE        __inline
#elif (COMPILER == COMPILER_GCC)
    #define STATIC_INLINE static inline
    #define INLINE        inline
#endif
    

// Macro to avoid compiler warnings when detecting unreferenced parameters
#define UNREFERENCED_PARAMETER(PAR)    (PAR)

    
// Additional point representations used internally:

// Types for point representations for Weierstrass a=-3 curve "numsp256d1" 
typedef struct { dig256 X; dig256 Y; dig256 Z; dig256 Z2; dig256 Z3; } point_chu_precomp_numsp256d1t;  // Point representation in Chudnovsky coordinates (X:Y:Z:Z^2:Z^3) (used for precomputed points).
typedef point_chu_precomp_numsp256d1t point_chu_precomp_numsp256d1[1];                      

// Types for point representations for twisted Edwards a=1 curve "numsp256t1"                  
typedef struct { dig256 X; dig256 Y; dig256 Z; dig256 Td; } point_extproj_precomp_numsp256t1t;         // Point representation in homogeneous coordinates (X:Y:Z:dT) (used for precomputed points).
typedef point_extproj_precomp_numsp256t1t point_extproj_precomp_numsp256t1[1]; 


// Types for point representations for Weierstrass a=-3 curve "numsp384d1"  
typedef struct { dig384 X; dig384 Y; dig384 Z; dig384 Z2; dig384 Z3; } point_chu_precomp_numsp384d1t;  // Point representation in Chudnovsky coordinates (X:Y:Z:Z^2:Z^3) (used for precomputed points).
typedef point_chu_precomp_numsp384d1t point_chu_precomp_numsp384d1[1];                       

// Types for point representations for twisted Edwards a=1 curve "numsp384t1"                  
typedef struct { dig384 X; dig384 Y; dig384 Z; dig384 Td; } point_extproj_precomp_numsp384t1t;         // Point representation in homogeneous coordinates (X:Y:Z:Td) (used for precomputed points).
typedef point_extproj_precomp_numsp384t1t point_extproj_precomp_numsp384t1[1];  


// Types for point representations for Weierstrass a=-3 curve "numsp512d1"   
typedef struct { dig512 X; dig512 Y; dig512 Z; dig512 Z2; dig512 Z3; } point_chu_precomp_numsp512d1t;  // Point representation in Chudnovsky coordinates (X:Y:Z:Z^2:Z^3) (used for precomputed points).
typedef point_chu_precomp_numsp512d1t point_chu_precomp_numsp512d1[1];                        

// Types for point representations for twisted Edwards a=1 curve "numsp512t1"                  
typedef struct { dig512 X; dig512 Y; dig512 Z; dig512 Td; } point_extproj_precomp_numsp512t1t;         // Point representation in homogeneous coordinates (X:Y:Z:Td) (used for precomputed points).
typedef point_extproj_precomp_numsp512t1t point_extproj_precomp_numsp512t1[1]; 



/********************** Constant-time unsigned comparisons ***********************/

// The following functions return 1 (TRUE) if condition is true, 0 (FALSE) otherwise

static __inline unsigned char is_digit_nonzero_ct(dig x)
{ // Is x != 0?
    return (unsigned char)((x | (0-x)) >> (ML_WORD - 1));
}

static __inline unsigned char is_digit_zero_ct(dig x)
{ // Is x = 0?
    return (unsigned char)(1 ^ is_digit_nonzero_ct(x));
}

static __inline unsigned char are_digits_notequal_ct(dig x, dig y)
{ // Is x != y?
    return (unsigned char)(((x ^ y) | (0-(x ^ y))) >> (ML_WORD - 1));
}

static __inline unsigned char are_digits_equal_ct(dig x, dig y)
{ // Is x = y?
    return (unsigned char)(1 ^ are_digits_notequal_ct(x, y));
}

static __inline unsigned char is_digit_lessthan_ct(dig x, dig y)
{ // Is x < y?
    return (unsigned char)((x ^ ((x ^ y) | ((x - y) ^ y))) >> (ML_WORD - 1)); 



/***************** Platform-dependent definitions of digit operations *******************/

#if TARGET_GENERIC == TRUE
    
// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                        \
     tempReg = (addend1) + (dig)(carryIn);                                       \
     (sumOut) = (addend2) + tempReg;                                             \
     (carryOut) = (is_digit_lessthan_ct(tempReg, (dig)(carryIn)) | is_digit_lessthan_ct((sumOut), tempReg));

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)             \
     tempReg = (minuend) - (subtrahend);                                          \
     borrowReg = (is_digit_lessthan_ct((minuend), (subtrahend)) | ((borrowIn) & is_digit_zero_ct(tempReg)));    \
     (differenceOut) = tempReg - (dig)(borrowIn);                                 \
     (borrowOut) = borrowReg;
    
// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut)    \
     (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (ML_WORD - (shift)));
    
// Digit shift left
#define SHIFTL(highIn, lowIn, shift, shiftOut)    \
     (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (ML_WORD - (shift)));

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)     \
     dig_x_dig(multiplier, multiplicand, &lo);

#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_WIN)

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)   \
    carryOut = _addcarry_u64(carryIn, addend1, addend2, &sumOut);

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)   \
    borrowOut = _subborrow_u64(borrowIn, minuend, subtrahend, &differenceOut);

// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut)   \
    shiftOut = __shiftright128(lowIn, highIn, shift);

// Digit shift left
#define SHIFTL(highIn, lowIn, shift, shiftOut)   \
     shiftOut = __shiftleft128(lowIn, highIn, shift);

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)    \
    lo = _umul128(multiplier, multiplicand, hi);

#elif (TARGET == TARGET_AMD64 && OS_TARGET == OS_LINUX)

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                         \
    tempReg = (uint128_t)(addend1) + (uint128_t)(addend2) + (uint128_t)(carryIn); \
    (carryOut) = (dig)(tempReg >> ML_WORD);                                       \
    (sumOut) = (dig)tempReg;
    
// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                 \
    tempReg = (uint128_t)(minuend) - (uint128_t)(subtrahend) - (uint128_t)(borrowIn); \
    (borrowOut) = (dig)(tempReg >> (sizeof(uint128_t)*8 - 1));                        \
    (differenceOut) = (dig)tempReg;

// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut)    \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (ML_WORD - (shift)));

// Digit shift left
#define SHIFTL(highIn, lowIn, shift, shiftOut)    \
    (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (ML_WORD - (shift)));

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                      \
    tempReg = (uint128_t)(multiplier) * (uint128_t)(multiplicand); \
    *(hi) = (dig)(tempReg >> ML_WORD);                             \
    (lo) = (dig)tempReg;

#elif (TARGET == TARGET_x86 && OS_TARGET == OS_WIN)

// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                          \
     carryOut = _addcarry_u32(carryIn, addend1, addend2, &sumOut);

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)              \
     borrowOut = _subborrow_u32(borrowIn, minuend, subtrahend, &differenceOut);
    
// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut)    \
     shiftOut = (dig)__ull_rshift(((uint64_t)highIn << ML_WORD) ^ (uint64_t)lowIn, shift);
    
// Digit shift left
#define SHIFTL(highIn, lowIn, shift, shiftOut)    \
     shiftOut = (dig)(__ll_lshift(((uint64_t)highIn << ML_WORD) ^ (uint64_t)lowIn, shift) >> ML_WORD);
    
// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                     \
     tempReg = (uint64_t)(multiplier) * (uint64_t)(multiplicand); \
     *(hi) = (dig)(tempReg >> ML_WORD);                           \
     (lo) = (dig)tempReg;

#elif (TARGET == TARGET_x86 && OS_TARGET == OS_LINUX) || (TARGET == TARGET_ARM)
    
// Digit addition with carry
#define ADDC(carryIn, addend1, addend2, carryOut, sumOut)                         \
    tempReg = (uint64_t)(addend1) + (uint64_t)(addend2) + (uint64_t)(carryIn);    \
    (carryOut) = (dig)(tempReg >> ML_WORD);                                       \
    (sumOut) = (dig)tempReg;

// Digit subtraction with borrow
#define SUBC(borrowIn, minuend, subtrahend, borrowOut, differenceOut)                 \
    tempReg = (uint64_t)(minuend) - (uint64_t)(subtrahend) - (uint64_t)(borrowIn);    \
    (borrowOut) = (dig)(tempReg >> (sizeof(uint64_t)*8 - 1));                         \
    (differenceOut) = (dig)tempReg;
    
// Digit shift right
#define SHIFTR(highIn, lowIn, shift, shiftOut)    \
    (shiftOut) = ((lowIn) >> (shift)) ^ ((highIn) << (ML_WORD - (shift)));
    
// Digit shift left
#define SHIFTL(highIn, lowIn, shift, shiftOut)    \
    (shiftOut) = ((highIn) << (shift)) ^ ((lowIn) >> (ML_WORD - (shift)));

// Digit multiplication
#define MUL(multiplier, multiplicand, hi, lo)                      \
    tempReg = (uint64_t)(multiplier) * (uint64_t)(multiplicand);   \
    *(hi) = (dig)(tempReg >> ML_WORD);                             \
    (lo) = (dig)tempReg;

#endif
}



/*************************** Function prototypes *****************************/

/********** Field functions ***********/

// Low-level field multiplication c=a*b mod p in x64 assembly and C
void fpmul256_a(dig256 a, dig256 b, dig256 c);
void fpmul384_a(dig384 a, dig384 b, dig384 c);
void fpmul512_a(dig512 a, dig512 b, dig512 c);

BOOL fpmul256_c(dig256 a, dig256 b, dig256 c);                
BOOL fpmul384_c(dig384 a, dig384 b, dig384 c);
BOOL fpmul512_c(dig512 a, dig512 b, dig512 c);

// Low-level field squaring c=a^2 mod p in x64 assembly and C
void fpsqr256_a(dig256 a, dig256 c);
void fpsqr384_a(dig384 a, dig384 c);
void fpsqr512_a(dig512 a, dig512 c);

BOOL fpsqr256_c(dig256 a, dig256 c);
BOOL fpsqr384_c(dig384 a, dig384 c);
BOOL fpsqr512_c(dig512 a, dig512 c);

// Low-level subtraction a = modulus-a, or field negation, a = -a (mod p) if modulus=p, in x64 assembly and C
BOOL fpneg256_a(dig256 modulus, dig256 a);
BOOL fpneg384_a(dig384 modulus, dig384 a);
BOOL fpneg512_a(dig512 modulus, dig512 a);

BOOL fpneg256_c(dig256 modulus, dig256 a);
BOOL fpneg384_c(dig384 modulus, dig384 a);
BOOL fpneg512_c(dig512 modulus, dig512 a);

// Low-level field addition c = a+b mod p in x64 assembly and C
void fpadd256_a(dig256 a, dig256 b, dig256 c);
void fpadd384_a(dig384 a, dig384 b, dig384 c);
void fpadd512_a(dig512 a, dig512 b, dig512 c);

BOOL fpadd256_c(dig256 a, dig256 b, dig256 c);
BOOL fpadd384_c(dig384 a, dig384 b, dig384 c);
BOOL fpadd512_c(dig512 a, dig512 b, dig512 c);

// Low-level field subtraction c = a-b mod p in x64 assembly and C
void fpsub256_a(dig256 a, dig256 b, dig256 c);
void fpsub384_a(dig384 a, dig384 b, dig384 c);
void fpsub512_a(dig512 a, dig512 b, dig512 c);

BOOL fpsub256_c(dig256 a, dig256 b, dig256 c);
BOOL fpsub384_c(dig384 a, dig384 b, dig384 c);
BOOL fpsub512_c(dig512 a, dig512 b, dig512 c);

// Low-level field division by two c = a/2 mod p in x64 assembly and C
void fpdiv2_256_a(dig256 a, dig256 c);
void fpdiv2_384_a(dig384 a, dig384 c);
void fpdiv2_512_a(dig512 a, dig512 c);

BOOL fpdiv2_256_c(dig256 a, dig256 c);
BOOL fpdiv2_384_c(dig384 a, dig384 c);
BOOL fpdiv2_512_c(dig512 a, dig512 c);

// Low-level field zeroing in x64 assembly and C
void fpzero256_a(dig256 a);
void fpzero384_a(dig384 a);
void fpzero512_a(dig512 a);

BOOL fpzero256_c(dig256 a);
BOOL fpzero384_c(dig384 a);
BOOL fpzero512_c(dig512 a);

// Low-level field inversion, a = a^-1 mod p (= a^(p-2) mod p)
void fpinv256_fixedchain(dig256 a);
void fpinv384_fixedchain(dig384 a);
void fpinv512_fixedchain(dig512 a);


/********************** Generic modular operations and complementary functions ************************/

// Generic digit multiplication, c = a*b, where a,b in [0, 2^nbits-1], and nbits is the bitlength of a computer word or digit
BOOL dig_x_dig(dig a, dig b, dig* c);

// Modular addition, c = a+b mod modulus, where a,b,c in [0, modulus-1], lng{a,b,c,modulus} = nwords 
void mod_add(dig* a, dig* b, dig* c, dig* modulus, unsigned int nwords);

// Correction c = a (mod modulus), where a,modulus < 2^nbits
// This operation is intended for cases in which nbits and nbits_modulus are close
BOOL correction_mod(dig* a, dig* c, dig* modulus, unsigned int nbits_modulus, unsigned int nbits);

// Copy function dst <- src, where lng(dst) = lng(src) = nwords
void copy(dig* src, dig* dst, unsigned int nwords);

// Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit
unsigned char subtract(dig* a, dig* b, dig* c, unsigned int nwords);

// Compare elements a and b, where lng(a) = lng(b) = nwords
// If a = b then return TRUE, else return FALSE
BOOL compare(dig *a, dig *b, unsigned int nwords);

// Montgomery multiplication, mc = ma*mb*Rprime^(-1) mod modulus, where ma,mb,mc in [0, modulus-1], lng{ma,mb,mc,modulus} = nwords
// ma, mb are assumed to be in Montgomery representation
void Montgomery_multiply(dig* ma, dig* mb, dig* mc, dig* modulus, dig* Montgomery_rprime, unsigned int nwords);
// nwords is fixed and taken from the set {256/ML_WORD,384/ML_WORD,512/ML_WORD} for the following functions:
void Montgomery_multiply256(dig* ma, dig* mb, dig* mc, dig* modulus, dig* Montgomery_rprime, unsigned int nwords);
void Montgomery_multiply384(dig* ma, dig* mb, dig* mc, dig* modulus, dig* Montgomery_rprime, unsigned int nwords);
void Montgomery_multiply512(dig* ma, dig* mb, dig* mc, dig* modulus, dig* Montgomery_rprime, unsigned int nwords);

// Montgomery inversion, mc = ma^(-1) mod modulus, where ma,mc in [0, modulus-1], ma,mc,modulus < 2^nbits, nbits in {256,384,512}
// ma is assumed to be in Montgomery representation
void Montgomery_inversion256(dig256 ma, dig256 mc, dig256 modulus, dig256 Montgomery_rprime);
void Montgomery_inversion384(dig384 ma, dig384 mc, dig384 modulus, dig384 Montgomery_rprime);
void Montgomery_inversion512(dig512 ma, dig512 mc, dig512 modulus, dig512 Montgomery_rprime);

// Conversion to Montgomery representation, mc = a*Rprime mod modulus, where a,mc in [0, modulus-1], a,mc,modulus < 2^nbits, nbits in {256,384,512}
void toMontgomery256(dig256 a, dig256 mc, dig256 modulus, dig256 Montgomery_Rprime, dig256 Montgomery_rprime);
void toMontgomery384(dig384 a, dig384 mc, dig384 modulus, dig384 Montgomery_Rprime, dig384 Montgomery_rprime);
void toMontgomery512(dig512 a, dig512 mc, dig512 modulus, dig512 Montgomery_Rprime, dig512 Montgomery_rprime);

// Conversion from Montgomery, c = ma*1*Rprime^(-1) mod modulus, where ma,c in [0, modulus-1], ma,c,modulus < 2^nbits
// ma is assumed to be in Montgomery representation
void fromMontgomery256(dig256 ma, dig256 c, dig256 modulus, dig256 Montgomery_rprime);
void fromMontgomery384(dig384 ma, dig384 c, dig384 modulus, dig384 Montgomery_rprime);
void fromMontgomery512(dig512 ma, dig512 c, dig512 modulus, dig512 Montgomery_rprime);


/********** Curve functions ***********/

// SECURITY NOTE: the following functions are used for internal computations only and their correctness depends on the context 
//                in which they are used. 

// Check if curve structure is NULL
BOOL is_ecc_curve_null(PCurveStruct pCurve);

// Weierstrass a=-3 curves   

// "Complete" addition P = P+Q using mixed Jacobian-affine coordinates, Weierstrass a=-3 curve
void eccadd_mixed_jac_numsp256d1(point_numsp256d1 Q, point_jac_numsp256d1 P, point_jac_numsp256d1 *table, PCurveStruct JacCurve); 
void eccadd_mixed_jac_numsp384d1(point_numsp384d1 Q, point_jac_numsp384d1 P, point_jac_numsp384d1 *table, PCurveStruct JacCurve); 
void eccadd_mixed_jac_numsp512d1(point_numsp512d1 Q, point_jac_numsp512d1 P, point_jac_numsp512d1 *table, PCurveStruct JacCurve);  

// Point mixed addition P = P+Q using conditionals (if-statements), Weierstrass a=-3 curve
static void eccadd_mixed_jac_conditionals_numsp256d1(point_numsp256d1 Q, point_jac_numsp256d1 P, PCurveStruct JacCurve); 
static void eccadd_mixed_jac_conditionals_numsp384d1(point_numsp384d1 Q, point_jac_numsp384d1 P, PCurveStruct JacCurve); 
static void eccadd_mixed_jac_conditionals_numsp512d1(point_numsp512d1 Q, point_jac_numsp512d1 P, PCurveStruct JacCurve); 

// "Complete" addition P = P+Q, Weierstrass a=-3 curve. Table initialization is not included.
static void eccadd_jac_no_init_numsp256d1(point_jac_numsp256d1 Q, point_jac_numsp256d1 P, point_jac_numsp256d1 *table, PCurveStruct JacCurve); 
static void eccadd_jac_no_init_numsp384d1(point_jac_numsp384d1 Q, point_jac_numsp384d1 P, point_jac_numsp384d1 *table, PCurveStruct JacCurve); 
static void eccadd_jac_no_init_numsp512d1(point_jac_numsp512d1 Q, point_jac_numsp512d1 P, point_jac_numsp512d1 *table, PCurveStruct JacCurve); 

// Point doubling-addition P = 2P+Q using conditionals (if-statements), Weierstrass a=-3 curve
static void eccdoubleadd_jac_conditionals_numsp256d1(point_chu_precomp_numsp256d1 Q, point_jac_numsp256d1 P, PCurveStruct JacCurve);
static void eccdoubleadd_jac_conditionals_numsp384d1(point_chu_precomp_numsp384d1 Q, point_jac_numsp384d1 P, PCurveStruct JacCurve);
static void eccdoubleadd_jac_conditionals_numsp512d1(point_chu_precomp_numsp512d1 Q, point_jac_numsp512d1 P, PCurveStruct JacCurve); 

// Point doubling-addition P = 2P+Q using Jacobian coordinates, Weierstrass a=-3 curve
void eccdoubleadd_jac_numsp256d1(point_chu_precomp_numsp256d1 Q, point_jac_numsp256d1 P, PCurveStruct JacCurve);
void eccdoubleadd_jac_numsp384d1(point_chu_precomp_numsp384d1 Q, point_jac_numsp384d1 P, PCurveStruct JacCurve);
void eccdoubleadd_jac_numsp512d1(point_chu_precomp_numsp512d1 Q, point_jac_numsp512d1 P, PCurveStruct JacCurve);

// Special point addition R = P+Q with identical Z-coordinate for the precomputation, Weierstrass a=-3 curve
static void eccadd_jac_precomp_numsp256d1(point_jac_numsp256d1 P, point_chu_precomp_numsp256d1 Q, point_chu_precomp_numsp256d1 R);
static void eccadd_jac_precomp_numsp384d1(point_jac_numsp384d1 P, point_chu_precomp_numsp384d1 Q, point_chu_precomp_numsp384d1 R);
static void eccadd_jac_precomp_numsp512d1(point_jac_numsp512d1 P, point_chu_precomp_numsp512d1 Q, point_chu_precomp_numsp512d1 R);

// Precomputation scheme using Jacobian coordinates, Weierstrass a=-3 curve
void ecc_precomp_jac_numsp256d1(point_numsp256d1 P, point_chu_precomp_numsp256d1 *T, unsigned int npoints, PCurveStruct JacCurve);
void ecc_precomp_jac_numsp384d1(point_numsp384d1 P, point_chu_precomp_numsp384d1 *T, unsigned int npoints, PCurveStruct JacCurve);
void ecc_precomp_jac_numsp512d1(point_numsp512d1 P, point_chu_precomp_numsp512d1 *T, unsigned int npoints, PCurveStruct JacCurve);

// Constant-time table lookup to extract a Chudnovsky point from the precomputed table, Weierstrass a=-3 curve
void lut_chu_numsp256d1(point_chu_precomp_numsp256d1* table, point_chu_precomp_numsp256d1 P, int digit, unsigned int npoints, PCurveStruct JacCurve);
void lut_chu_numsp384d1(point_chu_precomp_numsp384d1* table, point_chu_precomp_numsp384d1 P, int digit, unsigned int npoints, PCurveStruct JacCurve);
void lut_chu_numsp512d1(point_chu_precomp_numsp512d1* table, point_chu_precomp_numsp512d1 P, int digit, unsigned int npoints, PCurveStruct JacCurve);

// Evaluation for the complete addition: determines the index for table lookup and the mask for element selections using complete_select_<NUMS_curve>
unsigned int complete_eval_numsp256d1(dig256 val1, dig256 val2, dig256 val3, dig *mask);
unsigned int complete_eval_numsp384d1(dig384 val1, dig384 val2, dig384 val3, dig *mask);
unsigned int complete_eval_numsp512d1(dig512 val1, dig512 val2, dig512 val3, dig *mask);
unsigned int complete_eval_numsp256d1_a(dig256 val1, dig256 val2, dig256 val3, dig *mask);
unsigned int complete_eval_numsp384d1_a(dig384 val1, dig384 val2, dig384 val3, dig *mask);
unsigned int complete_eval_numsp512d1_a(dig512 val1, dig512 val2, dig512 val3, dig *mask);

// Field element selection for the complete addition using mask
void complete_select_numsp256d1(dig256 in1, dig256 in2, dig256 out, dig mask);
void complete_select_numsp384d1(dig384 in1, dig384 in2, dig384 out, dig mask);
void complete_select_numsp512d1(dig512 in1, dig512 in2, dig512 out, dig mask);
void complete_select_numsp256d1_a(dig256 in1, dig256 in2, dig256 out, dig mask);
void complete_select_numsp384d1_a(dig384 in1, dig384 in2, dig384 out, dig mask);
void complete_select_numsp512d1_a(dig512 in1, dig512 in2, dig512 out, dig mask);

// Point extraction from 4-LUT for the complete addition
void complete_lut4_numsp256d1(point_jac_numsp256d1 *table, unsigned int index, point_jac_numsp256d1 P);
void complete_lut4_numsp384d1(point_jac_numsp384d1 *table, unsigned int index, point_jac_numsp384d1 P);
void complete_lut4_numsp512d1(point_jac_numsp512d1 *table, unsigned int index, point_jac_numsp512d1 P);
void complete_lut4_numsp256d1_a(point_jac_numsp256d1 *table, unsigned int index, point_jac_numsp256d1 P);
void complete_lut4_numsp384d1_a(point_jac_numsp384d1 *table, unsigned int index, point_jac_numsp384d1 P);
void complete_lut4_numsp512d1_a(point_jac_numsp512d1 *table, unsigned int index, point_jac_numsp512d1 P);

// Point extraction from 5-LUT for the complete addition
void complete_lut5_numsp256d1(point_jac_numsp256d1 *table, unsigned int index, point_jac_numsp256d1 P);
void complete_lut5_numsp384d1(point_jac_numsp384d1 *table, unsigned int index, point_jac_numsp384d1 P);
void complete_lut5_numsp512d1(point_jac_numsp512d1 *table, unsigned int index, point_jac_numsp512d1 P);
void complete_lut5_numsp256d1_a(point_jac_numsp256d1 *table, unsigned int index, point_jac_numsp256d1 P);
void complete_lut5_numsp384d1_a(point_jac_numsp384d1 *table, unsigned int index, point_jac_numsp384d1 P);
void complete_lut5_numsp512d1_a(point_jac_numsp512d1 *table, unsigned int index, point_jac_numsp512d1 P);

// Point extraction from n-LUT for the complete addition
void complete_lut_numsp256d1(point_jac_numsp256d1 *table, unsigned int index, point_jac_numsp256d1 P, unsigned int npoints);
void complete_lut_numsp384d1(point_jac_numsp384d1 *table, unsigned int index, point_jac_numsp384d1 P, unsigned int npoints);
void complete_lut_numsp512d1(point_jac_numsp512d1 *table, unsigned int index, point_jac_numsp512d1 P, unsigned int npoints);

// (Internal) fixed-base scalar multiplication Q = k.P, where P = P_table, using the Modified LSB-set method, Weierstrass a=-3 curve
ECCRYPTO_STATUS ecc_scalar_mul_fixed_internal_numsp256d1(point_numsp256d1 *P_table, dig *k, point_numsp256d1 Q, unsigned int w, unsigned int v, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_scalar_mul_fixed_internal_numsp384d1(point_numsp384d1 *P_table, dig *k, point_numsp384d1 Q, unsigned int w, unsigned int v, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_scalar_mul_fixed_internal_numsp512d1(point_numsp512d1 *P_table, dig *k, point_numsp512d1 Q, unsigned int w, unsigned int v, PCurveStruct JacCurve);

// (Internal) precomputation function using affine coordinates for fixed-base scalar multiplication, Weierstrass a=-3 curve
ECCRYPTO_STATUS ecc_precomp_fixed_internal_numsp256d1(point_numsp256d1 P, point_numsp256d1* P_table, unsigned int w, unsigned int v, unsigned int d, unsigned int e, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_precomp_fixed_internal_numsp384d1(point_numsp384d1 P, point_numsp384d1* P_table, unsigned int w, unsigned int v, unsigned int d, unsigned int e, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_precomp_fixed_internal_numsp512d1(point_numsp512d1 P, point_numsp512d1* P_table, unsigned int w, unsigned int v, unsigned int d, unsigned int e, PCurveStruct JacCurve);

// Constant-time table lookup to extract an affine point from the fixed-base precomputed table, Weierstrass a=-3 curve
void lut_aff_numsp256d1(point_numsp256d1* table, point_numsp256d1 P, int digit, int sign, unsigned int npoints, PCurveStruct JacCurve);
void lut_aff_numsp384d1(point_numsp384d1* table, point_numsp384d1 P, int digit, int sign, unsigned int npoints, PCurveStruct JacCurve);
void lut_aff_numsp512d1(point_numsp512d1* table, point_numsp512d1 P, int digit, int sign, unsigned int npoints, PCurveStruct JacCurve);

// (Internal) double-scalar multiplication R = k.P+l.Q, where P = P_table, using wNAF with Interleaving, Weierstrass a=-3 curve
ECCRYPTO_STATUS ecc_double_scalar_mul_internal_numsp256d1(point_numsp256d1 *P_table, dig *k, point_numsp256d1 Q, dig *l, point_numsp256d1 R, unsigned int w_P, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_double_scalar_mul_internal_numsp384d1(point_numsp384d1 *P_table, dig *k, point_numsp384d1 Q, dig *l, point_numsp384d1 R, unsigned int w_P, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_double_scalar_mul_internal_numsp512d1(point_numsp512d1 *P_table, dig *k, point_numsp512d1 Q, dig *l, point_numsp512d1 R, unsigned int w_P, PCurveStruct JacCurve);

// (Internal)  precomputation function using affine coordinates for the fixed-base of double-scalar multiplication, Weierstrass a=-3 curve
ECCRYPTO_STATUS ecc_precomp_dblmul_internal_numsp256d1(point_numsp256d1 P, point_numsp256d1* P_table, unsigned int w, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_precomp_dblmul_internal_numsp384d1(point_numsp384d1 P, point_numsp384d1* P_table, unsigned int w, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_precomp_dblmul_internal_numsp512d1(point_numsp512d1 P, point_numsp512d1* P_table, unsigned int w, PCurveStruct JacCurve);

// Additional functions based on macros

// Zeroing Chudnovsky point (X:Y:Z:Z^2:Z^3): P = (0:0:0:0:0)
#define ecczero_chu_numsp256d1(P);    fpzero256(P->X);  \
                                      fpzero256(P->Y);  \
                                      fpzero256(P->Z);  \
                                      fpzero256(P->Z2); \
                                      fpzero256(P->Z3); \

#define ecczero_chu_numsp384d1(P);    fpzero384(P->X);  \
                                      fpzero384(P->Y);  \
                                      fpzero384(P->Z);  \
                                      fpzero384(P->Z2); \
                                      fpzero384(P->Z3); \

#define ecczero_chu_numsp512d1(P);    fpzero512(P->X);  \
                                      fpzero512(P->Y);  \
                                      fpzero512(P->Z);  \
                                      fpzero512(P->Z2); \
                                      fpzero512(P->Z3); \

// Copy Chudnovsky point Q = (X:Y:Z:Z^2:Z^3) to P: P = Q
#define ecccopy_chu_numsp256d1(Q, P); fpcopy256(Q->X, P->X);   \
                                      fpcopy256(Q->Y, P->Y);   \
                                      fpcopy256(Q->Z, P->Z);   \
                                      fpcopy256(Q->Z2, P->Z2); \
                                      fpcopy256(Q->Z3, P->Z3); \

#define ecccopy_chu_numsp384d1(Q, P); fpcopy384(Q->X, P->X);   \
                                      fpcopy384(Q->Y, P->Y);   \
                                      fpcopy384(Q->Z, P->Z);   \
                                      fpcopy384(Q->Z2, P->Z2); \
                                      fpcopy384(Q->Z3, P->Z3); \

#define ecccopy_chu_numsp512d1(Q, P); fpcopy512(Q->X, P->X);   \
                                      fpcopy512(Q->Y, P->Y);   \
                                      fpcopy512(Q->Z, P->Z);   \
                                      fpcopy512(Q->Z2, P->Z2); \
                                      fpcopy512(Q->Z3, P->Z3); \


// Twisted Edwards a=1 curves

// (Internal) complete point addition P = P+Q or P = P+P using extended projective coordinates (X,Y,Z,Ta,Tb) for P and (X,Y,Z,d*T) for Q, twisted Edwards a=1 curve
STATIC_INLINE void eccadd_extproj_internal_numsp256t1(point_extproj_precomp_numsp256t1 Q, point_extproj_numsp256t1 P, PCurveStruct TedCurve);
STATIC_INLINE void eccadd_extproj_internal_numsp384t1(point_extproj_precomp_numsp384t1 Q, point_extproj_numsp384t1 P, PCurveStruct TedCurve);
STATIC_INLINE void eccadd_extproj_internal_numsp512t1(point_extproj_precomp_numsp512t1 Q, point_extproj_numsp512t1 P, PCurveStruct TedCurve);

// Complete mixed addition P = P+Q or P = P+P using mixed extended projective-affine coordinates, twisted Edwards a=1 curve
void eccadd_mixed_extproj_numsp256t1(point_extaff_precomp_numsp256t1 Q, point_extproj_numsp256t1 P, PCurveStruct TedCurve);
void eccadd_mixed_extproj_numsp384t1(point_extaff_precomp_numsp384t1 Q, point_extproj_numsp384t1 P, PCurveStruct TedCurve);
void eccadd_mixed_extproj_numsp512t1(point_extaff_precomp_numsp512t1 Q, point_extproj_numsp512t1 P, PCurveStruct TedCurve);

// Precomputation scheme using extended projective coordinates, twisted Edwards a=1 curve
void ecc_precomp_extproj_numsp256t1(point_extproj_numsp256t1 P, point_extproj_precomp_numsp256t1 *T, unsigned int npoints, PCurveStruct TedCurve);
void ecc_precomp_extproj_numsp384t1(point_extproj_numsp384t1 P, point_extproj_precomp_numsp384t1 *T, unsigned int npoints, PCurveStruct TedCurve);
void ecc_precomp_extproj_numsp512t1(point_extproj_numsp512t1 P, point_extproj_precomp_numsp512t1 *T, unsigned int npoints, PCurveStruct TedCurve);

// Constant-time table lookup to extract an extended projective point from the precomputed table, twisted Edwards a=1 curve (it does not use coordinates Ta, Tb)
void lut_extproj_numsp256t1(point_extproj_precomp_numsp256t1* table, point_extproj_precomp_numsp256t1 P, int digit, unsigned int npoints, PCurveStruct TedCurve);
void lut_extproj_numsp384t1(point_extproj_precomp_numsp384t1* table, point_extproj_precomp_numsp384t1 P, int digit, unsigned int npoints, PCurveStruct TedCurve);
void lut_extproj_numsp512t1(point_extproj_precomp_numsp512t1* table, point_extproj_precomp_numsp512t1 P, int digit, unsigned int npoints, PCurveStruct TedCurve);

// (Internal) fixed-base scalar multiplication Q = k.P, where P = P_table, using affine coordinates and the Modified LSB-set method, twisted Edwards a=1 curve
ECCRYPTO_STATUS ecc_scalar_mul_fixed_internal_numsp256t1(point_extaff_precomp_numsp256t1 *P_table, dig *k, point_numsp256t1 Q, unsigned int w, unsigned int v, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_scalar_mul_fixed_internal_numsp384t1(point_extaff_precomp_numsp384t1 *P_table, dig *k, point_numsp384t1 Q, unsigned int w, unsigned int v, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_scalar_mul_fixed_internal_numsp512t1(point_extaff_precomp_numsp512t1 *P_table, dig *k, point_numsp512t1 Q, unsigned int w, unsigned int v, PCurveStruct TedCurve);

// (Internal) precomputation function using extended affine coordinates for fixed-base scalar multiplication, twisted Edwards a=1 curve
ECCRYPTO_STATUS ecc_precomp_fixed_internal_numsp256t1(point_numsp256t1 P, point_extaff_precomp_numsp256t1* P_table, unsigned int w, unsigned int v, unsigned int d, unsigned int e, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_precomp_fixed_internal_numsp384t1(point_numsp384t1 P, point_extaff_precomp_numsp384t1* P_table, unsigned int w, unsigned int v, unsigned int d, unsigned int e, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_precomp_fixed_internal_numsp512t1(point_numsp512t1 P, point_extaff_precomp_numsp512t1* P_table, unsigned int w, unsigned int v, unsigned int d, unsigned int e, PCurveStruct TedCurve);

// Constant-time table lookup to extract an extended affine point from the fixed-base precomputed table, twisted Edwards a=1 curve
void lut_extaff_numsp256t1(point_extaff_precomp_numsp256t1* table, point_extaff_precomp_numsp256t1 P, int digit, int sign, unsigned int npoints, PCurveStruct TedCurve);
void lut_extaff_numsp384t1(point_extaff_precomp_numsp384t1* table, point_extaff_precomp_numsp384t1 P, int digit, int sign, unsigned int npoints, PCurveStruct TedCurve);
void lut_extaff_numsp512t1(point_extaff_precomp_numsp512t1* table, point_extaff_precomp_numsp512t1 P, int digit, int sign, unsigned int npoints, PCurveStruct TedCurve);

// (Internal) double-scalar multiplication R = k.P+l.Q, where P = P_table, using wNAF with Interleaving, twisted Edwards a=1 curve
ECCRYPTO_STATUS ecc_double_scalar_mul_internal_numsp256t1(point_extaff_precomp_numsp256t1 *P_table, dig *k, point_numsp256t1 Q, dig *l, point_numsp256t1 R, unsigned int w_P, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_double_scalar_mul_internal_numsp384t1(point_extaff_precomp_numsp384t1 *P_table, dig *k, point_numsp384t1 Q, dig *l, point_numsp384t1 R, unsigned int w_P, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_double_scalar_mul_internal_numsp512t1(point_extaff_precomp_numsp512t1 *P_table, dig *k, point_numsp512t1 Q, dig *l, point_numsp512t1 R, unsigned int w_P, PCurveStruct TedCurve);

// (Internal) precomputation function using extended affine coordinates for the fixed-base of double-scalar multiplication, twisted Edwards a=1 curve
ECCRYPTO_STATUS ecc_precomp_dblmul_internal_numsp256t1(point_numsp256t1 P, point_extaff_precomp_numsp256t1* P_table, unsigned int w_P, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_precomp_dblmul_internal_numsp384t1(point_numsp384t1 P, point_extaff_precomp_numsp384t1* P_table, unsigned int w_P, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_precomp_dblmul_internal_numsp512t1(point_numsp512t1 P, point_extaff_precomp_numsp512t1* P_table, unsigned int w_P, PCurveStruct TedCurve);

// Additional functions based on macros

// Zeroing extended projective point (X,Y,Z,d*T): P = (0,0,0,0)
#define ecczero_extproj_precomp_numsp256t1(P); fpzero256(P->X);  \
                                               fpzero256(P->Y);  \
                                               fpzero256(P->Z);  \
                                               fpzero256(P->Td); \

#define ecczero_extproj_precomp_numsp384t1(P); fpzero384(P->X);  \
                                               fpzero384(P->Y);  \
                                               fpzero384(P->Z);  \
                                               fpzero384(P->Td); \

#define ecczero_extproj_precomp_numsp512t1(P); fpzero512(P->X);  \
                                               fpzero512(P->Y);  \
                                               fpzero512(P->Z);  \
                                               fpzero512(P->Td); \
                                           
// Zeroing extended affine point (x,y,d*t): P = (0,0,0)
#define ecczero_extaff_precomp_numsp256t1(P); fpzero256(P->x);   \
                                              fpzero256(P->y);   \
                                              fpzero256(P->td);  \

#define ecczero_extaff_precomp_numsp384t1(P); fpzero384(P->x);   \
                                              fpzero384(P->y);   \
                                              fpzero384(P->td);  \

#define ecczero_extaff_precomp_numsp512t1(P); fpzero512(P->x);   \
                                              fpzero512(P->y);   \
                                              fpzero512(P->td);  \

// Copy extended affine point Q = (x,y,dt) to P: P = Q
#define ecccopy_extaff_numsp256t1(Q, P); fpcopy256(Q->x, P->x);  \
                                         fpcopy256(Q->y, P->y);  \
                                         fpcopy256(Q->td, P->td);\

#define ecccopy_extaff_numsp384t1(Q, P); fpcopy384(Q->x, P->x);  \
                                         fpcopy384(Q->y, P->y);  \
                                         fpcopy384(Q->td, P->td);\

#define ecccopy_extaff_numsp512t1(Q, P); fpcopy512(Q->x, P->x);  \
                                         fpcopy512(Q->y, P->y);  \
                                         fpcopy512(Q->td, P->td);\

// Copy extended projective point Q = (X:Y:Z:Td) to P: P = Q
#define ecccopy_extproj2_numsp256t1(Q, P); fpcopy256(Q->X, P->X);  \
                                           fpcopy256(Q->Y, P->Y);  \
                                           fpcopy256(Q->Z, P->Z);  \
                                           fpcopy256(Q->Td, P->Td);\

#define ecccopy_extproj2_numsp384t1(Q, P); fpcopy384(Q->X, P->X);  \
                                           fpcopy384(Q->Y, P->Y);  \
                                           fpcopy384(Q->Z, P->Z);  \
                                           fpcopy384(Q->Td, P->Td);\

#define ecccopy_extproj2_numsp512t1(Q, P); fpcopy512(Q->X, P->X);  \
                                           fpcopy512(Q->Y, P->Y);  \
                                           fpcopy512(Q->Z, P->Z);  \
                                           fpcopy512(Q->Td, P->Td);\


// Internal cryptographic functions

// (Internal) ECDSA signature generation with input for the random nonce. The public function that generates the random nonce internally (called ecdsa_sign_<curve>) can be found in msr_ecclib.h 
// It computes the signature (r,s) of a message m using as inputs a private key pPrivateKey, the generator table pTableGen, the hash of the message m HashedMessage with its byte-length and a random nonce RandomNonce
// The set of valid values for the bitlength of HashedMessage is {256,384,512}
ECCRYPTO_STATUS ecdsa_sign_internal_numsp256d1(dig256 pPrivateKey, point_numsp256d1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig256 RandomNonce, dig256 r, dig256 s, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_sign_internal_numsp384d1(dig384 pPrivateKey, point_numsp384d1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig384 RandomNonce, dig384 r, dig384 s, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_sign_internal_numsp512d1(dig512 pPrivateKey, point_numsp512d1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig512 RandomNonce, dig512 r, dig512 s, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_sign_internal_numsp256t1(dig256 pPrivateKey, point_extaff_precomp_numsp256t1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig256 RandomNonce, dig256 r, dig256 s, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecdsa_sign_internal_numsp384t1(dig384 pPrivateKey, point_extaff_precomp_numsp384t1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig384 RandomNonce, dig384 r, dig384 s, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecdsa_sign_internal_numsp512t1(dig512 pPrivateKey, point_extaff_precomp_numsp512t1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig512 RandomNonce, dig512 r, dig512 s, PCurveStruct TedCurve);


// Recoding functions

void fixed_window_recode(dig *scalar, unsigned int nbit, unsigned int w, int *digits);
void mLSB_set_recode(dig *scalar, unsigned int nbit, unsigned int l, unsigned int d, int *digits);
void wNAF_recode(dig *scalar, unsigned int nbits, unsigned int w, int *digits);


// Format conversion functions

// Convert nbits of inarray from bytes to digit in little endian
ECCRYPTO_STATUS bytes_to_digits_little_endian(unsigned char* inarray, dig* outarray, dig nbits);


#ifdef __cplusplus
}
#endif

#endif
