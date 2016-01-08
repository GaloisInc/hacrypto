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
* Abstract: main header file
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
******************************************************************************/  

#ifndef __MSR_ECCLIB_H__
#define __MSR_ECCLIB_H__

// For C++
#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>


// Definition of operative system

#define OS_WIN       1
#define OS_LINUX     2

#if defined(__WINDOWS__)     // Microsoft Windows OS
    #define OS_TARGET OS_WIN
#elif defined(__LINUX__)     // Linux OS
    #define OS_TARGET OS_LINUX  
#else
    #error -- "Unknown OS"
#endif


// Definition of compiler

#define COMPILER_VC      1
#define COMPILER_GCC     2

#if defined(_MSC_VER)        // Microsoft Visual C compiler
    #define COMPILER COMPILER_VC
#elif defined(__GNUC__)      // GNU GCC compiler
    #define COMPILER COMPILER_GCC   
#else
    #error -- "Unknown COMPILER"
#endif


// Definition of the targeted architecture and basic data types. "dig" and "sdig" 
// are data types for representing unsigned and signed computer words, respectively.
    
#define TARGET_AMD64     1
#define TARGET_x86       2
#define TARGET_ARM       3

#if defined(_AMD64_)
    #define TARGET TARGET_AMD64
    #define RADIX  64
    typedef uint64_t dig;       // unsigned 64-bit digit
    typedef int64_t  sdig;      // signed 64-bit digit
#elif defined(_X86_)
    #define TARGET TARGET_x86
    #define RADIX  32
    typedef uint32_t dig;       // unsigned 32-bit digit
    typedef int32_t  sdig;      // signed 32-bit digit
#elif defined(_ARM_)
    #define TARGET TARGET_ARM
    #define RADIX  32
    typedef uint32_t dig;       // unsigned 32-bit digit
    typedef int32_t  sdig;      // signed 32-bit digit
#else
    #error -- "Unknown ARCHITECTURE"
#endif


// Instruction support

#if (TARGET == TARGET_AMD64 || TARGET == TARGET_x86)
    #if defined(_AVX_)
        #define AVX_SUPPORT    // AVX support selection 
    #endif
#endif

#if (TARGET == TARGET_AMD64 && OS_TARGET == OS_LINUX)
    typedef unsigned uint128_t __attribute__((mode(TI)));
#endif
    

// Some useful macro definitions

typedef int BOOL; 
#ifndef TRUE
    #define TRUE 1
#endif
#ifndef FALSE
    #define FALSE 0
#endif

#ifndef NULL
    #define NULL ((void *)0)
#endif

#define NBITS_TO_NWORDS(nbits)    (((nbits)+(sizeof(dig)*8)-1)/(sizeof(dig)*8))    // Conversion macro from number of bytes to number of computer words


// Definitions of the error-handling type and error codes

typedef enum {
    ECCRYPTO_ERROR,                            // 0x00
    ECCRYPTO_SUCCESS,                          // 0x01
    ECCRYPTO_ERROR_DURING_TEST,                // 0x02
    ECCRYPTO_ERROR_UNKNOWN,                    // 0x03
    ECCRYPTO_ERROR_NOT_IMPLEMENTED,            // 0x04
    ECCRYPTO_ERROR_NO_MEMORY,                  // 0x05
    ECCRYPTO_ERROR_INVALID_PARAMETER,          // 0x06
    ECCRYPTO_ERROR_INVALID_NONCE_FOR_SIGNING,  // 0x07
    ECCRYPTO_ERROR_SHARED_KEY,                 // 0x08
    ECCRYPTO_ERROR_SIGNATURE_VERIFICATION,     // 0x09
    ECCRYPTO_ERROR_TOO_MANY_ITERATIONS,        // 0x0A
    ECCRYPTO_ERROR_END_OF_LIST
} ECCRYPTO_STATUS;

#define ECCRYPTO_STATUS_TYPE_SIZE (ECCRYPTO_ERROR_END_OF_LIST)


// Definitions of the error messages
// NOTE: they must match the error codes above

#define ECCRYPTO_MSG_ERROR                                  "ECCRYPTO_ERROR"
#define ECCRYPTO_MSG_SUCCESS                                "ECCRYPTO_SUCCESS"
#define ECCRYPTO_MSG_ERROR_DURING_TEST                      "ECCRYPTO_ERROR_DURING_TEST"
#define ECCRYPTO_MSG_ERROR_UNKNOWN                          "ECCRYPTO_ERROR_UNKNOWN"
#define ECCRYPTO_MSG_ERROR_NOT_IMPLEMENTED                  "ECCRYPTO_ERROR_NOT_IMPLEMENTED"
#define ECCRYPTO_MSG_ERROR_NO_MEMORY                        "ECCRYPTO_ERROR_NO_MEMORY"
#define ECCRYPTO_MSG_ERROR_INVALID_PARAMETER                "ECCRYPTO_ERROR_INVALID_PARAMETER"
#define ECCRYPTO_MSG_ERROR_INVALID_NONCE_FOR_SIGNING        "ECCRYPTO_ERROR_INVALID_NONCE_FOR_SIGNING"
#define ECCRYPTO_MSG_ERROR_SHARED_KEY                       "ECCRYPTO_ERROR_SHARED_KEY"
#define ECCRYPTO_MSG_ERROR_SIGNATURE_VERIFICATION           "ECCRYPTO_ERROR_SIGNATURE_VERIFICATION"
#define ECCRYPTO_MSG_ERROR_TOO_MANY_ITERATIONS              "ECCRYPTO_ERROR_TOO_MANY_ITERATIONS"


// Select supported bitlengths (security levels)

#define ECCURVES_256
#define ECCURVES_384
#define ECCURVES_512


// Define if zeroing of temporaries in low-level functions is desired
//#define TEMP_ZEROING


// Definition of operation type targeted for precomputation

typedef enum {
    OP_FIXEDBASE,
    OP_DOUBLESCALAR,
    OP_END_OF_LIST    // List size indicator
} OpType;

#define OpTypeSize (OP_END_OF_LIST)


// Definition of memory footprint type for precomputed tables in the scalar multiplication

typedef enum {
    MEM_DEFAULT,
    MEM_COMPACT,
    MEM_LARGE,
    MEM_END_OF_LIST    // List size indicator
} MemType;

#define MemTypeSize (MEM_END_OF_LIST)


// Window width for variable-base precomputed table in variable-base scalar multiplication and double-scalar multiplication

#define W_VARBASE         5    // Memory requirement: 2.5KB for numsp256d1, 3.75KB for numsp384d1 and 5KB for numsp512d1 
                               //                     2KB for numsp256t1, 3KB for numsp384t1 and 4KB for numsp512t1 


// Window width for fixed-base precomputed table in fixed-base scalar multiplication

#define W_MEM_LARGE       6    // Memory requirement: 6KB for numsp256d1, 9KB for numsp384d1 and 12KB for numsp512d1 
#define V_MEM_LARGE       3    //                     9KB for numsp256t1, 13.5KB for numsp384t1 and 18KB for numsp512t1 

#define W_MEM_COMPACT_W   3    // Memory requirement: 768 bytes for numsp256d1, 1.125KB for numsp384d1 and 1.5KB for numsp512d1 
#define V_MEM_COMPACT_W   3    //                       

#define W_MEM_COMPACT_TE  2    // Memory requirement: 384 bytes for numsp256t1, 576 bytes for numsp384t1 and 768 bytes for numsp512t1 
#define V_MEM_COMPACT_TE  2    //                      


// Window width for fixed-base precomputed table in double-scalar multiplication

#define W_P_MEM_LARGE     7    // Memory requirement: 2KB for numsp256d1, 3KB for numsp384d1 and 4KB for numsp512d1 
                               //                     3KB for numsp256t1, 4.5KB for numsp384t1 and 6KB for numsp512t1 

#define W_P_MEM_COMPACT   2    // Memory requirement: 64 bytes for numsp256d1, 96 bytes for numsp384d1 and 128 bytes for numsp512d1 
                               //                     96 bytes for numsp256t1, 128 bytes for numsp384t1 and 192 bytes for numsp512t1 


// Basic parameters for supported curves

#define MAXBITLENGTH    512                                 // Max. field bitlength supported
#define ML_WORD         (sizeof(dig)*8)                     // Number of bits in a computer word
#define MAXWORDS_FIELD  NBITS_TO_NWORDS(MAXBITLENGTH)       // Max. number of words needed to represent supported fields
#define MAXBYTES_FIELD  ((MAXBITLENGTH+7)/8)                // Max. number of bytes needed to represent supported fields
#define MAXPOINTS       64                                  // Max. number of precomputed points for variable-base scalar multiplication
#define WMAX            8                                   // Max. window size (number of rows) for fixed-base scalar multiplication
#define VMAX            8                                   // Max. table size (number of tables) for fixed-base scalar multiplication


// Definition of data types for multi-precision field elements

#define ML_WORDS256 NBITS_TO_NWORDS(256)                    // Number of words to represent 256-bit field elements or elements in Z_r
#define ML_WORDS384 NBITS_TO_NWORDS(384)                    // Number of words to represent 384-bit field elements or elements in Z_r
#define ML_WORDS512 NBITS_TO_NWORDS(512)                    // Number of words to represent 512-bit field elements or elements in Z_r

typedef dig dig256[ML_WORDS256];                            // Multiprecision type to represent 256-bit field elements or elements in Z_r
typedef dig dig384[ML_WORDS384];                            // Multiprecision type to represent 384-bit field elements or elements in Z_r
typedef dig dig512[ML_WORDS512];                            // Multiprecision type to represent 512-bit field elements or elements in Z_r


// Types for point representations for Weierstrass a=-3 curve "numsp256d1"  
typedef struct { dig256 X; dig256 Y; dig256 Z; } point_jac_numsp256d1t;                // Point representation in Jacobian coordinates (X:Y:Z) such that x = X/Z^2, y = Y/Z^3.
typedef point_jac_numsp256d1t point_jac_numsp256d1[1];                                                              
typedef struct { dig256 x; dig256 y; } point_numsp256d1t;                              // Point representation in affine coordinates (x,y).
typedef point_numsp256d1t point_numsp256d1[1];                                               

// Types for point representations for twisted Edwards a=1 curve "numsp256t1"
typedef struct { dig256 X; dig256 Y; dig256 Z; dig256 Ta; dig256 Tb; } point_extproj_numsp256t1t; // Point representation in homogeneous coordinates (X:Y:Z:Ta:Tb) such that
typedef point_extproj_numsp256t1t point_extproj_numsp256t1[1];                                    // x = X/Z, y = Y/Z, T = Ta*Tb = X*Y/Z.
typedef struct { dig256 x; dig256 y; dig256 td; } point_extaff_precomp_numsp256t1t;               // Point representation in affine coordinates (x,y,2dt) (used for precomputed points).
typedef point_extaff_precomp_numsp256t1t point_extaff_precomp_numsp256t1[1];  
typedef struct { dig256 x; dig256 y; } point_numsp256t1t;                                         // Point representation in affine coordinates (x,y)
typedef point_numsp256t1t point_numsp256t1[1]; 


// Types for point representations for Weierstrass a=-3 curve "numsp384d1" 
typedef struct { dig384 X; dig384 Y; dig384 Z; } point_jac_numsp384d1t;                // Point representation in Jacobian coordinates (X:Y:Z) such that x = X/Z^2, y = Y/Z^3.
typedef point_jac_numsp384d1t point_jac_numsp384d1[1];                                                                 
typedef struct { dig384 x; dig384 y; } point_numsp384d1t;                              // Point representation in affine coordinates (x,y).
typedef point_numsp384d1t point_numsp384d1[1];                                               

// Types for point representations for twisted Edwards a=1 curve "numsp384t1"
typedef struct { dig384 X; dig384 Y; dig384 Z; dig384 Ta; dig384 Tb; } point_extproj_numsp384t1t; // Point representation in homogeneous coordinates (X:Y:Z:Ta:Tb) such that
typedef point_extproj_numsp384t1t point_extproj_numsp384t1[1];                                    // x = X/Z, y = Y/Z, T = Ta*Tb = X*Y/Z.
typedef struct { dig384 x; dig384 y; dig384 td; } point_extaff_precomp_numsp384t1t;               // Point representation in affine coordinates (x,y,dt) (used for precomputed points).
typedef point_extaff_precomp_numsp384t1t point_extaff_precomp_numsp384t1[1];  
typedef struct { dig384 x; dig384 y; } point_numsp384t1t;                                         // Point representation in affine coordinates (x,y)
typedef point_numsp384t1t point_numsp384t1[1]; 


// Types for point representations for Weierstrass a=-3 curve "numsp512d1"    
typedef struct { dig512 X; dig512 Y; dig512 Z; } point_jac_numsp512d1t;                // Point representation in Jacobian coordinates (X:Y:Z) such that x = X/Z^2, y = Y/Z^3.
typedef point_jac_numsp512d1t point_jac_numsp512d1[1];                                                                    
typedef struct { dig512 x; dig512 y; } point_numsp512d1t;                              // Point representation in affine coordinates (x,y).
typedef point_numsp512d1t point_numsp512d1[1];                                               

// Types for point representations for twisted Edwards a=1 curve "numsp512t1"
typedef struct { dig512 X; dig512 Y; dig512 Z; dig512 Ta; dig512 Tb; } point_extproj_numsp512t1t; // Point representation in homogeneous coordinates (X:Y:Z:Ta:Tb) such that
typedef point_extproj_numsp512t1t point_extproj_numsp512t1[1];                                    // x = X/Z, y = Y/Z, T = Ta*Tb = X*Y/Z.
typedef struct { dig512 x; dig512 y; dig512 td; } point_extaff_precomp_numsp512t1t;               // Point representation in affine coordinates (x,y,dt) (used for precomputed points).
typedef point_extaff_precomp_numsp512t1t point_extaff_precomp_numsp512t1[1];  
typedef struct { dig512 x; dig512 y; } point_numsp512t1t;                                         // Point representation in affine coordinates (x,y)
typedef point_numsp512t1t point_numsp512t1[1];


// Definition of type random_bytes to implement callback functions outputting "nbytes" random values to "random_array"
typedef ECCRYPTO_STATUS (*RandomBytes)(unsigned int nbytes, unsigned char* random_array);


// Curve IDs of supported curves
typedef enum
{
    numsp256d1,        // NUMS Weierstrass curves
    numsp384d1,
    numsp512d1,
    numsp256t1,        // NUMS twisted Edwards curves
    numsp384t1,
    numsp512t1
} Curve_ID;


// Elliptic curve structures:

// This data struct is for the static curve data
typedef struct
{    
    Curve_ID         Curve;                             // Curve ID, curve defined over GF(prime)  
    unsigned int     nbits;                             // Two times the targeted security level 
    unsigned int     rbits;                             // Bitlength of the order of the curve (sub)group 
    unsigned int     pbits;                             // Bitlength of the prime 
    unsigned char    prime[MAXBYTES_FIELD];             // Prime
    unsigned char    parameter1[MAXBYTES_FIELD];        // Curve parameter ("a" for Weierstrass, "a" for twisted Edwards)
    unsigned char    parameter2[MAXBYTES_FIELD];        // Curve parameter ("b" for Weierstrass, "d" for twisted Edwards)
    unsigned char    order[MAXBYTES_FIELD];             // Prime order of the curve (sub)group 
    unsigned char    generator_x[MAXBYTES_FIELD];       // x-coordinate of generator
    unsigned char    generator_y[MAXBYTES_FIELD];       // y-coordinate of generator
    unsigned int     cofactor;                          // Co-factor of the curve group
    unsigned char    Rprime[MAXBYTES_FIELD];            // (2^W)^2 mod r, where r is the order and W is in {256,384,512}
    unsigned char    rprime[MAXBYTES_FIELD];            // -(r^-1) mod 2^W
} CurveStaticData, *PCurveStaticData;

// This data struct is for bitlength-specific curve data that is initialized during the curve setup
typedef struct
{
    Curve_ID         Curve;                             // Curve ID, curve defined over GF(prime)  
    unsigned int     nbits;                             // Two times the targeted security level 
    unsigned int     rbits;                             // Bitlength of the order of the curve (sub)group 
    unsigned int     pbits;                             // Bitlength of the prime 
    dig*             prime;                             // Prime
    dig*             parameter1;                        // Curve parameter ("a" for Weierstrass, "a" for twisted Edwards)
    dig*             parameter2;                        // Curve parameter ("b" for Weierstrass, "d" for twisted Edwards)
    dig*             order;                             // Prime order of the curve (sub)group 
    dig*             generator_x;                       // x-coordinate of generator
    dig*             generator_y;                       // y-coordinate of generator
    unsigned int     cofactor;                          // Co-factor of the curve 
    unsigned int     w_fixedbase;                       // Parameter w for fixed-base scalar multiplication
    unsigned int     v_fixedbase;                       // Parameter v for fixed-base scalar multiplication
    unsigned int     w_doublescalar;                    // Window width w for double-scalar multiplication
    dig*             Rprime;                            // (2^W)^2 mod r, where r is the order and W is in {256,384,512}
    dig*             rprime;                            // -(r^-1) mod 2^W
    RandomBytes      RandomBytesFunction;               // Function providing random bytes to generate nonces or secret keys
} CurveStruct, *PCurveStruct;


// Supported curves:

// "numsp256d1": Weierstrass curve a=-3, E: y^2 = x^3 - 3x + 152961, p = 2^256-189
extern CurveStaticData curve_numsp256d1;

// "numsp256t1": twisted Edwards curve a=1, E: x^2 + y^2 = 1 - 15342x^2y^2, p = 2^256-189
extern CurveStaticData curve_numsp256t1;

// "numsp384d1": Weierstrass curve a=-3, E: y^2 = x^3 - 3x - 34568, p = 2^384-317
extern CurveStaticData curve_numsp384d1;

// "numsp384t1": twisted Edwards curve a=1, E: x^2 + y^2 = 1 - 11556x^2y^2, p = 2^384-317
extern CurveStaticData curve_numsp384t1;

// "numsp512d1": Weierstrass curve a=-3, E: y^2 = x^3 - 3x + 121243, p = 2^512-569
extern CurveStaticData curve_numsp512d1;

// "numsp512t1": twisted Edwards curve a=1, E: x^2 + y^2 = 1 - 78296x^2y^2, p = 2^512-569
extern CurveStaticData curve_numsp512t1;



/*************************** Function prototypes *****************************/

/********** Field functions ***********/

// Copy of a field element, c = a 
void fpcopy256(dig256 a, dig256 c);
void fpcopy384(dig384 a, dig384 c);
void fpcopy512(dig512 a, dig512 c);

// Zero a field element, a=0 
void fpzero256(dig256 a);
void fpzero384(dig384 a);
void fpzero512(dig512 a);

// Is field element zero, a=0?  
BOOL fp_iszero256(dig256 a);
BOOL fp_iszero384(dig384 a);
BOOL fp_iszero512(dig512 a);

// Field multiplication c=a*b mod p
void fpmul256(dig256 a, dig256 b, dig256 c);
void fpmul384(dig384 a, dig384 b, dig384 c);
void fpmul512(dig512 a, dig512 b, dig512 c);

// Field squaring c=a^2 mod p
void fpsqr256(dig256 a, dig256 c);
void fpsqr384(dig384 a, dig384 c);
void fpsqr512(dig512 a, dig512 c);

// Field inversion, a = a^-1 mod p (= a^(p-2) mod p)
void fpinv256(dig256 a);
void fpinv384(dig384 a);
void fpinv512(dig512 a);

// Subtraction a = modulus-a, or field negation, a = -a (mod p) if modulus=p
BOOL fpneg256(dig256 modulus, dig256 a);
BOOL fpneg384(dig384 modulus, dig384 a);
BOOL fpneg512(dig512 modulus, dig512 a);

// Evaluate if an element is in [0, modulus-1]
BOOL mod_eval256(dig256 a, dig256 modulus);
BOOL mod_eval384(dig384 a, dig384 modulus);
BOOL mod_eval512(dig512 a, dig512 modulus);

// Field addition, c = a+b mod p
void fpadd256(dig256 a, dig256 b, dig256 c);
void fpadd384(dig384 a, dig384 b, dig384 c);
void fpadd512(dig512 a, dig512 b, dig512 c);

// Field subtraction, c = a-b mod p
void fpsub256(dig256 a, dig256 b, dig256 c);
void fpsub384(dig384 a, dig384 b, dig384 c);
void fpsub512(dig512 a, dig512 b, dig512 c);

// Field division by 2, c = a/2 mod p
void fpdiv2_256(dig256 a, dig256 c);
void fpdiv2_384(dig384 a, dig384 c);
void fpdiv2_512(dig512 a, dig512 c);


/*************************** Operations modulo the order r of a curve *****************************/

// Addition modulo the order, c = a+b mod r, where a,b,c in [0, r-1]
void addition_mod_order(dig* a, dig* b, dig* c, PCurveStruct PCurve);

// Modular correction using the order of a curve, c = a mod r, where a,r < 2^nbits 
BOOL correction_mod_order(dig* a, dig* c, PCurveStruct PCurve);

// Compare elements a and b, where a,b in [1, r-1]
// If a = b then return TRUE, else return FALSE
BOOL compare_mod_order(dig *a, dig *b, PCurveStruct PCurve);

// Output random values in the range [1, order-1] that can be used as nonces or private keys.
// It makes requests of random values with length "rbits" to the "random_bytes" function, which should be provided by the caller. The process repeats until random value is in [0, order-2].
// If successful, the output is given in "random_digits" in the range [1, order-1].
// The "random_bytes" function, which is passed through the curve structure PCurve, should be set up in advance using ecc_curve_initialize(). 
// It follows the procedure in "Digital Signature Standard (DSS), FIPS.186-4" (see App. B.4.2 and B.5.2) to generate nonces and private keys.
ECCRYPTO_STATUS random_mod_order(dig* random_digits, PCurveStruct PCurve);

// Montgomery multiplication modulo the order, mc = ma*mb*Rprime^(-1) mod r, where ma,mb,mc in [0, r-1], ma,mb,mc,r < 2^nbits, nbits in {256,384,512}
// ma, mb are assumed to be in Montgomery representation
void Montgomery_multiply_mod_order256(dig256 ma, dig256 mb, dig256 mc, PCurveStruct PCurve);
void Montgomery_multiply_mod_order384(dig384 ma, dig384 mb, dig384 mc, PCurveStruct PCurve);
void Montgomery_multiply_mod_order512(dig512 ma, dig512 mb, dig512 mc, PCurveStruct PCurve);

// Montgomery inversion modulo the order, mc = ma^(-1) mod r, where ma,mc in [0, r-1], ma,mc,r < 2^nbits, nbits in {256,384,512}
// ma is assumed to be in Montgomery representation
void Montgomery_inversion_mod_order256(dig256 ma, dig256 mc, PCurveStruct PCurve);
void Montgomery_inversion_mod_order384(dig384 ma, dig384 mc, PCurveStruct PCurve);
void Montgomery_inversion_mod_order512(dig512 ma, dig512 mc, PCurveStruct PCurve);

// Conversion to Montgomery representation modulo the order, mc = a*Rprime mod r, where a,mc in [0, r-1], a,mc,r < 2^nbits, nbits in {256,384,512}
void toMontgomery_mod_order256(dig256 a, dig256 mc, PCurveStruct PCurve);
void toMontgomery_mod_order384(dig384 a, dig384 mc, PCurveStruct PCurve);
void toMontgomery_mod_order512(dig512 a, dig512 mc, PCurveStruct PCurve);

// Conversion from Montgomery modulo the order, c = ma*1*Rprime^(-1) mod r, where ma,c in [0, r-1], ma,c,r < 2^nbits, nbits in {256,384,512}
// ma is assumed to be in Montgomery representation
void fromMontgomery_mod_order256(dig256 ma, dig256 c, PCurveStruct PCurve);
void fromMontgomery_mod_order384(dig384 ma, dig384 c, PCurveStruct PCurve);
void fromMontgomery_mod_order512(dig512 ma, dig512 c, PCurveStruct PCurve);


/********** Main curve functions ***********/

// NOTE: (Most of) the following functions accept input/output points in standard affine representation (x,y).
//       These are the functions that are commonly required by most ECC protocols. 

// Initialize curve structure pCurve with static data from pCurveData
ECCRYPTO_STATUS ecc_curve_initialize(PCurveStruct pCurve, MemType memory_use, RandomBytes RandomBytesFunction, PCurveStaticData pCurveData);

// Dynamic allocation of memory for curve structure
PCurveStruct ecc_curve_allocate(PCurveStaticData CurveData);

// Free memory for curve structure
void ecc_curve_free(PCurveStruct pCurve);

// Output error/success message for a given ECCRYPTO_STATUS 
const char* ecc_get_error_message(ECCRYPTO_STATUS Status);

// Weierstrass a=-3 curves

// Set generator P = (x,y) on Weierstrass a=-3 curve
void eccset_numsp256d1(point_numsp256d1 P, PCurveStruct JacCurve);
void eccset_numsp384d1(point_numsp384d1 P, PCurveStruct JacCurve);
void eccset_numsp512d1(point_numsp512d1 P, PCurveStruct JacCurve);

// Check if point P = (x,y) on Weierstrass a=-3 curve is the point at infinity (0,0)
BOOL ecc_is_infinity_numsp256d1(point_numsp256d1 P, PCurveStruct JacCurve);
BOOL ecc_is_infinity_numsp384d1(point_numsp384d1 P, PCurveStruct JacCurve);
BOOL ecc_is_infinity_numsp512d1(point_numsp512d1 P, PCurveStruct JacCurve);

// Variable-base scalar multiplication Q = k.P using fixed-window method, Weierstrass a=-3 curve
// P is the input point and k is the scalar
ECCRYPTO_STATUS ecc_scalar_mul_numsp256d1(point_numsp256d1 P, dig *k, point_numsp256d1 Q, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_scalar_mul_numsp384d1(point_numsp384d1 P, dig *k, point_numsp384d1 Q, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_scalar_mul_numsp512d1(point_numsp512d1 P, dig *k, point_numsp512d1 Q, PCurveStruct JacCurve);

// Fixed-base scalar multiplication Q = k.P, where P = P_table, using the Modified LSB-set method, Weierstrass a=-3 curve
// P_table is the input point table and k is the scalar. P_table is precalculated by calling ecc_precomp_fixed_<NUMS_curve>
// The size of P_table is determined during initialization with ecc_curve_initialize
ECCRYPTO_STATUS ecc_scalar_mul_fixed_numsp256d1(point_numsp256d1 *P_table, dig *k, point_numsp256d1 Q, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_scalar_mul_fixed_numsp384d1(point_numsp384d1 *P_table, dig *k, point_numsp384d1 Q, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_scalar_mul_fixed_numsp512d1(point_numsp512d1 *P_table, dig *k, point_numsp512d1 Q, PCurveStruct JacCurve);

// Function that computes the precomputed table "P_table" to be used by fixed-base scalar multiplications ecc_scalar_mul_fixed_<NUMS_curve>
// P is the input point used to create the table
// The size of P_table is determined during initialization with ecc_curve_initialize
ECCRYPTO_STATUS ecc_precomp_fixed_numsp256d1(point_numsp256d1 P, point_numsp256d1* P_table, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_precomp_fixed_numsp384d1(point_numsp384d1 P, point_numsp384d1* P_table, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_precomp_fixed_numsp512d1(point_numsp512d1 P, point_numsp512d1* P_table, PCurveStruct JacCurve);

// Double-scalar multiplication R = k.P+l.Q, where P = P_table, using wNAF with Interleaving, Weierstrass a=-3 curve
// P_table is the fixed-base input point table, with corresponding scalar k, and Q is the variable-base input point, with corresponding scalar l
// P_table is precalculated by calling ecc_precomp_dblmul_<NUMS_curve>
// The size of P_table is determined during initialization with ecc_curve_initialize
ECCRYPTO_STATUS ecc_double_scalar_mul_numsp256d1(point_numsp256d1 *P_table, dig *k, point_numsp256d1 Q, dig *l, point_numsp256d1 R, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_double_scalar_mul_numsp384d1(point_numsp384d1 *P_table, dig *k, point_numsp384d1 Q, dig *l, point_numsp384d1 R, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_double_scalar_mul_numsp512d1(point_numsp512d1 *P_table, dig *k, point_numsp512d1 Q, dig *l, point_numsp512d1 R, PCurveStruct JacCurve);

// Function that outputs the precomputed table "P_table" to be used by double-scalar multiplications ecc_double_scalar_mul_<NUMS_curve>
// P is the input point used to create the table
// The size of P_table is determined during initialization with ecc_curve_initialize
ECCRYPTO_STATUS ecc_precomp_dblmul_numsp256d1(point_numsp256d1 P, point_numsp256d1* P_table, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_precomp_dblmul_numsp384d1(point_numsp384d1 P, point_numsp384d1* P_table, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_precomp_dblmul_numsp512d1(point_numsp512d1 P, point_numsp512d1* P_table, PCurveStruct JacCurve);

// Allocates dynamically memory for precomputation table used during fixed-base or double-scalar multiplications.
// This function must be called before using a table generated by ecc_precomp_fixed_<NUMS_curve> or ecc_precomp_dblmul_<NUMS_curve>. 
point_numsp256d1* ecc_allocate_precomp_numsp256d1(OpType scalarmultype, PCurveStruct JacCurve);
point_numsp384d1* ecc_allocate_precomp_numsp384d1(OpType scalarmultype, PCurveStruct JacCurve);
point_numsp512d1* ecc_allocate_precomp_numsp512d1(OpType scalarmultype, PCurveStruct JacCurve);

// Main functions based on macros

// Copy point Q = (x,y) to P: P = Q
#define ecccopy_numsp256d1(Q, P); fpcopy256(Q->x, P->x);  \
                                  fpcopy256(Q->y, P->y);  \

#define ecccopy_numsp384d1(Q, P); fpcopy384(Q->x, P->x);  \
                                  fpcopy384(Q->y, P->y);  \

#define ecccopy_numsp512d1(Q, P); fpcopy512(Q->x, P->x);  \
                                  fpcopy512(Q->y, P->y);  \

// Zeroing point (x,y): P = (0,0)
#define ecczero_numsp256d1(P);    fpzero256(P->x);  \
                                  fpzero256(P->y);  \

#define ecczero_numsp384d1(P);    fpzero384(P->x);  \
                                  fpzero384(P->y);  \

#define ecczero_numsp512d1(P);    fpzero512(P->x);  \
                                  fpzero512(P->y);  \


// Twisted Edwards a=1 curves

// Set generator P = (x,y) on twisted Edwards a=1 curve
void eccset_numsp256t1(point_numsp256t1 P, PCurveStruct TedCurve);
void eccset_numsp384t1(point_numsp384t1 P, PCurveStruct TedCurve);
void eccset_numsp512t1(point_numsp512t1 P, PCurveStruct TedCurve);

// Check if point P = (x,y) on twisted Edwards a=1 curve is the neutral point (0,1) 
BOOL ecc_is_neutral_numsp256t1(point_numsp256t1 P, PCurveStruct TedCurve);
BOOL ecc_is_neutral_numsp384t1(point_numsp384t1 P, PCurveStruct TedCurve);
BOOL ecc_is_neutral_numsp512t1(point_numsp512t1 P, PCurveStruct TedCurve);

// Variable-base scalar multiplication Q = k.P using fixed-window method, twisted Edwards a=1 curve
// P is the input point and k is the scalar
ECCRYPTO_STATUS ecc_scalar_mul_numsp256t1(point_numsp256t1 P, dig *k, point_numsp256t1 Q, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_scalar_mul_numsp384t1(point_numsp384t1 P, dig *k, point_numsp384t1 Q, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_scalar_mul_numsp512t1(point_numsp512t1 P, dig *k, point_numsp512t1 Q, PCurveStruct TedCurve);

// Fixed-base scalar multiplication Q = k.P, where P = P_table, using the Modified LSB-set method, twisted Edwards a=1 curve
// P_table is the input point table and k is the scalar. P_table is precalculated by calling ecc_precomp_fixed_<NUMS_curve>
// The size of P_table is determined during initialization with ecc_curve_initialize
ECCRYPTO_STATUS ecc_scalar_mul_fixed_numsp256t1(point_extaff_precomp_numsp256t1 *P_table, dig *k, point_numsp256t1 Q, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_scalar_mul_fixed_numsp384t1(point_extaff_precomp_numsp384t1 *P_table, dig *k, point_numsp384t1 Q, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_scalar_mul_fixed_numsp512t1(point_extaff_precomp_numsp512t1 *P_table, dig *k, point_numsp512t1 Q, PCurveStruct TedCurve);

// Function that computes the precomputed table "P_table" to be used by fixed-base scalar multiplications ecc_scalar_mul_fixed_<NUMS_curve>
// P is the input point used to create the table
// The size of P_table is determined during initialization with ecc_curve_initialize
ECCRYPTO_STATUS ecc_precomp_fixed_numsp256t1(point_numsp256t1 P, point_extaff_precomp_numsp256t1* P_table, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_precomp_fixed_numsp384t1(point_numsp384t1 P, point_extaff_precomp_numsp384t1* P_table, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_precomp_fixed_numsp512t1(point_numsp512t1 P, point_extaff_precomp_numsp512t1* P_table, PCurveStruct TedCurve);

// Double-scalar multiplication R = k.P+l.Q, where P = P_table, using wNAF with Interleaving, twisted Edwards a=1 curve
// P_table is the fixed-base input point table, with corresponding scalar k, and Q is the variable-base input point, with corresponding scalar l
// P_table is precalculated by calling ecc_precomp_dblmul_<NUMS_curve>
// The size of P_table is determined during initialization with ecc_curve_initialize
ECCRYPTO_STATUS ecc_double_scalar_mul_numsp256t1(point_extaff_precomp_numsp256t1 *P_table, dig *k, point_numsp256t1 Q, dig *l, point_numsp256t1 R, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_double_scalar_mul_numsp384t1(point_extaff_precomp_numsp384t1 *P_table, dig *k, point_numsp384t1 Q, dig *l, point_numsp384t1 R, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_double_scalar_mul_numsp512t1(point_extaff_precomp_numsp512t1 *P_table, dig *k, point_numsp512t1 Q, dig *l, point_numsp512t1 R, PCurveStruct TedCurve);

// Function that outputs the precomputed table "P_table" to be used by double-scalar multiplications ecc_double_scalar_mul_<NUMS_curve>
// P is the input point used to create the table
// The size of P_table is determined during initialization with ecc_curve_initialize
ECCRYPTO_STATUS ecc_precomp_dblmul_numsp256t1(point_numsp256t1 P, point_extaff_precomp_numsp256t1* P_table, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_precomp_dblmul_numsp384t1(point_numsp384t1 P, point_extaff_precomp_numsp384t1* P_table, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_precomp_dblmul_numsp512t1(point_numsp512t1 P, point_extaff_precomp_numsp512t1* P_table, PCurveStruct TedCurve);

// Allocates dynamically memory for precomputation table used during fixed-base or double-scalar multiplications.
// This function must be called before using a table generated by ecc_precomp_fixed_<NUMS_curve> or ecc_precomp_dblmul_<NUMS_curve>. 
point_extaff_precomp_numsp256t1* ecc_allocate_precomp_numsp256t1(OpType scalarmultype, PCurveStruct TedCurve);
point_extaff_precomp_numsp384t1* ecc_allocate_precomp_numsp384t1(OpType scalarmultype, PCurveStruct TedCurve);
point_extaff_precomp_numsp512t1* ecc_allocate_precomp_numsp512t1(OpType scalarmultype, PCurveStruct TedCurve);

// Main functions based on macros

// Copy point Q = (x,y) to P: P = Q
#define ecccopy_numsp256t1(Q, P)  ecccopy_numsp256d1(Q, P) 
#define ecccopy_numsp384t1(Q, P)  ecccopy_numsp384d1(Q, P) 
#define ecccopy_numsp512t1(Q, P)  ecccopy_numsp512d1(Q, P)

// Zeroing point (x,y): P = (0,0)
#define ecczero_numsp256t1(P)     ecczero_numsp256d1(P) 
#define ecczero_numsp384t1(P)     ecczero_numsp384d1(P) 
#define ecczero_numsp512t1(P)     ecczero_numsp512d1(P) 



/********** Additional curve functions ***********/

// NOTE: the following functions also accept input/output points in some projective coordinate system (X:Y:Z) or variants.
//       These functions can be needed in some special cases in which access to projective coordinates is required.   

// Weierstrass a=-3 curves

// Copy Jacobian point (X:Y:Z) on Weierstrass a=-3 curve, P = Q
void ecccopy_jac_numsp256d1(point_jac_numsp256d1 Q, point_jac_numsp256d1 P, PCurveStruct JacCurve);
void ecccopy_jac_numsp384d1(point_jac_numsp384d1 Q, point_jac_numsp384d1 P, PCurveStruct JacCurve);
void ecccopy_jac_numsp512d1(point_jac_numsp512d1 Q, point_jac_numsp512d1 P, PCurveStruct JacCurve);

// Check if Jacobian point P = (X:Y:Z) on Weierstrass a=-3 curve is the point at infinity (0:Y:0)
BOOL ecc_is_infinity_jac_numsp256d1(point_jac_numsp256d1 P, PCurveStruct JacCurve);
BOOL ecc_is_infinity_jac_numsp384d1(point_jac_numsp384d1 P, PCurveStruct JacCurve);
BOOL ecc_is_infinity_jac_numsp512d1(point_jac_numsp512d1 P, PCurveStruct JacCurve);

// Normalize a Jacobian point Q = (X:Y:Z) -> P = (x,y)
void eccnorm_numsp256d1(point_jac_numsp256d1 Q, point_numsp256d1 P, PCurveStruct JacCurve);
void eccnorm_numsp384d1(point_jac_numsp384d1 Q, point_numsp384d1 P, PCurveStruct JacCurve);
void eccnorm_numsp512d1(point_jac_numsp512d1 Q, point_numsp512d1 P, PCurveStruct JacCurve);

// Point doubling P = 2P using Jacobian coordinates (X:Y:Z), Weierstrass a=-3 curve
void eccdouble_jac_numsp256d1(point_jac_numsp256d1 P, PCurveStruct JacCurve);
void eccdouble_jac_numsp384d1(point_jac_numsp384d1 P, PCurveStruct JacCurve);
void eccdouble_jac_numsp512d1(point_jac_numsp512d1 P, PCurveStruct JacCurve);

// "Complete" addition P = P+Q using Jacobian coordinates (X:Y:Z), Weierstrass a=-3 curve
void eccadd_jac_numsp256d1(point_jac_numsp256d1 Q, point_jac_numsp256d1 P, PCurveStruct JacCurve); 
void eccadd_jac_numsp384d1(point_jac_numsp384d1 Q, point_jac_numsp384d1 P, PCurveStruct JacCurve); 
void eccadd_jac_numsp512d1(point_jac_numsp512d1 Q, point_jac_numsp512d1 P, PCurveStruct JacCurve);

// Additional functions based on macros

// Copy Jacobian point Q = (X:Y:Z) to P: P = Q
#define ecccopy_jac_numsp256d1(Q, P); fpcopy256(Q->X, P->X);  \
                                      fpcopy256(Q->Y, P->Y);  \
                                      fpcopy256(Q->Z, P->Z);  \

#define ecccopy_jac_numsp384d1(Q, P); fpcopy384(Q->X, P->X);  \
                                      fpcopy384(Q->Y, P->Y);  \
                                      fpcopy384(Q->Z, P->Z);  \

#define ecccopy_jac_numsp512d1(Q, P); fpcopy512(Q->X, P->X);  \
                                      fpcopy512(Q->Y, P->Y);  \
                                      fpcopy512(Q->Z, P->Z);  \

// Zeroing Jacobian point (X:Y:Z): P = (0:0:0)
#define ecczero_jac_numsp256d1(P);    fpzero256(P->X);  \
                                      fpzero256(P->Y);  \
                                      fpzero256(P->Z);  \

#define ecczero_jac_numsp384d1(P);    fpzero384(P->X);  \
                                      fpzero384(P->Y);  \
                                      fpzero384(P->Z);  \

#define ecczero_jac_numsp512d1(P);    fpzero512(P->X);  \
                                      fpzero512(P->Y);  \
                                      fpzero512(P->Z);  \

// Convert affine point Q = (x,y) to Jacobian P = (X:Y:1), where X=x, Y=y
#define eccconvert_aff_to_jac_numsp256d1(Q, P); fpcopy256(Q->x, P->X);        \
                                                fpcopy256(Q->y, P->Y);        \
                                                fpzero256(P->Z); P->Z[0] = 1; \
                              
#define eccconvert_aff_to_jac_numsp384d1(Q, P); fpcopy384(Q->x, P->X);        \
                                                fpcopy384(Q->y, P->Y);        \
                                                fpzero384(P->Z); P->Z[0] = 1; \

#define eccconvert_aff_to_jac_numsp512d1(Q, P); fpcopy512(Q->x, P->X);        \
                                                fpcopy512(Q->y, P->Y);        \
                                                fpzero512(P->Z); P->Z[0] = 1; \

// Twisted Edwards a=1 curves

// Copy extended projective point on twisted Edwards a=1 curve using projective coordinates (X:Y:Z:Ta:Tb), P = Q
void ecccopy_extproj_numsp256t1(point_extproj_numsp256t1 Q, point_extproj_numsp256t1 P, PCurveStruct TedCurve);
void ecccopy_extproj_numsp384t1(point_extproj_numsp384t1 Q, point_extproj_numsp384t1 P, PCurveStruct TedCurve);
void ecccopy_extproj_numsp512t1(point_extproj_numsp512t1 Q, point_extproj_numsp512t1 P, PCurveStruct TedCurve);

// Check if extended projective point P = (X:Y:Z:Ta:Tb) on twisted Edwards a=1 curve is the neutral point (0:1:1) 
BOOL ecc_is_neutral_extproj_numsp256t1(point_extproj_numsp256t1 P, PCurveStruct TedCurve);
BOOL ecc_is_neutral_extproj_numsp384t1(point_extproj_numsp384t1 P, PCurveStruct TedCurve);
BOOL ecc_is_neutral_extproj_numsp512t1(point_extproj_numsp512t1 P, PCurveStruct TedCurve);

// Normalize a twisted Edwards point Q = (X:Y:Z) -> P = (x,y)
void eccnorm_numsp256t1(point_extproj_numsp256t1 Q, point_numsp256t1 P, PCurveStruct TedCurve);
void eccnorm_numsp384t1(point_extproj_numsp384t1 Q, point_numsp384t1 P, PCurveStruct TedCurve);
void eccnorm_numsp512t1(point_extproj_numsp512t1 Q, point_numsp512t1 P, PCurveStruct TedCurve);

// Point doubling 2P using extended projective coordinates (X:Y:Z:Ta:Tb), twisted Edwards a=1 curve
void eccdouble_extproj_numsp256t1(point_extproj_numsp256t1 P, PCurveStruct TedCurve);
void eccdouble_extproj_numsp384t1(point_extproj_numsp384t1 P, PCurveStruct TedCurve);
void eccdouble_extproj_numsp512t1(point_extproj_numsp512t1 P, PCurveStruct TedCurve);

// Complete point addition P = P+Q or P = P+P using extended projective coordinates (X:Y:Z:Ta:Tb), twisted Edwards a=1 curve
void eccadd_extproj_numsp256t1(point_extproj_numsp256t1 Q, point_extproj_numsp256t1 P, PCurveStruct TedCurve);
void eccadd_extproj_numsp384t1(point_extproj_numsp384t1 Q, point_extproj_numsp384t1 P, PCurveStruct TedCurve);
void eccadd_extproj_numsp512t1(point_extproj_numsp512t1 Q, point_extproj_numsp512t1 P, PCurveStruct TedCurve);

// Additional functions based on macros

// Copy extended projective point Q = (X:Y:Z:Ta:Tb) to P: P = Q
#define ecccopy_extproj_numsp256t1(Q, P); fpcopy256(Q->X, P->X);  \
                                          fpcopy256(Q->Y, P->Y);  \
                                          fpcopy256(Q->Z, P->Z);  \
                                          fpcopy256(Q->Ta, P->Ta);\
                                          fpcopy256(Q->Tb, P->Tb);\

#define ecccopy_extproj_numsp384t1(Q, P); fpcopy384(Q->X, P->X);  \
                                          fpcopy384(Q->Y, P->Y);  \
                                          fpcopy384(Q->Z, P->Z);  \
                                          fpcopy384(Q->Ta, P->Ta);\
                                          fpcopy384(Q->Tb, P->Tb);\

#define ecccopy_extproj_numsp512t1(Q, P); fpcopy512(Q->X, P->X);  \
                                          fpcopy512(Q->Y, P->Y);  \
                                          fpcopy512(Q->Z, P->Z);  \
                                          fpcopy512(Q->Ta, P->Ta);\
                                          fpcopy512(Q->Tb, P->Tb);\

// Zeroing extended projective point (X:Y:Z:Ta:Tb): P = (0:0:0:0:0)
#define ecczero_extproj_numsp256t1(P); fpzero256(P->X);  \
                                       fpzero256(P->Y);  \
                                       fpzero256(P->Z);  \
                                       fpzero256(P->Ta); \
                                       fpzero256(P->Tb); \

#define ecczero_extproj_numsp384t1(P); fpzero384(P->X);  \
                                       fpzero384(P->Y);  \
                                       fpzero384(P->Z);  \
                                       fpzero384(P->Ta); \
                                       fpzero384(P->Tb); \

#define ecczero_extproj_numsp512t1(P); fpzero512(P->X);  \
                                       fpzero512(P->Y);  \
                                       fpzero512(P->Z);  \
                                       fpzero512(P->Ta); \
                                       fpzero512(P->Tb); \

// Convert affine point Q = (x,y) to extended projective P = (X:Y:1:Ta:Tb), where X=x, Y=y, Ta=x, Ty=y
#define eccconvert_aff_to_extproj_numsp256t1(Q, P); fpcopy256(Q->x, P->X);        \
                                                    fpcopy256(Q->y, P->Y);        \
                                                    fpzero256(P->Z); P->Z[0] = 1; \
                                                    fpcopy256(Q->x, P->Ta);       \
                                                    fpcopy256(Q->y, P->Tb);       \
                              
#define eccconvert_aff_to_extproj_numsp384t1(Q, P); fpcopy384(Q->x, P->X);        \
                                                    fpcopy384(Q->y, P->Y);        \
                                                    fpzero384(P->Z); P->Z[0] = 1; \
                                                    fpcopy384(Q->x, P->Ta);       \
                                                    fpcopy384(Q->y, P->Tb);       \

#define eccconvert_aff_to_extproj_numsp512t1(Q, P); fpcopy512(Q->x, P->X);        \
                                                    fpcopy512(Q->y, P->Y);        \
                                                    fpzero512(P->Z); P->Z[0] = 1; \
                                                    fpcopy512(Q->x, P->Ta);       \
                                                    fpcopy512(Q->y, P->Tb);       \



/********** Cryptographic functions ***********/

// Integer encoding:
// ----------------
// Imported and exported integer values (i.e., keys and coordinate values) are represented as n-bit digits using the datatypes "dig256", "dig384" and 
// "dig512" for n=256, 384 and 512, respectively. Each n-bit digit consists of a fixed number of computer words (words use the datatype "dig"), and 
// each computer word is interpreted as octets in little endian format (i.e., the least significant octet is stored in the lowest address). The total   
// number of octets in an n-bit digit is given by n/8.
// For example:
//
//             the 256-bit coordinate value 0x696F1853C1E466D7FC82C96CCEEEDD6BD02C2F9375894EC10BF46306C2B56C77 is represented with (04) computer words
//             in a 64-bit computer in little endian format as:
//             {0x0BF46306C2B56C77, 0xD02C2F9375894EC1, 0xFC82C96CCEEEDD6B, 0x696F1853C1E466D7}
//             Consequently, its encoding in little endian format containing 32 octets is
//             {77, 6C, B5, C2, 06, 63, F4, 0B, C1, 4E, 89, 75, 93, 2F, 2C, D0, 6B, DD, EE, CE, 6C, C9, 82, FC, D7, 66, E4, C1, 53, 18, 6F, 69},
//             where 77 is stored in the lowest byte-address and 69 is stored in the highest byte-address. 
//
// 
// Point encoding:
// ----------------
// Imported and exported elliptic curve points with coordinates (x,y) are encoded as {x || y}, where each coordinate value uses the integer encoding
// above in little endian format. 
//
// See sample.c for an example on the key/point formatting.


// Computes precomputed table pTableGen for the generator
// The output pTableGen contains the generator G and several of its multiples: 3*G, 5*G, ..., n*G
ECCRYPTO_STATUS ecc_generator_table_numsp256d1(point_numsp256d1* pTableGen, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_generator_table_numsp384d1(point_numsp384d1* pTableGen, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_generator_table_numsp512d1(point_numsp512d1* pTableGen, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_generator_table_numsp256t1(point_extaff_precomp_numsp256t1* pTableGen, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_generator_table_numsp384t1(point_extaff_precomp_numsp384t1* pTableGen, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_generator_table_numsp512t1(point_extaff_precomp_numsp512t1* pTableGen, PCurveStruct TedCurve);

// Public key generation using a private key as input
// It computes the public key pPublicKey = pPrivateKey*G, where G is the generator (G and its multiples are passed through pTableGen)
ECCRYPTO_STATUS ecc_keygen_numsp256d1(dig256 pPrivateKey, point_numsp256d1* pTableGen, point_numsp256d1 pPublicKey, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_keygen_numsp384d1(dig384 pPrivateKey, point_numsp384d1* pTableGen, point_numsp384d1 pPublicKey, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_keygen_numsp512d1(dig512 pPrivateKey, point_numsp512d1* pTableGen, point_numsp512d1 pPublicKey, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_keygen_numsp256t1(dig256 pPrivateKey, point_extaff_precomp_numsp256t1* pTableGen, point_numsp256t1 pPublicKey, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_keygen_numsp384t1(dig384 pPrivateKey, point_extaff_precomp_numsp384t1* pTableGen, point_numsp384t1 pPublicKey, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_keygen_numsp512t1(dig512 pPrivateKey, point_extaff_precomp_numsp512t1* pTableGen, point_numsp512t1 pPublicKey, PCurveStruct TedCurve);

// Key-pair generation
// It produces a private key pPrivateKey and computes the public key pPublicKey = pPrivateKey*G, where G is the generator (G and its multiples are passed through pTableGen)
ECCRYPTO_STATUS ecc_full_keygen_numsp256d1(point_numsp256d1* pTableGen, dig256 pPrivateKey, point_numsp256d1 pPublicKey, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_full_keygen_numsp384d1(point_numsp384d1* pTableGen, dig384 pPrivateKey, point_numsp384d1 pPublicKey, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_full_keygen_numsp512d1(point_numsp512d1* pTableGen, dig512 pPrivateKey, point_numsp512d1 pPublicKey, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecc_full_keygen_numsp256t1(point_extaff_precomp_numsp256t1* pTableGen, dig256 pPrivateKey, point_numsp256t1 pPublicKey, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_full_keygen_numsp384t1(point_extaff_precomp_numsp384t1* pTableGen, dig384 pPrivateKey, point_numsp384t1 pPublicKey, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecc_full_keygen_numsp512t1(point_extaff_precomp_numsp512t1* pTableGen, dig512 pPrivateKey, point_numsp512t1 pPublicKey, PCurveStruct TedCurve);

// Secret agreement computation for the ECDH(E) key exchange
// It computes the shared secret key pSecretAgreement = X(pPrivateKey*pPublicKey), where X() denotes the x-coordinate of an EC point
ECCRYPTO_STATUS ecdh_secret_agreement_numsp256d1(dig256 pPrivateKey, point_numsp256d1 pPublicKey, dig256 pSecretAgreement, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdh_secret_agreement_numsp384d1(dig384 pPrivateKey, point_numsp384d1 pPublicKey, dig384 pSecretAgreement, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdh_secret_agreement_numsp512d1(dig512 pPrivateKey, point_numsp512d1 pPublicKey, dig512 pSecretAgreement, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdh_secret_agreement_numsp256t1(dig256 pPrivateKey, point_numsp256t1 pPublicKey, dig256 pSecretAgreement, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecdh_secret_agreement_numsp384t1(dig384 pPrivateKey, point_numsp384t1 pPublicKey, dig384 pSecretAgreement, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecdh_secret_agreement_numsp512t1(dig512 pPrivateKey, point_numsp512t1 pPublicKey, dig512 pSecretAgreement, PCurveStruct TedCurve);

// ECDSA signature generation
// It computes the signature (r,s) of a message m using as inputs a private key pPrivateKey, the generator table pTableGen, and the hash of the message m HashedMessage with its byte-length
// The set of valid values for the bitlength of HashedMessage is {256,384,512}
ECCRYPTO_STATUS ecdsa_sign_numsp256d1(dig256 pPrivateKey, point_numsp256d1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig256 r, dig256 s, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_sign_numsp384d1(dig384 pPrivateKey, point_numsp384d1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig384 r, dig384 s, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_sign_numsp512d1(dig512 pPrivateKey, point_numsp512d1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig512 r, dig512 s, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_sign_numsp256t1(dig256 pPrivateKey, point_extaff_precomp_numsp256t1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig256 r, dig256 s, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecdsa_sign_numsp384t1(dig384 pPrivateKey, point_extaff_precomp_numsp384t1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig384 r, dig384 s, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecdsa_sign_numsp512t1(dig512 pPrivateKey, point_extaff_precomp_numsp512t1* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig512 r, dig512 s, PCurveStruct TedCurve);

// Computes precomputed table pTableVer for the ECDSA signature verification
// The output pTableVer contains the generator G and several of its multiples: 3*G, 5*G, ..., n*G
ECCRYPTO_STATUS ecdsa_verification_table_numsp256d1(point_numsp256d1* pTableVer, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_verification_table_numsp384d1(point_numsp384d1* pTableVer, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_verification_table_numsp512d1(point_numsp512d1* pTableVer, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_verification_table_numsp256t1(point_extaff_precomp_numsp256t1* pTableVer, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecdsa_verification_table_numsp384t1(point_extaff_precomp_numsp384t1* pTableVer, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecdsa_verification_table_numsp512t1(point_extaff_precomp_numsp512t1* pTableVer, PCurveStruct TedCurve);

// ECDSA signature verification
// It verifies the validity of the signature (r,s) of a message m using as inputs the generator table pTableVer, a public key pPublicKey and the hash of the message m HashedMessage with its byte-length
// If the signature is valid, then valid = TRUE, otherwise valid = FALSE
ECCRYPTO_STATUS ecdsa_verify_numsp256d1(point_numsp256d1* pTableVer, point_numsp256d1 pPublicKey, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig256 r, dig256 s, BOOL* valid, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_verify_numsp384d1(point_numsp384d1* pTableVer, point_numsp384d1 pPublicKey, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig384 r, dig384 s, BOOL* valid, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_verify_numsp512d1(point_numsp512d1* pTableVer, point_numsp512d1 pPublicKey, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig512 r, dig512 s, BOOL* valid, PCurveStruct JacCurve);
ECCRYPTO_STATUS ecdsa_verify_numsp256t1(point_extaff_precomp_numsp256t1* pTableVer, point_numsp256t1 pPublicKey, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig256 r, dig256 s, BOOL* valid, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecdsa_verify_numsp384t1(point_extaff_precomp_numsp384t1* pTableVer, point_numsp384t1 pPublicKey, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig384 r, dig384 s, BOOL* valid, PCurveStruct TedCurve);
ECCRYPTO_STATUS ecdsa_verify_numsp512t1(point_extaff_precomp_numsp512t1* pTableVer, point_numsp512t1 pPublicKey, unsigned char* HashedMessage, unsigned int SizeHashedMessage, dig512 r, dig512 s, BOOL* valid, PCurveStruct TedCurve);


#ifdef __cplusplus
}
#endif

#endif