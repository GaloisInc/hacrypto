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
* Abstract: additional curve, field and recoding functions
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
******************************************************************************/  

#include <malloc.h>
#include "msr_ecclib.h"
#include "msr_ecclib_priv.h"
#if (TARGET == TARGET_AMD64 || TARGET == TARGET_x86)
    #include <immintrin.h>
#endif


ECCRYPTO_STATUS ecc_curve_initialize(PCurveStruct pCurve, MemType memory_use, RandomBytes RandomBytesFunction, PCurveStaticData pCurveData)
{ // Initialize curve structure pCurve with static data extracted from pCurveData
    unsigned int w_fixed = 0, v_fixed = 0, w_doublescalar = 0, e, nbits;

    if (is_ecc_curve_null(pCurve) || pCurveData == NULL || pCurveData->prime == NULL || pCurveData->parameter1 == NULL || pCurveData->parameter2 == NULL || 
        pCurveData->order == NULL || pCurveData->generator_x == NULL || pCurveData->generator_y == NULL || pCurveData->Rprime == NULL || pCurveData->rprime == NULL) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    nbits = pCurveData->nbits;

    if (memory_use == MEM_LARGE) {
        w_doublescalar = W_P_MEM_LARGE;
        w_fixed = W_MEM_LARGE;
        v_fixed = V_MEM_LARGE;
    } else if (memory_use == MEM_COMPACT) {
        w_doublescalar = W_P_MEM_COMPACT;
        if (pCurveData->Curve == numsp256d1 || pCurveData->Curve == numsp384d1 || pCurveData->Curve == numsp512d1) {
            w_fixed = W_MEM_COMPACT_W;
            v_fixed = V_MEM_COMPACT_W;
        } else {
            w_fixed = W_MEM_COMPACT_TE;
            v_fixed = V_MEM_COMPACT_TE;
        }
    } else {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    e = (pCurveData->rbits + w_fixed*v_fixed - 1)/(w_fixed*v_fixed);
    if (pCurveData->rbits - e*w_fixed*v_fixed == 0) {                 // This parameter selection is not allowed
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    pCurve->Curve = pCurveData->Curve;
    pCurve->nbits = pCurveData->nbits;
    pCurve->rbits = pCurveData->rbits;
    pCurve->pbits = pCurveData->pbits;
    pCurve->cofactor = pCurveData->cofactor;
    pCurve->w_fixedbase = w_fixed;
    pCurve->v_fixedbase = v_fixed;
    pCurve->w_doublescalar = w_doublescalar;
    pCurve->RandomBytesFunction = RandomBytesFunction;

    bytes_to_digits_little_endian(pCurveData->prime, pCurve->prime, nbits);
    bytes_to_digits_little_endian(pCurveData->parameter1, pCurve->parameter1, nbits);
    bytes_to_digits_little_endian(pCurveData->parameter2, pCurve->parameter2, nbits);
    bytes_to_digits_little_endian(pCurveData->order, pCurve->order, nbits);
    bytes_to_digits_little_endian(pCurveData->generator_x, pCurve->generator_x, nbits);
    bytes_to_digits_little_endian(pCurveData->generator_y, pCurve->generator_y, nbits);
    bytes_to_digits_little_endian(pCurveData->Rprime, pCurve->Rprime, nbits);
    bytes_to_digits_little_endian(pCurveData->rprime, pCurve->rprime, nbits);
    
    return ECCRYPTO_SUCCESS;
}


PCurveStruct ecc_curve_allocate(PCurveStaticData CurveData)
{ // Dynamic allocation of memory for curve structure
    dig nbytes = (CurveData->nbits + 7)/8;
    PCurveStruct pCurve = NULL;

    pCurve = (PCurveStruct)calloc(1, sizeof(CurveStruct));
    pCurve->prime = (dig*)calloc(1, nbytes);
    pCurve->parameter1 = (dig*)calloc(1, nbytes);
    pCurve->parameter2 = (dig*)calloc(1, nbytes);
    pCurve->order = (dig*)calloc(1, nbytes);
    pCurve->generator_x = (dig*)calloc(1, nbytes);
    pCurve->generator_y = (dig*)calloc(1, nbytes);
    pCurve->Rprime = (dig*)calloc(1, nbytes);
    pCurve->rprime = (dig*)calloc(1, nbytes);
    if (is_ecc_curve_null(pCurve)) {
        return NULL;
    }

    return pCurve;
}


void ecc_curve_free(PCurveStruct pCurve)
{ // Free memory for curve structure

    if (pCurve != NULL)
    {
        if (pCurve->prime != NULL) {
            free(pCurve->prime);
        }
        if (pCurve->parameter1 != NULL) {
            free(pCurve->parameter1);
        }
        if (pCurve->parameter2 != NULL) {
            free(pCurve->parameter2);
        }
        if (pCurve->order != NULL) {
            free(pCurve->order);
        }
        if (pCurve->generator_x != NULL) {
            free(pCurve->generator_x);
        }
        if (pCurve->generator_y != NULL) {
            free(pCurve->generator_y);
        }
        if (pCurve->Rprime != NULL) {
             free(pCurve->Rprime);
        }
        if (pCurve->rprime != NULL) {
             free(pCurve->rprime);
        }
        free(pCurve);
    }

    return;
}


BOOL is_ecc_curve_null(PCurveStruct pCurve)
{ // Check if curve structure is NULL

    if (pCurve == NULL || pCurve->prime == NULL || pCurve->parameter1 == NULL || pCurve->parameter2 == NULL || pCurve->order == NULL || 
        pCurve->generator_x == NULL || pCurve->generator_y == NULL || pCurve->Rprime == NULL || pCurve->rprime == NULL)
    {
        return TRUE;
    }

    return FALSE;
}


#ifdef ECCURVES_256
//
// Specialized 256-bit field operations for curves "numsp256d1" and "numsp256t1"
//

void fpcopy256(dig256 a, dig256 c)
{ // Copy of a 256-bit field element, c = a 
    unsigned int i;

    for (i = 0; i < ML_WORDS256; i++)
    {
        c[i] = a[i]; 
    }
    return;
}


BOOL fp_iszero256(dig256 a)
{ // Is 256-bit field element zero, a=0?  
    unsigned int i;
    dig c;

    c = a[0];
    for (i = 1; i < ML_WORDS256; i++)
    {
        c = c | a[i]; 
    }

    return is_digit_zero_ct(c);
}


BOOL mod_eval256(dig256 a, dig256 modulus)
{ // Evaluate if 256-bit element is in [0, modulus-1] 
  // eval = TRUE if 0 <= a < modulus, else eval = FALSE 
    BOOL eval = FALSE;
    dig256 t1;
    
    fpcopy256(a, t1);
    eval = fpneg256(modulus, t1);            // eval = TRUE if a <= modulus
    eval = (eval & (fp_iszero256(t1) ^ 1));  // eval = TRUE if a < modulus

// cleanup
#ifdef TEMP_ZEROING
    fpzero256(t1);
#endif
    return eval;
}


void fpinv256_fixedchain(dig256 a)
{ // Inverse of field element, af = a^-1 = a^(p-2) mod p
  // Hardwired for p = 2^256-189
    int i, j;
    dig256 t1, t2, t3, t4, t5;
     
    fpsqr256(a, t1);                   // t1 = a^2                  
    fpmul256(a, t1, t2);               // t2 = a^3   
    fpsqr256(t2, t3);                  // t3 = a^6   
    fpsqr256(t3, t4);                  // t4 = a^12                  
    fpmul256(t2, t4, t5);              // t5 = a^15                   
    fpsqr256(t1, t2);                  // t2 = a^4      
    fpsqr256(t2, t1);                                      
    fpsqr256(t1, t2);                                      
    fpsqr256(t2, t1);                                      
    fpsqr256(t1, t2);                  // t2 = a^64                 
    fpmul256(a, t2, t3);               // t3 = a^65                    
    fpsqr256(t5, t2);                  // t2 = a^30                     
    fpsqr256(t2, t1);                   
    fpsqr256(t1, t2);                   
    fpsqr256(t2, t4);                  // t4 = a^240                  
    fpmul256(t5, t4, t1);              // t1 = a^255                    
    fpsqr256(t1, t2);                  // t2 = a^510                      
    fpsqr256(t2, t4);                                  
    fpsqr256(t4, t2);                                          
    fpsqr256(t2, t4);                                          
    fpsqr256(t4, t2);                                          
    fpsqr256(t2, t4);                                          
    fpsqr256(t4, t2);                                          
    fpsqr256(t2, t4);                  // t4 = a^65280                 
    fpmul256(t3, t4, t2);              // t2 = a^65345                 
    fpmul256(t1, t4, t3);              // t3 = a^65535      
    fpcopy256(t3, a);                  // af = a^65535

    for (i=0; i<14; i++) {
        for (j=0; j<16; j++) { 
            fpsqr256(a, t1); 
            fpcopy256(t1, a); 
        }                              // af = af^65536
        fpmul256(t3, t1, a);           // af = af * a^65535    
    }
    for (i=0; i<16; i++) { 
        fpsqr256(a, t1); 
        fpcopy256(t1, a); 
    }                                  // af = af^65536
    fpmul256(t2, t1, a);               // af = af * a^65345 = a^(2^256-191)
    
// cleanup
#ifdef TEMP_ZEROING
    fpzero256(t1);
    fpzero256(t2);
    fpzero256(t3);
    fpzero256(t4);
    fpzero256(t5);
#endif
    return;
}


#if defined(AVX_SUPPORT) && (TARGET_GENERIC == FALSE)

void lut_chu_numsp256d1(point_chu_precomp_numsp256d1* table, point_chu_precomp_numsp256d1 P, int digit, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract a Chudnovsky point (X:Y:Z:Z^2:Z^3) from the precomputed table
  // Weierstrass a=-3 curve over p = 2^256-189
  // Operation: P = sign * table[(|digit|-1)/2], where sign=1 if digit>0 and sign=-1 if digit<0
    unsigned int i;
    int sign, pos, mask;
    __m256d point[5], temp_point[5], full_mask;
    
    sign = ((unsigned int)digit >> (sizeof(int)*8 - 1)) - 1;           // if digit<0 then sign = 0x00...0 else sign = 0xFF...F
    pos = ((sign & (digit ^ -digit)) ^ -digit) >> 1;                   // position = (|digit|-1)/2  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->X);         // point = table[0] 
    point[1] = _mm256_loadu_pd ((double const *) table[0]->Y);    
    point[2] = _mm256_loadu_pd ((double const *) table[0]->Z);    
    point[3] = _mm256_loadu_pd ((double const *) table[0]->Z2);   
    point[4] = _mm256_loadu_pd ((double const *) table[0]->Z3);    

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->X);    // temp_point = table[i+1]
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->Y);
        temp_point[2] = _mm256_loadu_pd ((double const *) table[i]->Z);
        temp_point[3] = _mm256_loadu_pd ((double const *) table[i]->Z2);
        temp_point[4] = _mm256_loadu_pd ((double const *) table[i]->Z3);
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);     
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);  
        point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask);  
        point[3] = _mm256_blendv_pd (point[3], temp_point[3], full_mask);  
        point[4] = _mm256_blendv_pd (point[4], temp_point[4], full_mask); 
    }
    
    _mm256_storeu_pd ((double *)P->X, point[0]);    
    _mm256_storeu_pd ((double *)P->Y, point[1]);  
    _mm256_storeu_pd ((double *)P->Z, point[2]);    
    _mm256_storeu_pd ((double *)P->Z2, point[3]);    
    _mm256_storeu_pd ((double *)P->Z3, point[4]);    
    fpneg256(PCurve->prime, P->Y);                                    // point[1]: y coordinate  
    temp_point[1] = _mm256_loadu_pd ((double const *)P->Y);           // temp_point[1]: -y coordinate
    full_mask = _mm256_set1_pd ((double)sign);
    point[1] = _mm256_blendv_pd (temp_point[1], point[1], full_mask); // if mask = 0x00...0 then choose negative of the point
    _mm256_storeu_pd ((double *)P->Y, point[1]); 

    return;
}


void lut_aff_numsp256d1(point_numsp256d1* table, point_numsp256d1 P, int digit, int sign, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract an affine point from the precomputed table
  // If (sign = 0x00...0) then final digit is positive, else if (sign = 0xFF...F) then final digit is negative
  // Weierstrass a=-3 curve over p = 2^256-189
  // Operation: if sign=0 then P = table[digit], else if (sign=-1) then P = -table[digit]
    unsigned int i;
    int pos, mask;
    __m256d point[2], temp_point[2], full_mask;
    
    pos = digit;                                                       // Load digit position.  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->x);         // point = table[0] 
    point[1] = _mm256_loadu_pd ((double const *) table[0]->y);  

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->x);    // temp_point = table[i+1]
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->y);
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);     
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask); 
    }
    
    _mm256_storeu_pd ((double *)P->x, point[0]);    
    _mm256_storeu_pd ((double *)P->y, point[1]); 
    fpneg256(PCurve->prime, P->y);                                    // point[1]: y coordinate  
    temp_point[1] = _mm256_loadu_pd ((double const *)P->y);           // temp_point[1]: -y coordinate
    full_mask = _mm256_set1_pd ((double)sign);
    point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask); // if mask = 0xFF...F then choose negative of the point
    _mm256_storeu_pd ((double *)P->y, point[1]); 

    return;
}


void lut_extproj_numsp256t1(point_extproj_precomp_numsp256t1* table, point_extproj_precomp_numsp256t1 P, int digit, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract a twisted Edwards point (X,Y,Z,Td) from the precomputed table
  // Twisted Edwards a=1 curve over p = 2^256-189
  // Operation: P = sign * table[(|digit|-1)/2], where sign=1 if digit>0 and sign=-1 if digit<0
    unsigned int i;
    int sign, pos, mask;
    __m256d point[4], temp_point[4], full_mask;
    
    sign = ((unsigned int)digit >> (sizeof(unsigned int)*8 - 1)) - 1;      // if digit<0 then sign = 0x00...0 else sign = 0xFF...F
    pos = ((sign & (digit ^ -digit)) ^ -digit) >> 1;                       // position = (|digit|-1)/2    
    point[0] = _mm256_loadu_pd ((double const *) table[0]->X);             // point = table[0] 
    point[1] = _mm256_loadu_pd ((double const *) table[0]->Y);    
    point[2] = _mm256_loadu_pd ((double const *) table[0]->Z);    
    point[3] = _mm256_loadu_pd ((double const *) table[0]->Td);    

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->X);    // temp_point = table[i+1]
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->Y);
        temp_point[2] = _mm256_loadu_pd ((double const *) table[i]->Z);
        temp_point[3] = _mm256_loadu_pd ((double const *) table[i]->Td);
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);     
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);  
        point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask);  
        point[3] = _mm256_blendv_pd (point[3], temp_point[3], full_mask);  
    }
    
    temp_point[0] = _mm256_loadu_pd ((double const *) point);              // point: x, t coordinate
    temp_point[3] = _mm256_loadu_pd ((double const *) point+3*4);          // temp_point: -x, -t coordinate
    fpneg256(PCurve->prime, (dig*)&temp_point[0]);                         
    fpneg256(PCurve->prime, (dig*)&temp_point[3]); 
    full_mask = _mm256_set1_pd ((double)sign);
    point[0] = _mm256_blendv_pd (temp_point[0], point[0], full_mask);      // if mask = 0x00...0 then choose negative of the point
    point[3] = _mm256_blendv_pd (temp_point[3], point[3], full_mask);
    _mm256_storeu_pd ((double *)P->X, point[0]); 
    _mm256_storeu_pd ((double *)P->Y, point[1]); 
    _mm256_storeu_pd ((double *)P->Z, point[2]); 
    _mm256_storeu_pd ((double *)P->Td, point[3]); 
    
    return;
}


void lut_extaff_numsp256t1(point_extaff_precomp_numsp256t1* table, point_extaff_precomp_numsp256t1 P, int digit, int sign, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract an affine point (x,y,td) from the precomputed table
  // Twisted Edwards a=1 curve over p = 2^256-189
  // Operation: if sign=0 then P = table[digit], else if (sign=-1) then P = -table[digit]
    unsigned int i;
    int pos, mask;
    __m256d point[3], temp_point[3], full_mask;

    pos = digit;                                                           // Load digit position.  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->x);             // point = table[0] 
    point[1] = _mm256_loadu_pd ((double const *) table[0]->y);  
    point[2] = _mm256_loadu_pd ((double const *) table[0]->td);  

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->x);    // temp_point = table[i+1]
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->y);
        temp_point[2] = _mm256_loadu_pd ((double const *) table[i]->td);
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);     
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);    
        point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask); 
    }
    
    temp_point[0] = _mm256_loadu_pd ((double const *) point);   
    temp_point[2] = _mm256_loadu_pd ((double const *) point+2*4); 
    fpneg256(PCurve->prime, (dig*)&temp_point[0]);                  
    fpneg256(PCurve->prime, (dig*)&temp_point[2]);                         // point negated: -x, -t coordinate
    full_mask = _mm256_set1_pd ((double)sign);                             // temp_point is point negated
    point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);      // if mask = 0xFF...F then choose negative of the point
    point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask);
    _mm256_storeu_pd ((double *)P->x, point[0]); 
    _mm256_storeu_pd ((double *)P->y, point[1]); 
    _mm256_storeu_pd ((double *)P->td, point[2]);

    return;
}

#endif

#endif


#ifdef ECCURVES_384
//
// Specialized 384-bit field operations for curves "numsp384d1" and "numsp384t1"
//

void fpcopy384(dig384 a, dig384 c)
{ // Copy of a 384-bit field element, c = a 
    unsigned int i;

    for (i = 0; i < ML_WORDS384; i++)
    {
        c[i] = a[i]; 
    }
    return;
}


BOOL fp_iszero384(dig384 a)
{ // Is 384-bit field element zero, a=0?  
    unsigned int i;
    dig c;

    c = a[0];
    for (i = 1; i < ML_WORDS384; i++)
    {
        c = c | a[i]; 
    }

    return is_digit_zero_ct(c);
}


BOOL mod_eval384(dig384 a, dig384 modulus)
{ // Evaluate if 384-bit element is in [0, modulus-1] 
  // eval = TRUE if 0 <= a < modulus, else eval = FALSE 
    BOOL eval = FALSE;
    dig384 t1;
    
    fpcopy384(a, t1);
    eval = fpneg384(modulus, t1);            // eval = TRUE if a <= modulus
    eval = (eval & (fp_iszero384(t1) ^ 1));  // eval = TRUE if a < modulus

// cleanup
#ifdef TEMP_ZEROING
    fpzero384(t1);
#endif
    return eval;
}


void fpinv384_fixedchain(dig384 a)
{ // Inverse of field element, af = a^-1 = a^(p-2) mod p
  // Hardwired for p = 2^384-319
    int j;
    dig384 t3, t12, tF, T, o10, o40, aux;

    fpsqr384(a, aux);           // a = t1
    fpmul384(a, aux, t3);       // t3
    fpsqr384(t3, aux); 
    fpsqr384(aux, t12);         // t12
    fpmul384(t3, t12, tF);      // tF
    fpsqr384(tF, T); 
    fpsqr384(T, aux);  
    fpsqr384(aux, T);  
    fpsqr384(T, aux); 
    fpmul384(tF, aux, T);       // T
    fpsqr384(T, aux);  
    fpsqr384(aux, T); 
    fpmul384(t3, T, o10);       // o10
    fpcopy384(o10, aux);
    for (j=0; j<10; j++) { 
        fpsqr384(aux, T); 
        fpcopy384(T, aux); 
    }
    fpmul384(o10, aux, T);
    fpcopy384(T, aux);
    for (j=0; j<20; j++) { 
        fpsqr384(aux, o40); 
        fpcopy384(o40, aux); 
    }
    fpmul384(T, aux, o40);
    fpcopy384(o40, aux);
    for (j=0; j<40; j++) { 
        fpsqr384(aux, T); 
        fpcopy384(T, aux); 
    }
    fpmul384(o40, aux, T);
    fpcopy384(T, aux);
    for (j=0; j<80; j++) { 
        fpsqr384(aux, t12); 
        fpcopy384(t12, aux); 
    }
    fpmul384(T, t12, aux);
    fpcopy384(aux, T);
    for (j=0; j<160; j++) { 
        fpsqr384(aux, t12); 
        fpcopy384(t12, aux); 
    }
    fpmul384(T, t12, aux);
    for (j=0; j<10; j++) { 
        fpsqr384(aux, T); 
        fpcopy384(T, aux); 
    }
    fpmul384(o10, T, aux);
    for (j=0; j<40; j++) { 
        fpsqr384(aux, T); 
        fpcopy384(T, aux); 
    }
    fpmul384(o40, aux, T);
    fpsqr384(T, aux); 
    fpsqr384(aux, T);  
    fpsqr384(T, aux);  
    fpsqr384(aux, T); 
    fpmul384(tF, T, aux);
    fpsqr384(aux, T); 
    fpmul384(a, T, aux); 
    fpsqr384(aux, T);  
    fpsqr384(T, aux);  
    fpsqr384(aux, T); 
    fpmul384(t3, T, aux);
    for (j=0; j<6; j++) { 
        fpsqr384(aux, T); 
        fpcopy384(T, aux); 
    }
    fpcopy384(a, aux);
    fpmul384(T, aux, a);
    
// cleanup
#ifdef TEMP_ZEROING
    fpzero384(t3);
    fpzero384(t12);
    fpzero384(tF);
    fpzero384(T);
    fpzero384(o10);
    fpzero384(o40);
    fpzero384(aux);
#endif
    return;
}


#if defined(AVX_SUPPORT) && (TARGET_GENERIC == FALSE)

void lut_chu_numsp384d1(point_chu_precomp_numsp384d1* table, point_chu_precomp_numsp384d1 P, int digit, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract a Chudnovsky point (X:Y:Z:Z^2:Z^3) from the precomputed table
  // Weierstrass a=-3 curve over p = 2^384-319
  // Operation: P = sign * table[(|digit|-1)/2], where sign=1 if digit>0 and sign=-1 if digit<0
    unsigned int i;
    int sign, pos, mask;
    __m256d point[5], temp_point[5], full_mask;
    __m128d pointb[5], temp_pointb[5], full_maskb;
    
    sign = ((unsigned int)digit >> (sizeof(int)*8 - 1)) - 1;           // if digit<0 then sign = 0x00...0 else sign = 0xFF...F
    pos = ((sign & (digit ^ -digit)) ^ -digit) >> 1;                   // position = (|digit|-1)/2  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->X);         // point = table[0] 
    pointb[0] = _mm_loadu_pd ((double const *) table[0]->X+4);          
    point[1] = _mm256_loadu_pd ((double const *) table[0]->Y);  
    pointb[1] = _mm_loadu_pd ((double const *) table[0]->Y+4);            
    point[2] = _mm256_loadu_pd ((double const *) table[0]->Z);  
    pointb[2] = _mm_loadu_pd ((double const *) table[0]->Z+4);            
    point[3] = _mm256_loadu_pd ((double const *) table[0]->Z2);  
    pointb[3] = _mm_loadu_pd ((double const *) table[0]->Z2+4);           
    point[4] = _mm256_loadu_pd ((double const *) table[0]->Z3);  
    pointb[4] = _mm_loadu_pd ((double const *) table[0]->Z3+4);            

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        full_maskb = _mm_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->X);    // temp_point = table[i+1]
        temp_pointb[0] = _mm_loadu_pd ((double const *) table[i]->X+4); 
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->Y);
        temp_pointb[1] = _mm_loadu_pd ((double const *) table[i]->Y+4); 
        temp_point[2] = _mm256_loadu_pd ((double const *) table[i]->Z);
        temp_pointb[2] = _mm_loadu_pd ((double const *) table[i]->Z+4); 
        temp_point[3] = _mm256_loadu_pd ((double const *) table[i]->Z2);
        temp_pointb[3] = _mm_loadu_pd ((double const *) table[i]->Z2+4); 
        temp_point[4] = _mm256_loadu_pd ((double const *) table[i]->Z3);
        temp_pointb[4] = _mm_loadu_pd ((double const *) table[i]->Z3+4); 
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);    
        pointb[0] = _mm_blendv_pd (pointb[0], temp_pointb[0], full_maskb);      
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);   
        pointb[1] = _mm_blendv_pd (pointb[1], temp_pointb[1], full_maskb);   
        point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask);    
        pointb[2] = _mm_blendv_pd (pointb[2], temp_pointb[2], full_maskb);  
        point[3] = _mm256_blendv_pd (point[3], temp_point[3], full_mask);    
        pointb[3] = _mm_blendv_pd (pointb[3], temp_pointb[3], full_maskb);  
        point[4] = _mm256_blendv_pd (point[4], temp_point[4], full_mask);   
        pointb[4] = _mm_blendv_pd (pointb[4], temp_pointb[4], full_maskb);  
    }
    
    _mm256_storeu_pd ((double *)P->X, point[0]);  
    _mm_storeu_pd ((double *)P->X+4, pointb[0]);   
    _mm256_storeu_pd ((double *)P->Y, point[1]);   
    _mm_storeu_pd ((double *)P->Y+4, pointb[1]);   
    _mm256_storeu_pd ((double *)P->Z, point[2]);  
    _mm_storeu_pd ((double *)P->Z+4, pointb[2]);      
    _mm256_storeu_pd ((double *)P->Z2, point[3]);  
    _mm_storeu_pd ((double *)P->Z2+4, pointb[3]);      
    _mm256_storeu_pd ((double *)P->Z3, point[4]);   
    _mm_storeu_pd ((double *)P->Z3+4, pointb[4]);     
    fpneg384(PCurve->prime, P->Y);                                     // point[1]: y coordinate  
    temp_point[1] = _mm256_loadu_pd ((double const *)P->Y);            // temp_point[1]: -y coordinate
    temp_pointb[1] = _mm_loadu_pd ((double const *)P->Y+4);     
    full_mask = _mm256_set1_pd ((double)sign);    
    full_maskb = _mm_set1_pd ((double)sign);
    point[1] = _mm256_blendv_pd (temp_point[1], point[1], full_mask);  // if mask = 0x00...0 then choose negative of the point
    pointb[1] = _mm_blendv_pd (temp_pointb[1], pointb[1], full_maskb);
    _mm256_storeu_pd ((double *)P->Y, point[1]); 
    _mm_storeu_pd ((double *)P->Y+4, pointb[1]); 

    return;
}


void lut_aff_numsp384d1(point_numsp384d1* table, point_numsp384d1 P, int digit, int sign, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract an affine point from the precomputed table
  // If (sign = 0x00...0) then final digit is positive, else if (sign = 0xFF...F) then final digit is negative
  // Weierstrass a=-3 curve over p = 2^384-319
  // Operation: if sign=0 then P = table[digit], else if (sign=-1) then P = -table[digit]
    unsigned int i;
    int pos, mask;
    __m256d point[2], temp_point[2], full_mask;
    __m128d pointb[2], temp_pointb[2], full_maskb;
            
    pos = digit;                                                       // Load digit position.  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->x);         // point = table[0] 
    pointb[0] = _mm_loadu_pd ((double const *) table[0]->x+4);          
    point[1] = _mm256_loadu_pd ((double const *) table[0]->y);  
    pointb[1] = _mm_loadu_pd ((double const *) table[0]->y+4);            

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        full_maskb = _mm_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->x);    // temp_point = table[i+1]
        temp_pointb[0] = _mm_loadu_pd ((double const *) table[i]->x+4); 
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->y);
        temp_pointb[1] = _mm_loadu_pd ((double const *) table[i]->y+4);
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);    
        pointb[0] = _mm_blendv_pd (pointb[0], temp_pointb[0], full_maskb);      
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);   
        pointb[1] = _mm_blendv_pd (pointb[1], temp_pointb[1], full_maskb); 
    }
    
    _mm256_storeu_pd ((double *)P->x, point[0]);  
    _mm_storeu_pd ((double *)P->x+4, pointb[0]);   
    _mm256_storeu_pd ((double *)P->y, point[1]);   
    _mm_storeu_pd ((double *)P->y+4, pointb[1]); 
    fpneg384(PCurve->prime, P->y);                                    // point[1]: y coordinate  
    temp_point[1] = _mm256_loadu_pd ((double const *)P->y);           // temp_point[1]: -y coordinate
    temp_pointb[1] = _mm_loadu_pd ((double const *)P->y+4);     
    full_mask = _mm256_set1_pd ((double)sign);    
    full_maskb = _mm_set1_pd ((double)sign);
    point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask); // if mask = 0xFF...F then choose negative of the point
    pointb[1] = _mm_blendv_pd (pointb[1], temp_pointb[1], full_maskb);
    _mm256_storeu_pd ((double *)P->y, point[1]); 
    _mm_storeu_pd ((double *)P->y+4, pointb[1]); 

    return;
}


void lut_extproj_numsp384t1(point_extproj_precomp_numsp384t1* table, point_extproj_precomp_numsp384t1 P, int digit, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract a twisted Edwards point (X,Y,Z,Td) from the precomputed table
  // Twisted Edwards a=1 curve over p = 2^384-319
  // Operation: P = sign * table[(|digit|-1)/2], where sign=1 if digit>0 and sign=-1 if digit<0
    unsigned int i;
    int sign, pos, mask;
    __m256d point[6], temp_point[6], full_mask;
    
    sign = ((unsigned int)digit >> (sizeof(unsigned int)*8 - 1)) - 1;      // if digit<0 then sign = 0x00...0 else sign = 0xFF...F
    pos = ((sign & (digit ^ -digit)) ^ -digit) >> 1;                       // position = (|digit|-1)/2  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->X);             // point = table[0]  
    point[1] = _mm256_loadu_pd ((double const *) table[0]->X+4);  
    point[2] = _mm256_loadu_pd ((double const *) table[0]->X+2*4);  
    point[3] = _mm256_loadu_pd ((double const *) table[0]->X+3*4);  
    point[4] = _mm256_loadu_pd ((double const *) table[0]->X+4*4);  
    point[5] = _mm256_loadu_pd ((double const *) table[0]->X+5*4);         // 384*4 coord = 1536 and 1536/256 = 6   

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((int)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->X);    // temp_point = table[i+1]
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->X+4);
        temp_point[2] = _mm256_loadu_pd ((double const *) table[i]->X+2*4);
        temp_point[3] = _mm256_loadu_pd ((double const *) table[i]->X+3*4);
        temp_point[4] = _mm256_loadu_pd ((double const *) table[i]->X+4*4);
        temp_point[5] = _mm256_loadu_pd ((double const *) table[i]->X+5*4);
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);     
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);  
        point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask);  
        point[3] = _mm256_blendv_pd (point[3], temp_point[3], full_mask);   
        point[4] = _mm256_blendv_pd (point[4], temp_point[4], full_mask);  
        point[5] = _mm256_blendv_pd (point[5], temp_point[5], full_mask); 
    }
                    
    temp_point[0] = _mm256_loadu_pd ((double const *) point);              // point: x, t coordinate       
    temp_point[1] = _mm256_loadu_pd ((double const *) point+4);            // temp_point: -x, -t coordinate            
    temp_point[2] = _mm256_loadu_pd ((double const *) point+8);                    
    temp_point[3] = _mm256_loadu_pd ((double const *) point+12);          
    temp_point[4] = _mm256_loadu_pd ((double const *) point+16);                
    temp_point[5] = _mm256_loadu_pd ((double const *) point+20);     
    fpneg384(PCurve->prime, (dig*)temp_point);       
    fpneg384(PCurve->prime, (dig*)temp_point+3*ML_WORDS384);    
    full_mask = _mm256_set1_pd ((double)sign); 
    point[0] = _mm256_blendv_pd (temp_point[0], point[0], full_mask);      // if mask = 0x00...0 then choose negative of the point
    point[1] = _mm256_blendv_pd (temp_point[1], point[1], full_mask);
    point[2] = _mm256_blendv_pd (temp_point[2], point[2], full_mask);  
    point[3] = _mm256_blendv_pd (temp_point[3], point[3], full_mask); 
    point[4] = _mm256_blendv_pd (temp_point[4], point[4], full_mask);  
    point[5] = _mm256_blendv_pd (temp_point[5], point[5], full_mask); 
    _mm256_storeu_pd ((double *)P->X, point[0]);    
    _mm256_storeu_pd ((double *)P->X+4, point[1]); 
    _mm256_storeu_pd ((double *)P->X+2*4, point[2]);    
    _mm256_storeu_pd ((double *)P->X+3*4, point[3]);      
    _mm256_storeu_pd ((double *)P->X+4*4, point[4]);    
    _mm256_storeu_pd ((double *)P->X+5*4, point[5]);

    return;
}


void lut_extaff_numsp384t1(point_extaff_precomp_numsp384t1* table, point_extaff_precomp_numsp384t1 P, int digit, int sign, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract an extended affine point (x+y,y-x,2t) from the precomputed table
  // Twisted Edwards a=1 curve over p = 2^384-319
  // Operation: if sign=0 then P = table[digit], else if (sign=-1) then P = -table[digit]
    unsigned int i;
    int pos, mask;
    __m256d point[5], temp_point[5], full_mask;
    __m128d full_maskb;
            
    pos = digit;                                                           // Load digit position.  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->x);             // point = table[0] 
    point[1] = _mm256_loadu_pd ((double const *) table[0]->x+4);          
    point[2] = _mm256_loadu_pd ((double const *) table[0]->x+2*4);         
    point[3] = _mm256_loadu_pd ((double const *) table[0]->x+3*4);  
    *((__m128d*)point+8) = _mm_loadu_pd ((double const *) table[0]->x+4*4);            

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        full_maskb = _mm_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->x);    // temp_point = table[i+1] 
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->x+4);          
        temp_point[2] = _mm256_loadu_pd ((double const *) table[i]->x+2*4);         
        temp_point[3] = _mm256_loadu_pd ((double const *) table[i]->x+3*4);  
        *((__m128d*)temp_point+8) = _mm_loadu_pd ((double const *) table[i]->x+4*4);            
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask); 
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);
        point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask); 
        point[3] = _mm256_blendv_pd (point[3], temp_point[3], full_mask);   
        *((__m128d*)point+8) = _mm_blendv_pd (*((__m128d*)point+8), *((__m128d*)temp_point+8), full_maskb); 
    }
    
    temp_point[0] = _mm256_loadu_pd ((double const *) point);              // point: x, t coordinate       
    temp_point[1] = _mm256_loadu_pd ((double const *) point+4);            // temp_point: -x, -t coordinate     
    temp_point[2] = _mm256_loadu_pd ((double const *) point+8);                
    temp_point[3] = _mm256_loadu_pd ((double const *) point+12);                
    temp_point[4] = _mm256_loadu_pd ((double const *) point+16); 
    fpneg384(PCurve->prime, (dig*)temp_point);    
    fpneg384(PCurve->prime, (dig*)temp_point+2*ML_WORDS384);    
    full_mask = _mm256_set1_pd ((double)sign); 
    point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);      // if mask = 0xFF...F then choose negative of the point
    point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);
    point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask); 
    point[3] = _mm256_blendv_pd (point[3], temp_point[3], full_mask);  
    point[4] = _mm256_blendv_pd (point[4], temp_point[4], full_mask); 
    _mm256_storeu_pd ((double *)P->x, point[0]);    
    _mm256_storeu_pd ((double *)P->x+4, point[1]); 
    _mm256_storeu_pd ((double *)P->x+2*4, point[2]);    
    _mm256_storeu_pd ((double *)P->x+3*4, point[3]);      
    _mm_storeu_pd ((double *)P->x+4*4, *((__m128d*)point+8));

    return;
}

#endif

#endif


#ifdef ECCURVES_512
//
// Specialized 512-bit field operations for curves "numsp512d1" and "numsp512t1"
//

void fpcopy512(dig512 a, dig512 c)
{ // Copy of a 512-bit field element, c = a 
    unsigned int i;

    for (i = 0; i < ML_WORDS512; i++)
    {
        c[i] = a[i]; 
    }
    return;
}


BOOL fp_iszero512(dig512 a)
{ // Is 512-bit field element zero, a=0?  
    unsigned int i;
    dig c;

    c = a[0];
    for (i = 1; i < ML_WORDS512; i++)
    {
        c = c | a[i]; 
    }

    return is_digit_zero_ct(c);
}


BOOL mod_eval512(dig512 a, dig512 modulus)
{ // Evaluate if 512-bit element is in [0, modulus-1] 
  // eval = TRUE if 0 <= a < modulus, else eval = FALSE 
    BOOL eval = FALSE;
    dig512 t1;
    
    fpcopy512(a, t1);
    eval = fpneg512(modulus, t1);            // eval = TRUE if a <= modulus
    eval = (eval & (fp_iszero512(t1) ^ 1));  // eval = TRUE if a < modulus

// cleanup
#ifdef TEMP_ZEROING
    fpzero512(t1);
#endif
    return eval;
}


void fpinv512_fixedchain(dig512 a)
{ // Inverse of field element, af = a^-1 = a^(p-2) mod p
  // Hardwired for p = 2^512-319
    int j;
    dig512 t2, T, t5, t7, t10, t80, aux, aux2;

    fpsqr512(a, t2);
    fpsqr512(t2, aux);
    fpmul512(a, aux, t5);
    fpmul512(t2, t5, t7);
    fpmul512(t2, a, T);
    fpcopy512(T, t80);
    fpsqr512(T, aux2);
    fpsqr512(aux2, aux);
    fpmul512(t80, aux, T);
    fpsqr512(T, aux);
    fpmul512(a, aux, T);
    fpcopy512(T, aux);
    for (j=0; j<5; j++) { 
        fpsqr512(aux, t10); 
        fpcopy512(t10, aux); 
    }
    fpmul512(T, aux, t10);
    fpcopy512(t10, aux);
    for (j=0; j<10; j++) { 
        fpsqr512(aux, T); 
        fpcopy512(T, aux); 
    }
    fpmul512(t10, aux, T);
    fpcopy512(T, aux);
    fpcopy512(T, aux2);
    for (j=0; j<20; j++) { 
        fpsqr512(aux, T); 
        fpcopy512(T, aux); 
    }
    fpmul512(aux2, aux, T);
    fpcopy512(T, aux);
    for (j=0; j<40; j++) { 
        fpsqr512(aux, t80); 
        fpcopy512(t80, aux); 
    }
    fpmul512(T, aux, t80);
    fpcopy512(t80, aux);
    for (j=0; j<80; j++) { 
        fpsqr512(aux, aux2); 
        fpcopy512(aux2, aux); 
    }
    fpmul512(t80, aux, T);
    fpcopy512(T, aux);
    for (j=0; j<80; j++) { 
        fpsqr512(aux, aux2); 
        fpcopy512(aux2, aux); 
    }
    fpmul512(t80, aux, T);
    fpcopy512(T, aux);
    for (j=0; j<10; j++) { 
        fpsqr512(aux, aux2); 
        fpcopy512(aux2, aux); 
    }
    fpmul512(t10, aux, T);
    fpsqr512(T, aux);
    fpmul512(a, aux, T);
    fpcopy512(T, aux);
    fpcopy512(T, aux2);
    for (j=0; j<251; j++) { 
        fpsqr512(aux, t80); 
        fpcopy512(t80, aux); 
    }
    fpmul512(aux2, aux, T);
    for (j=0; j<4; j++) { 
        fpsqr512(T, aux); 
        fpcopy512(aux, T); 
    }
    fpmul512(t7, aux, T);
    for (j=0; j<6; j++) { 
        fpsqr512(T, aux); 
        fpcopy512(aux, T); 
    }
    fpmul512(t5, aux, a);
    
// cleanup
#ifdef TEMP_ZEROING
    fpzero512(t2);
    fpzero512(T);
    fpzero512(t5);
    fpzero512(t7);
    fpzero512(t10);
    fpzero512(t80);
    fpzero512(aux);
    fpzero512(aux2);
#endif
    return;
}


#if defined(AVX_SUPPORT) && (TARGET_GENERIC == FALSE)

void lut_chu_numsp512d1(point_chu_precomp_numsp512d1* table, point_chu_precomp_numsp512d1 P, int digit, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract a Chudnovsky point (X:Y:Z:Z^2:Z^3) from the precomputed table
  // Weierstrass a=-3 curve over p = 2^512-319
  // Operation: P = sign * table[(|digit|-1)/2], where sign=1 if digit>0 and sign=-1 if digit<0
    unsigned int i;
    int sign, pos, mask;
    __m256d point[5], temp_point[5], point2[5], temp_point2[5], full_mask;
    
    sign = ((unsigned int)digit >> (sizeof(int)*8 - 1)) - 1;           // if digit<0 then sign = 0x00...0 else sign = 0xFF...F
    pos = ((sign & (digit ^ -digit)) ^ -digit) >> 1;                   // position = (|digit|-1)/2  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->X);         // point = table[0] 
    point2[0] = _mm256_loadu_pd ((double const *) table[0]->X+4);          
    point[1] = _mm256_loadu_pd ((double const *) table[0]->Y);  
    point2[1] = _mm256_loadu_pd ((double const *) table[0]->Y+4);            
    point[2] = _mm256_loadu_pd ((double const *) table[0]->Z);  
    point2[2] = _mm256_loadu_pd ((double const *) table[0]->Z+4);            
    point[3] = _mm256_loadu_pd ((double const *) table[0]->Z2);  
    point2[3] = _mm256_loadu_pd ((double const *) table[0]->Z2+4);           
    point[4] = _mm256_loadu_pd ((double const *) table[0]->Z3);  
    point2[4] = _mm256_loadu_pd ((double const *) table[0]->Z3+4);            

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->X);    // temp_point = table[i+1]
        temp_point2[0] = _mm256_loadu_pd ((double const *) table[i]->X+4); 
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->Y);
        temp_point2[1] = _mm256_loadu_pd ((double const *) table[i]->Y+4); 
        temp_point[2] = _mm256_loadu_pd ((double const *) table[i]->Z);
        temp_point2[2] = _mm256_loadu_pd ((double const *) table[i]->Z+4); 
        temp_point[3] = _mm256_loadu_pd ((double const *) table[i]->Z2);
        temp_point2[3] = _mm256_loadu_pd ((double const *) table[i]->Z2+4); 
        temp_point[4] = _mm256_loadu_pd ((double const *) table[i]->Z3);
        temp_point2[4] = _mm256_loadu_pd ((double const *) table[i]->Z3+4); 
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);    
        point2[0] = _mm256_blendv_pd (point2[0], temp_point2[0], full_mask);      
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);   
        point2[1] = _mm256_blendv_pd (point2[1], temp_point2[1], full_mask);   
        point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask);    
        point2[2] = _mm256_blendv_pd (point2[2], temp_point2[2], full_mask);  
        point[3] = _mm256_blendv_pd (point[3], temp_point[3], full_mask);    
        point2[3] = _mm256_blendv_pd (point2[3], temp_point2[3], full_mask);  
        point[4] = _mm256_blendv_pd (point[4], temp_point[4], full_mask);   
        point2[4] = _mm256_blendv_pd (point2[4], temp_point2[4], full_mask);  
    }
    
    _mm256_storeu_pd ((double *)P->X, point[0]);  
    _mm256_storeu_pd ((double *)P->X+4, point2[0]);   
    _mm256_storeu_pd ((double *)P->Y, point[1]);   
    _mm256_storeu_pd ((double *)P->Y+4, point2[1]);   
    _mm256_storeu_pd ((double *)P->Z, point[2]);  
    _mm256_storeu_pd ((double *)P->Z+4, point2[2]);      
    _mm256_storeu_pd ((double *)P->Z2, point[3]);  
    _mm256_storeu_pd ((double *)P->Z2+4, point2[3]);      
    _mm256_storeu_pd ((double *)P->Z3, point[4]);   
    _mm256_storeu_pd ((double *)P->Z3+4, point2[4]);     
    fpneg512(PCurve->prime, P->Y);                                    // point[1]: y coordinate  
    temp_point[1] = _mm256_loadu_pd ((double const *)P->Y);           // temp_point[1]: -y coordinate
    temp_point2[1] = _mm256_loadu_pd ((double const *)P->Y+4);     
    full_mask = _mm256_set1_pd ((double)sign); 
    point[1] = _mm256_blendv_pd (temp_point[1], point[1], full_mask); // if mask = 0x00...0 then choose negative of the point
    point2[1] = _mm256_blendv_pd (temp_point2[1], point2[1], full_mask);
    _mm256_storeu_pd ((double *)P->Y, point[1]); 
    _mm256_storeu_pd ((double *)P->Y+4, point2[1]); 

    return;
}


void lut_aff_numsp512d1(point_numsp512d1* table, point_numsp512d1 P, int digit, int sign, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract an affine point from the precomputed table
  // If (sign = 0x00...0) then final digit is positive, else if (sign = 0xFF...F) then final digit is negative
  // Weierstrass a=-3 curve over p = 2^512-319
  // Operation: if sign=0 then P = table[digit], else if (sign=-1) then P = -table[digit]
    unsigned int i;
    int pos, mask;
    __m256d point[2], temp_point[2], point2[2], temp_point2[2], full_mask;
                           
    pos = digit;                                                       // Load digit position.  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->x);         // point = table[0] 
    point2[0] = _mm256_loadu_pd ((double const *) table[0]->x+4);          
    point[1] = _mm256_loadu_pd ((double const *) table[0]->y);  
    point2[1] = _mm256_loadu_pd ((double const *) table[0]->y+4);            

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->x);    // temp_point = table[i+1]
        temp_point2[0] = _mm256_loadu_pd ((double const *) table[i]->x+4); 
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->y);
        temp_point2[1] = _mm256_loadu_pd ((double const *) table[i]->y+4);
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);    
        point2[0] = _mm256_blendv_pd (point2[0], temp_point2[0], full_mask);      
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);   
        point2[1] = _mm256_blendv_pd (point2[1], temp_point2[1], full_mask); 
    }
    
    _mm256_storeu_pd ((double *)P->x, point[0]);  
    _mm256_storeu_pd ((double *)P->x+4, point2[0]);   
    _mm256_storeu_pd ((double *)P->y, point[1]);   
    _mm256_storeu_pd ((double *)P->y+4, point2[1]); 
    fpneg512(PCurve->prime, P->y);                                    // point[1]: y coordinate  
    temp_point[1] = _mm256_loadu_pd ((double const *)P->y);           // temp_point[1]: -y coordinate
    temp_point2[1] = _mm256_loadu_pd ((double const *)P->y+4);     
    full_mask = _mm256_set1_pd ((double)sign);  
    point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask); // if mask = 0xFF...F then choose negative of the point
    point2[1] = _mm256_blendv_pd (point2[1], temp_point2[1], full_mask);
    _mm256_storeu_pd ((double *)P->y, point[1]); 
    _mm256_storeu_pd ((double *)P->y+4, point2[1]);

    return;
}


void lut_extproj_numsp512t1(point_extproj_precomp_numsp512t1* table, point_extproj_precomp_numsp512t1 P, int digit, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract a twisted Edwards point (X,Y,Z,Td) from the precomputed table
  // Twisted Edwards a=1 curve over p = 2^512-319
  // Operation: P = sign * table[(|digit|-1)/2], where sign=1 if digit>0 and sign=-1 if digit<0
    unsigned int i;
    int sign, pos, mask;
    __m256d point[8], temp_point[8], full_mask;
    
    sign = ((unsigned int)digit >> (sizeof(int)*8 - 1)) - 1;               // if digit<0 then sign = 0x00...0 else sign = 0xFF...F
    pos = ((sign & (digit ^ -digit)) ^ -digit) >> 1;                       // position = (|digit|-1)/2  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->X);             // point = table[0]  
    point[1] = _mm256_loadu_pd ((double const *) table[0]->X+4);  
    point[2] = _mm256_loadu_pd ((double const *) table[0]->X+2*4);  
    point[3] = _mm256_loadu_pd ((double const *) table[0]->X+3*4);  
    point[4] = _mm256_loadu_pd ((double const *) table[0]->X+4*4);  
    point[5] = _mm256_loadu_pd ((double const *) table[0]->X+5*4);       
    point[6] = _mm256_loadu_pd ((double const *) table[0]->X+6*4);     
    point[7] = _mm256_loadu_pd ((double const *) table[0]->X+7*4);         // 512*4 coord = 2048 and 2048/256 = 8  

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->X);    // temp_point = table[i+1]
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->X+4);
        temp_point[2] = _mm256_loadu_pd ((double const *) table[i]->X+2*4);
        temp_point[3] = _mm256_loadu_pd ((double const *) table[i]->X+3*4);
        temp_point[4] = _mm256_loadu_pd ((double const *) table[i]->X+4*4);
        temp_point[5] = _mm256_loadu_pd ((double const *) table[i]->X+5*4);
        temp_point[6] = _mm256_loadu_pd ((double const *) table[i]->X+6*4);
        temp_point[7] = _mm256_loadu_pd ((double const *) table[i]->X+7*4);
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);     
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);  
        point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask);  
        point[3] = _mm256_blendv_pd (point[3], temp_point[3], full_mask);   
        point[4] = _mm256_blendv_pd (point[4], temp_point[4], full_mask);  
        point[5] = _mm256_blendv_pd (point[5], temp_point[5], full_mask);  
        point[6] = _mm256_blendv_pd (point[6], temp_point[6], full_mask);  
        point[7] = _mm256_blendv_pd (point[7], temp_point[7], full_mask); 
    }
    
    temp_point[0] = _mm256_loadu_pd ((double const *) point);              // point: x, t coordinate
    temp_point[1] = _mm256_loadu_pd ((double const *) point+1*4);          // temp_point: -x, -t coordinate
    temp_point[6] = _mm256_loadu_pd ((double const *) point+6*4);    
    temp_point[7] = _mm256_loadu_pd ((double const *) point+7*4); 
    fpneg512(PCurve->prime, (dig*)&temp_point[0]); 
    fpneg512(PCurve->prime, (dig*)&temp_point[6]); 
    full_mask = _mm256_set1_pd ((double)sign);
    point[0] = _mm256_blendv_pd (temp_point[0], point[0], full_mask);      // if mask = 0x00...0 then choose negative of the point
    point[1] = _mm256_blendv_pd (temp_point[1], point[1], full_mask);
    point[6] = _mm256_blendv_pd (temp_point[6], point[6], full_mask);
    point[7] = _mm256_blendv_pd (temp_point[7], point[7], full_mask);
    _mm256_storeu_pd ((double *)P->X, point[0]); 
    _mm256_storeu_pd ((double *)P->X+4, point[1]); 
    _mm256_storeu_pd ((double *)P->Y, point[2]); 
    _mm256_storeu_pd ((double *)P->Y+4, point[3]); 
    _mm256_storeu_pd ((double *)P->Z, point[4]); 
    _mm256_storeu_pd ((double *)P->Z+4, point[5]); 
    _mm256_storeu_pd ((double *)P->Td, point[6]); 
    _mm256_storeu_pd ((double *)P->Td+4, point[7]);
    
    return;
}


void lut_extaff_numsp512t1(point_extaff_precomp_numsp512t1* table, point_extaff_precomp_numsp512t1 P, int digit, int sign, unsigned int npoints, PCurveStruct PCurve)
{ // Constant-time table lookup to extract an affine point (x,y,td) from the precomputed table
  // Twisted Edwards a=1 curve over p = 2^512-319
  // Operation: if sign=0 then P = table[digit], else if (sign=-1) then P = -table[digit]
    unsigned int i;
    int pos, mask;
    __m256d point[6], temp_point[6], full_mask;
            
    pos = digit;                                                           // Load digit position.  
    point[0] = _mm256_loadu_pd ((double const *) table[0]->x);             // point = table[0] 
    point[1] = _mm256_loadu_pd ((double const *) table[0]->x+4);          
    point[2] = _mm256_loadu_pd ((double const *) table[0]->y);  
    point[3] = _mm256_loadu_pd ((double const *) table[0]->y+4);          
    point[4] = _mm256_loadu_pd ((double const *) table[0]->td);  
    point[5] = _mm256_loadu_pd ((double const *) table[0]->td+4);            

    for (i=1; i<npoints; i++) 
    { 
        pos--;
        // If match then mask = 0xFF...F else mask = 0x00...0
        mask = is_digit_nonzero_ct((dig)pos) - 1; 
        full_mask = _mm256_set1_pd ((double)mask);
        temp_point[0] = _mm256_loadu_pd ((double const *) table[i]->x);    // temp_point = table[i+1]
        temp_point[1] = _mm256_loadu_pd ((double const *) table[i]->x+4); 
        temp_point[2] = _mm256_loadu_pd ((double const *) table[i]->y);
        temp_point[3] = _mm256_loadu_pd ((double const *) table[i]->y+4);
        temp_point[4] = _mm256_loadu_pd ((double const *) table[i]->td);
        temp_point[5] = _mm256_loadu_pd ((double const *) table[i]->td+4);
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);    
        point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);      
        point[2] = _mm256_blendv_pd (point[2], temp_point[2], full_mask);   
        point[3] = _mm256_blendv_pd (point[3], temp_point[3], full_mask);     
        point[4] = _mm256_blendv_pd (point[4], temp_point[4], full_mask);   
        point[5] = _mm256_blendv_pd (point[5], temp_point[5], full_mask); 
    }
    
    temp_point[0] = _mm256_loadu_pd ((double const *) point);              // point: x, t coordinate
    temp_point[1] = _mm256_loadu_pd ((double const *) point+1*4);          // temp_point: -x, -t coordinate
    temp_point[4] = _mm256_loadu_pd ((double const *) point+4*4);    
    temp_point[5] = _mm256_loadu_pd ((double const *) point+5*4);
    fpneg512(PCurve->prime, (dig*)&temp_point[0]);  
    fpneg512(PCurve->prime, (dig*)&temp_point[4]); 
    full_mask = _mm256_set1_pd ((double)sign);
    point[0] = _mm256_blendv_pd (point[0], temp_point[0], full_mask);      // if mask = 0xFF...F then choose negative of the point
    point[1] = _mm256_blendv_pd (point[1], temp_point[1], full_mask);
    point[4] = _mm256_blendv_pd (point[4], temp_point[4], full_mask);
    point[5] = _mm256_blendv_pd (point[5], temp_point[5], full_mask);
    _mm256_storeu_pd ((double *)P->x, point[0]); 
    _mm256_storeu_pd ((double *)P->x+4, point[1]); 
    _mm256_storeu_pd ((double *)P->y, point[2]); 
    _mm256_storeu_pd ((double *)P->y+4, point[3]); 
    _mm256_storeu_pd ((double *)P->td, point[4]); 
    _mm256_storeu_pd ((double *)P->td+4, point[5]); 

    return;
}

#endif

#endif



/******** Recoding function for variable-base scalar multiplication ********/

void fixed_window_recode(dig *scalar, unsigned int nbit, unsigned int w, int *digits)
{ // Computes the fixed window representation of scalar, where nonzero digits are in the set {+-1,+-3,...,+-(2^(w-1)-1)}
    dig i, j, val, mask, t, cwords;
    dig temp, res, borrow;

    cwords = NBITS_TO_NWORDS(nbit);               // Number of computer words to represent scalar
    t = (nbit+(w-2))/(w-1);                       // Fixed length of the fixed window representation
    mask = (1 << w) - 1;                          // w-bit mask
    val = (dig)(1 << (w-1));                      // 2^(w-1)

    for (i = 0; i <= (t-1); i++)
    {
        temp = (scalar[0] & mask) - val;          // ki = (k mod 2^w) - 2^(w-1)
        *digits = (int)temp;
        digits++;
                 
        res = scalar[0] - temp;                   // k = (k - ki)
        borrow = ((temp >> (ML_WORD - 1)) - 1) & ((dig)is_digit_lessthan_ct(scalar[0], temp));
        scalar[0] = res;
  
        for (j = 1; j < cwords; j++)
        {
            res = scalar[j];
            scalar[j] = res - borrow;
            borrow = (dig)is_digit_lessthan_ct(res, borrow); 
        }    
  
        for (j = 0; j < cwords-1; j++) {          // k / 2^(w-1) 
            SHIFTR(scalar[j+1], scalar[j], (w-1), scalar[j]);
        }
        scalar[cwords-1] = scalar[cwords-1] >> (w-1);
    } 
    *digits = (int)scalar[0];                     // kt = k  (t+1 digits)

    return;
}


/******** Recoding function for fixed-base scalar multiplication ********/

void mLSB_set_recode(dig *scalar, unsigned int nbit, unsigned int l, unsigned int d, int *digits)
{ //  Computes the modified LSB-set representation of scalar
    unsigned int cwords, i, j;
    dig temp, carry;
    
    cwords = NBITS_TO_NWORDS(nbit);                       // Number of computer words to represent scalar
    digits[d-1] = 0;

    // Shift scalar to the right by 1   
    for (j = 0; j < cwords-1; j++) {
        SHIFTR(scalar[j+1], scalar[j], 1, scalar[j]);
    }
    scalar[cwords-1] = scalar[cwords-1] >> 1;

    for (i = 0; i <= (d-2); i++)
    {
        digits[i] = (int)((scalar[0] & 1) - 1);           // Convention for the "sign" row: 
                                                          // if k_(i+1) = 0 then digit_i = -1 (negative), else if k_(i+1) = 1 then digit_i = 0 (positive)
        // Shift scalar to the right by 1   
        for (j = 0; j < cwords-1; j++) {
            SHIFTR(scalar[j+1], scalar[j], 1, scalar[j]);
        }
        scalar[cwords-1] = scalar[cwords-1] >> 1;
    } 

    for (i = d; i <= (l-1); i++)
    {
        digits[i] = scalar[0] & 1;                        // digits_i = k mod 2. Sign is determined by the "sign" row

        // Shift scalar to the right by 1  
        for (j = 0; j < cwords-1; j++) {
            SHIFTR(scalar[j+1], scalar[j], 1, scalar[j]);
        }
        scalar[cwords-1] = scalar[cwords-1] >> 1;

        temp = -digits[i-(i/d)*d] & digits[i];            // if (digits_i=0 \/ 1) then temp = 0, else if (digits_i=-1) then temp = 1 
            
        // floor(scalar/2) + temp
        scalar[0] = scalar[0] + temp;
        carry = (temp & (~(0-scalar[0]) >> (ML_WORD-1)) & (~scalar[0] >> (ML_WORD-1)));       // carry = (scalar[0] < temp);
        for (j = 1; j < cwords; j++)
        {
            scalar[j] = scalar[j] + carry; 
            carry = (carry & (~(0-scalar[j]) >> (ML_WORD-1)) & (~scalar[j] >> (ML_WORD-1)));  // carry = (scalar[j] < carry);
        }
    } 
    return;              
}


/******** Non-constant time recoding function for double-scalar multiplication ********/

void wNAF_recode(dig *scalar, unsigned int nbits, unsigned int w, int *digits)
{ // Computes wNAF of scalar, where digits are in set {0,+-1,+-3,...,+-(2^(w-1)-1)}
    unsigned int j, cwords, mask;
    int digit, index = 0, val1, val2;
    dig temp = 0, carry;
    
    for (j = 0; j <= nbits; j++) {                         // Initialize digit output to zero
        digits[j] = 0;
    }
    cwords = NBITS_TO_NWORDS(nbits);                       // Number of computer words to represent scalar
    val1 = (int)(1 << (w-1)) - 1;                          // 2^(w-1) - 1
    val2 = (int)(1 << w);                                  // 2^w
    mask = (unsigned int)val2 - 1;                         // 2^w - 1
    
    for (j = 0; j < cwords; j++) {
        temp = temp | scalar[j];
    }

    while (temp != 0)
    {
        digit = (scalar[0] & 1); 

        if (digit == 0) 
        {   // Shift scalar to the right by 1 
            for (j = 0; j < cwords-1; j++) {
                SHIFTR(scalar[j+1], scalar[j], 1, scalar[j]);
            }
            scalar[cwords-1] = scalar[cwords-1] >> 1;
            digits[index] = 0;
        }
        else
        {
            digit = (scalar[0] & mask); 

            // Shift scalar to the right by w
            for (j = 0; j < cwords-1; j++) {
                SHIFTR(scalar[j+1], scalar[j], w, scalar[j]);
            }
            scalar[cwords-1] = scalar[cwords-1] >> w;

            if (digit > val1) {
                digit = digit - val2; 
            }
            if (digit < 0) 
            {   // scalar + 1
                scalar[0] = scalar[0] + 1;
                carry = (scalar[0] < 1);
                for (j = 1; j < cwords; j++)
                {
                    scalar[j] = scalar[j] + carry;                
                    carry = (scalar[j] < carry);
                }
            }
            digits[index] = digit; 
            
            temp = 0;
            for (j = 0; j < cwords; j++) {
                temp = temp | scalar[j];
            }
            if (temp != 0)              // Check if scalar != 0
            {
                for (j = 0; j < (w-1); j++) 
                {     
                    index++; 
                    digits[index] = 0;
                }
            }
        }
        
        // To check if scalar != 0 
        temp = 0;
        for (j = 0; j < cwords; j++) {
            temp = temp | scalar[j];
        }
        index++;
    } 
    return;
}


/******************************** Conversion functions *************************************/

ECCRYPTO_STATUS bytes_to_digits_little_endian(unsigned char* inarray, dig* outarray, dig nbits)
{ // Convert nbits of inarray from bytes to digit format
  // Input and output are in little endian format
    dig dig_temp, mask, ndigits = NBITS_TO_NWORDS(nbits), nbytes_per_digit = sizeof(dig);
    dig i, j, index = 0;

    if (inarray == NULL || outarray == NULL) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    for (i = 0; i < ndigits; i++) {
        dig_temp = 0;
        for (j = 0; j < nbytes_per_digit; j++) {
            mask = (dig)inarray[index] << (8*j);
            dig_temp = dig_temp | mask;
            index++;
        }
        outarray[i] = dig_temp;
    }

    return ECCRYPTO_SUCCESS;
}


const char* ecc_get_error_message(ECCRYPTO_STATUS Status)
{ // Output error/success message for a given ECCRYPTO_STATUS
    struct error_mapping {
        unsigned int index;
        char*        string;
    } mapping[ECCRYPTO_STATUS_TYPE_SIZE] = {
        {ECCRYPTO_ERROR, ECCRYPTO_MSG_ERROR},
        {ECCRYPTO_SUCCESS, ECCRYPTO_MSG_SUCCESS},
        {ECCRYPTO_ERROR_DURING_TEST, ECCRYPTO_MSG_ERROR_DURING_TEST},
        {ECCRYPTO_ERROR_UNKNOWN, ECCRYPTO_MSG_ERROR_UNKNOWN},
        {ECCRYPTO_ERROR_NOT_IMPLEMENTED, ECCRYPTO_MSG_ERROR_NOT_IMPLEMENTED},
        {ECCRYPTO_ERROR_NO_MEMORY, ECCRYPTO_MSG_ERROR_NO_MEMORY},
        {ECCRYPTO_ERROR_INVALID_PARAMETER, ECCRYPTO_MSG_ERROR_INVALID_PARAMETER},
        {ECCRYPTO_ERROR_INVALID_NONCE_FOR_SIGNING, ECCRYPTO_MSG_ERROR_INVALID_NONCE_FOR_SIGNING},
        {ECCRYPTO_ERROR_SHARED_KEY, ECCRYPTO_MSG_ERROR_SHARED_KEY},
        {ECCRYPTO_ERROR_SIGNATURE_VERIFICATION, ECCRYPTO_MSG_ERROR_SIGNATURE_VERIFICATION},
        {ECCRYPTO_ERROR_TOO_MANY_ITERATIONS, ECCRYPTO_MSG_ERROR_TOO_MANY_ITERATIONS}
    };

    if (Status < 0 || Status >= ECCRYPTO_STATUS_TYPE_SIZE || mapping[Status].string == NULL) {
        return "Unrecognized ECCRYPTO_STATUS";
    } else {
        return mapping[Status].string;
    }
};


/************************** Multiprecision and modular operations **************************/

void copy(dig* src, dig* dst, unsigned int nwords)
{ // Copy function dst <- src, where lng(dst) = lng(src) = nwords
    unsigned int i;

    for (i = 0; i < nwords; i++)
    {
        dst[i] = src[i];
    }
}


static void multiply(dig* a, dig* b, dig* c, unsigned int nwords)
{ // Schoolbook multiprecision multiply, c = a*b, where lng(a) = lng(b) = nwords   
     unsigned int i, j;
     dig u, v;
     dig UV[2];
#if TARGET_GENERIC == TRUE 
     dig tempReg;
#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
     uint64_t tempReg;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_AMD64)
     uint128_t tempReg;
#endif
#if (OS_TARGET == OS_LINUX || TARGET == TARGET_ARM)
     dig carry = 0;
#else     
     unsigned char carry = 0;
#endif

     for (i = 0; i < 2*nwords; i++) {
         c[i] = 0;
     }

     for (i = 0; i < nwords; i++)
     {
          u = 0;
          for (j = 0; j < nwords; j++)
          {
               MUL(a[i], b[j], UV + 1, UV[0]); 
               ADDC(0, UV[0], u, carry, v); 
               u = UV[1] + carry;
               ADDC(0, c[i + j], v, carry, v); 
               u = u + carry;
               c[i + j] = v;
          }
          c[nwords + i] = u;
     }
}


static unsigned char add(dig* a, dig* b, dig* c, unsigned int nwords)
{ // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit   
    unsigned int i;
#if TARGET_GENERIC == TRUE 
    dig tempReg;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    uint64_t tempReg;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_AMD64)
    uint128_t tempReg;
#endif  
#if (OS_TARGET == OS_LINUX || TARGET == TARGET_ARM)
     dig carry = 0;
#else     
     unsigned char carry = 0;
#endif

    for (i = 0; i < nwords; i++)
    {
        ADDC(carry, a[i], b[i], carry, c[i]);
    }
    
    return (unsigned char)carry;
}


unsigned char subtract(dig* a, dig* b, dig* c, unsigned int nwords)
{ // Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit   
    unsigned int i;
    unsigned char borrow = 0;
#if TARGET_GENERIC == TRUE 
    dig tempReg;
    unsigned char borrowReg;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    uint64_t tempReg;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_AMD64)
    uint128_t tempReg;
#endif  

    for (i = 0; i < nwords; i++)
    {
        SUBC(borrow, a[i], b[i], borrow, c[i]);
    }

    return borrow;
}


BOOL compare(dig *a, dig *b, unsigned int nwords)
{ // Compare elements a and b, where lng(a) = lng(b) = nwords
  // If a = b then return equal = TRUE, else return equal = FALSE   
    unsigned int i;
    dig temp = 0;
          
    for (i = 0; i < nwords; i++) {                                            
        temp |= (a[i] ^ b[i]);
    }

    return (BOOL)is_digit_zero_ct(temp);
}


void mod_add(dig* a, dig* b, dig* c, dig* modulus, unsigned int nwords)
{ // Modular addition c = a + b (mod modulus), where a,b in [0, modulus-1], lng{a,b,modulus} = nwords   
    unsigned int i;
    dig mask;
    dig temp[MAXWORDS_FIELD];
    unsigned char cout = 0, bout = 0;

    cout = add(a, b, c, nwords);                // (cout, c) =  a + b  
    bout = subtract(c, modulus, c, nwords);     // c = c - modulus
    mask = (dig)(cout - bout);                  // if (cout, c) >= 0 then mask = 0x00..0, else if (cout, c) < 0 then mask = 0xFF..F

    for (i = 0; i < nwords; i++) {              // temp = mask & modulus
        temp[i] = (modulus[i] & mask);
    }
    add(c, temp, c, nwords);                    // c = c + (mask & modulus)

    return;
}


BOOL correction_mod(dig* a, dig* c, dig* modulus, unsigned int nbits_modulus, unsigned int nbits)
{ // Correction c = a (mod modulus), where a,modulus < 2^nbits
  // This operation is intended for cases in which nbits and nbits_modulus are close   
    unsigned int i, j, nwords = NBITS_TO_NWORDS(nbits);
    dig mask, temp[MAXWORDS_FIELD];
    unsigned char bout = 0;

    if (nbits < nbits_modulus) {
        return FALSE;
    }

    copy(a, c, nwords);
    for (j = 0; j < (unsigned int)(1 << (nbits-nbits_modulus+1)); j++) {  // One needs at most 2^(nbits-nbits_modulus+1)-1 passes to reduce any element in [0, 2^(nbits)-1] to [0, 2^(nbits_modulus)-1] 
        bout = subtract(c, modulus, c, nwords);                           // (bout, c) = a - modulus
        mask = (dig)(-bout);                                              // if (bout, c) >= 0 then mask = 0x00..0, else if (bout, c) < 0 then mask = 0xFF..F

        for (i = 0; i < nwords; i++) {                                    // temp = mask & modulus
            temp[i] = (modulus[i] & mask);
        }
        add(c, temp, c, nwords);                                          //  c = c + (mask & modulus)
    }

    // One extra subtraction to verify that the result c < modulus
    bout = subtract(c, modulus, temp, nwords);                            // (bout, temp) = c - modulus
    mask = (dig)(-bout);                                                  // if (bout, temp) >= 0 then mask = 0x00..0, else if (bout, temp) < 0 then mask = 0xFF..F

    return (BOOL)(mask & 1);
}


#if (TARGET_GENERIC == TRUE || TARGET != TARGET_AMD64)

void Montgomery_multiply(dig* ma, dig* mb, dig* mc, dig* modulus, dig* Montgomery_rprime, unsigned int nwords)
{ // Generic Montgomery multiplication, mc = ma*mb*r' mod modulus, where ma,mb,mc in [0, modulus-1], lng{ma,mb,mc,modulus} = nwords
  // ma, mb and mc are assumed to be in Montgomery representation
  // The Montgomery constant r' = -r^(-1) mod 2^(log_2(r)) is passed by Montgomery_rprime, where r is the modulus
    unsigned int i;
    dig mask;
    dig P[2*MAXWORDS_FIELD];
    dig Q[2*MAXWORDS_FIELD];
    dig temp[2*MAXWORDS_FIELD];
    unsigned char cout = 0, bout = 0;
     
    multiply(ma, mb, P, nwords);                 // P = ma * mb
    multiply(P, Montgomery_rprime, Q, nwords);   // Q = P * r' mod 2^(log_2(r))
    multiply(Q, modulus, temp, nwords);          // temp = Q * r
    cout = add(P, temp, temp, 2*nwords);         // (cout, temp) = P + Q * r     

    for (i = 0; i < nwords; i++) {               // (cout, mc) = (P + Q * r)/2^(log_2(r))
        mc[i] = temp[nwords + i];
    }

    // Final, constant-time subtraction     
    bout = subtract(mc, modulus, mc, nwords);    // (cout, mc) = (cout, mc) - r
    mask = (dig)(cout - bout);                   // if (cout, mc) >= 0 then mask = 0x00..0, else if (cout, mc) < 0 then mask = 0xFF..F

    for (i = 0; i < nwords; i++) {               // temp = mask & r
        temp[i] = (modulus[i] & mask);
    }
    add(mc, temp, mc, nwords);                   //  mc = mc + (mask & r)

    return;
}

#else

// Montgomery multiplication functions for x64 platforms

#ifdef ECCURVES_256

void Montgomery_multiply256(dig* ma, dig* mb, dig* mc, dig* modulus, dig* Montgomery_rprime, unsigned int nwords)
{ // Unrolled 256-bit Montgomery multiplication for x64 platforms, mc = ma*mb*r' mod modulus, where ma,mb,mc in [0, modulus-1], lng{ma,mb,mc,modulus} = nwords
  // ma, mb and mc are assumed to be in Montgomery representation
  // The Montgomery constant r' = -r^(-1) mod 2^(log_2(r)) is passed by Montgomery_rprime, where r is the modulus    
    unsigned int i;
    dig UV[2], mask;
    dig q, u = 0, v = 0; 
    dig Z[ML_WORDS256 + 2] = {0};
    unsigned char carry = 0;
#if (OS_TARGET == OS_LINUX && TARGET == TARGET_AMD64)
     uint128_t tempReg;
#endif
    
    // i = 0
    MUL(ma[0], mb[0], UV + 1, UV[0]);
    u = UV[1];
    Z[0] = UV[0];
    MUL(ma[1], mb[0], UV + 1, UV[0]);
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[1] = v;
    MUL(ma[2], mb[0], UV + 1, UV[0]);
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[2] = v;
    MUL(ma[3], mb[0], UV + 1, UV[0]);
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[3] = v;
        
    Z[4] = u;
    Z[5] = 0;
    MUL(Z[0], Montgomery_rprime[0], UV + 1, UV[0]); 
    q = UV[0];
    MUL(modulus[0], q, UV + 1, UV[0]);
    ADDC(0, Z[0], UV[0], carry, v);
    u = UV[1] + carry;    
    MUL(modulus[1], q, UV + 1, UV[0]);
    ADDC(0, Z[1], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[0] = v;
    MUL(modulus[2], q, UV + 1, UV[0]);
    ADDC(0, Z[2], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[1] = v;
    MUL(modulus[3], q, UV + 1, UV[0]);
    ADDC(0, Z[3], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[2] = v;
        
    ADDC(0, Z[4], u, carry, v);
    Z[3] = v;
    Z[4] = Z[5] + carry;
    
    // i = 1
    MUL(ma[0], mb[1], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[0], carry, UV[0]);
    u = UV[1] + carry;
    Z[0] = UV[0];
    MUL(ma[1], mb[1], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[1], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[1] = v;
    MUL(ma[2], mb[1], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[2], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[2] = v;
    MUL(ma[3], mb[1], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[3], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[3] = v;
            
    ADDC(0, Z[4], u, carry, v);
    Z[4] = v;
    Z[5] = carry;
    MUL(Z[0], Montgomery_rprime[0], UV + 1, UV[0]); 
    q = UV[0];
    MUL(modulus[0], q, UV + 1, UV[0]);
    ADDC(0, Z[0], UV[0], carry, v);
    u = UV[1] + carry;    
    MUL(modulus[1], q, UV + 1, UV[0]);
    ADDC(0, Z[1], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[0] = v;
    MUL(modulus[2], q, UV + 1, UV[0]);
    ADDC(0, Z[2], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[1] = v;
    MUL(modulus[3], q, UV + 1, UV[0]);
    ADDC(0, Z[3], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[2] = v;
        
    ADDC(0, Z[4], u, carry, v);
    Z[3] = v;
    Z[4] = Z[5] + carry;
    
    // i = 2
    MUL(ma[0], mb[2], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[0], carry, UV[0]);
    u = UV[1] + carry;
    Z[0] = UV[0];
    MUL(ma[1], mb[2], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[1], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[1] = v;
    MUL(ma[2], mb[2], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[2], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[2] = v;
    MUL(ma[3], mb[2], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[3], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[3] = v;
            
    ADDC(0, Z[4], u, carry, v);
    Z[4] = v;
    Z[5] = carry;
    MUL(Z[0], Montgomery_rprime[0], UV + 1, UV[0]); 
    q = UV[0];
    MUL(modulus[0], q, UV + 1, UV[0]);
    ADDC(0, Z[0], UV[0], carry, v);
    u = UV[1] + carry;    
    MUL(modulus[1], q, UV + 1, UV[0]);
    ADDC(0, Z[1], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[0] = v;
    MUL(modulus[2], q, UV + 1, UV[0]);
    ADDC(0, Z[2], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[1] = v;
    MUL(modulus[3], q, UV + 1, UV[0]);
    ADDC(0, Z[3], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[2] = v;
        
    ADDC(0, Z[4], u, carry, v);
    Z[3] = v;
    Z[4] = Z[5] + carry;
    
    // i = 3
    MUL(ma[0], mb[3], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[0], carry, UV[0]);
    u = UV[1] + carry;
    Z[0] = UV[0];
    MUL(ma[1], mb[3], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[1], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[1] = v;
    MUL(ma[2], mb[3], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[2], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[2] = v;
    MUL(ma[3], mb[3], UV + 1, UV[0]);
    ADDC(0, UV[0], Z[3], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[3] = v;
            
    ADDC(0, Z[4], u, carry, v);
    Z[4] = v;
    Z[5] = carry;
    MUL(Z[0], Montgomery_rprime[0], UV + 1, UV[0]); 
    q = UV[0];
    MUL(modulus[0], q, UV + 1, UV[0]);
    ADDC(0, Z[0], UV[0], carry, v);
    u = UV[1] + carry;    
    MUL(modulus[1], q, UV + 1, UV[0]);
    ADDC(0, Z[1], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[0] = v;
    MUL(modulus[2], q, UV + 1, UV[0]);
    ADDC(0, Z[2], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[1] = v;
    MUL(modulus[3], q, UV + 1, UV[0]);
    ADDC(0, Z[3], UV[0], carry, UV[0]);
    UV[1] = UV[1] + carry;
    ADDC(0, UV[0], u, carry, v);
    u = UV[1] + carry;
    Z[2] = v;
        
    ADDC(0, Z[4], u, carry, v);
    Z[3] = v;
    Z[4] = Z[5] + carry;
    
    // Final, constant-time subtraction     
    carry = subtract(Z, modulus, mc, nwords);  // (cout, mc) = (cout, Z) - r
    mask = (dig)(Z[4] - carry);                // if (cout, mc) >= 0 then mask = 0x00..0, else if (cout, mc) < 0 then mask = 0xFF..F

    for (i = 0; i < nwords; i++) {             // temp = mask & r
        Z[i] = (modulus[i] & mask);
    }
    add(mc, Z, mc, nwords);                    //  mc = mc + (mask & r)

    return;
}

#endif

#ifdef ECCURVES_384

void Montgomery_multiply384(dig* ma, dig* mb, dig* mc, dig* modulus, dig* Montgomery_rprime, unsigned int nwords)
{ // 384-bit Montgomery multiplication for x64 platforms, mc = ma*mb*r' mod modulus, where ma,mb,mc in [0, modulus-1], lng{ma,mb,mc,modulus} = nwords
  // ma, mb and mc are assumed to be in Montgomery representation
  // The Montgomery constant r' = -r^(-1) mod 2^(log_2(r)) is passed by Montgomery_rprime, where r is the modulus   
    unsigned int i;
    dig mask;
    dig P[2*MAXWORDS_FIELD];
    dig Q[2*MAXWORDS_FIELD];
    dig temp[2*MAXWORDS_FIELD];
    unsigned char cout = 0, bout = 0;           

    multiply(ma, mb, P, nwords);                 // P = ma * mb
    multiply(P, Montgomery_rprime, Q, nwords);   // Q = P * r' mod 2^(log_2(r))
    multiply(Q, modulus, temp, nwords);          // temp = Q * r
    cout = add(P, temp, temp, 2*nwords);         // (cout, temp) = P + Q * r     

    for (i = 0; i < nwords; i++) {               // (cout, mc) = (P + Q * r)/2^(log_2(r))
        mc[i] = temp[nwords + i];
    }

    // Final, constant-time subtraction     
    bout = subtract(mc, modulus, mc, nwords);    // (cout, mc) = (cout, mc) - r
    mask = (dig)(cout - bout);                   // if (cout, mc) >= 0 then mask = 0x00..0, else if (cout, mc) < 0 then mask = 0xFF..F

    for (i = 0; i < nwords; i++) {               // temp = mask & r
        temp[i] = (modulus[i] & mask);
    }
    add(mc, temp, mc, nwords);                   //  mc = mc + (mask & r)

    return;
}

#endif

#ifdef ECCURVES_512

void Montgomery_multiply512(dig* ma, dig* mb, dig* mc, dig* modulus, dig* Montgomery_rprime, unsigned int nwords)
{ // 512-bit Montgomery multiplication for x64 platforms, mc = ma*mb*r' mod modulus, where ma,mb,mc in [0, modulus-1], lng{ma,mb,mc,modulus} = nwords
  // ma, mb and mc are assumed to be in Montgomery representation
  // The Montgomery constant r' = -r^(-1) mod 2^(log_2(r)) is passed by Montgomery_rprime, where r is the modulus   
    unsigned int i;
    dig mask;
    dig P[2*MAXWORDS_FIELD];
    dig Q[2*MAXWORDS_FIELD];
    dig temp[2*MAXWORDS_FIELD];
    unsigned char cout = 0, bout = 0;           
     
    multiply(ma, mb, P, nwords);                 // P = ma * mb
    multiply(P, Montgomery_rprime, Q, nwords);   // Q = P * r' mod 2^(log_2(r))
    multiply(Q, modulus, temp, nwords);          // temp = Q * r
    cout = add(P, temp, temp, 2*nwords);         // (cout, temp) = P + Q * r     

    for (i = 0; i < nwords; i++) {               // (cout, mc) = (P + Q * r)/2^(log_2(r))
        mc[i] = temp[nwords + i];
    }

    // Final, constant-time subtraction     
    bout = subtract(mc, modulus, mc, nwords);    // (cout, mc) = (cout, mc) - r
    mask = (dig)(cout - bout);                   // if (cout, mc) >= 0 then mask = 0x00..0, else if (cout, mc) < 0 then mask = 0xFF..F

    for (i = 0; i < nwords; i++) {               // temp = mask & r
        temp[i] = (modulus[i] & mask);
    }
    add(mc, temp, mc, nwords);                   //  mc = mc + (mask & r)

    return;
}

#endif

#endif


ECCRYPTO_STATUS random_mod_order(dig* random_digits, PCurveStruct PCurve)
{ // Output random values in the range [1, order-1] in little endian format that can be used as nonces or private keys.
  // It makes requests of random values with length "rbits" to the "random_bytes" function. The process repeats until random value is in [0, order-2]. 
  // If successful, the output is given in "random_digits" in the range [1, order-1].
  // The "random_bytes" function, which is passed through the curve structure PCurve, should be set up in advance using ecc_curve_initialize(). 
  // It follows the procedure in "Digital Signature Standard (DSS), FIPS.186-4" (see App. B.4.2 and B.5.2) to generate nonces and private keys.
  // The caller is responsible of providing the "random_bytes" function passing random values as octets in little endian format.
    unsigned int ntry = 0, nbytes, nwords;    
    dig t1[MAXWORDS_FIELD] = {0}, order2[MAXWORDS_FIELD] = {0};
    unsigned int i;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (random_digits == NULL || is_ecc_curve_null(PCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    nbytes = (PCurve->rbits+7)/8;                           // Number of random bytes to be requested 
    nwords = NBITS_TO_NWORDS(PCurve->rbits);
    
    t1[0] = 2;
    subtract(PCurve->order, t1, order2, nwords);            // order2 = order-2

    do {
        ntry++;
        if (ntry > 100) {                                   // Max. 100 iterations to obtain random value in [0, order-2] 
            return ECCRYPTO_ERROR_TOO_MANY_ITERATIONS;
            goto cleanup;
        }
        Status = (PCurve->RandomBytesFunction)(nbytes, (unsigned char*)random_digits);
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    } while (subtract(order2, random_digits, t1, nwords) == 1);
    
    for (i = 1; i < MAXWORDS_FIELD; i++) {
        t1[i] = 0;
    }
    t1[0] = 1;
    add(random_digits, t1, random_digits, nwords);          // Output in the range [1, order-1]

cleanup:
    if (Status != ECCRYPTO_SUCCESS) {
        for (i = 0; i < nwords; i++) {
            ((dig volatile*)random_digits)[i] = 0;
        }
    }

    return Status;
}


/************************** Wrappers for modular operations using the order of a curve **************************/

void addition_mod_order(dig* a, dig* b, dig* c, PCurveStruct PCurve)
{ // Addition modulo the order, c = a+b mod r, where a,b,c in [0, r-1] 
    mod_add(a, b, c, PCurve->order, NBITS_TO_NWORDS(PCurve->rbits));
}

BOOL correction_mod_order(dig* a, dig* c, PCurveStruct PCurve)
{ // Modular correction using the order of a curve, c = a mod r, where a,r < 2^nbits
    return correction_mod(a, c, PCurve->order, PCurve->rbits, PCurve->nbits);
}

BOOL compare_mod_order(dig *a, dig *b, PCurveStruct PCurve)
{ // Compare elements a and b, where a,b in [1, r-1]     
  // If a = b then return TRUE, else return FALSE
    return compare(a, b, NBITS_TO_NWORDS(PCurve->rbits));
}
