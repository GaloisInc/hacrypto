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
* Abstract: core GF(p^2) and ECC operations over GF(p^2)
*
* This code is based on the paper "FourQ: four-dimensional decompositions on a 
* Q-curve over the Mersenne prime" by Craig Costello and Patrick Longa, in Advances 
* in Cryptology - ASIACRYPT, 2015.
* Preprint available at http://eprint.iacr.org/2015/565.
************************************************************************************/ 

#include "FourQ.h"
#if defined(GENERIC_IMPLEMENTATION)
    #include "generic/fp.h"
#else
    #include "AMD64/fp_x64.h"
#endif
#include <malloc.h>


/***********************************************/
/************* GF(p^2) FUNCTIONS ***************/

void fp2copy1271(f2elm_t a, f2elm_t c)
{// Copy of a GF(p^2) element, c = a
    fpcopy1271(a[0], c[0]);
    fpcopy1271(a[1], c[1]);
}


void fp2zero1271(f2elm_t a)
{// Zeroing a GF(p^2) element, a = 0
    fpzero1271(a[0]);
    fpzero1271(a[1]);
}


void fp2neg1271(f2elm_t a)
{// GF(p^2) negation, a = -a in GF((2^127-1)^2)
    fpneg1271(a[0]);
    fpneg1271(a[1]);
}


void fp2sqr1271(f2elm_t a, f2elm_t c)
{// GF(p^2) squaring, c = a^2 in GF((2^127-1)^2)

#ifdef ASM_SUPPORT
    fp2sqr1271_a(a, c);
#else
    felm_t t1, t2, t3;

    fpadd1271(a[0], a[1], t1);           // t1 = a0+a1 
    fpsub1271(a[0], a[1], t2);           // t2 = a0-a1
    fpmul1271(a[0], a[1], t3);           // t3 = a0*a1
    fpmul1271(t1, t2, c[0]);             // c0 = (a0+a1)(a0-a1)
    fpadd1271(t3, t3, c[1]);             // c1 = 2a0*a1
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(felm_t)/sizeof(unsigned int));
    clear_words((void*)t2, sizeof(felm_t)/sizeof(unsigned int));
    clear_words((void*)t3, sizeof(felm_t)/sizeof(unsigned int));
#endif
#endif
}


void fp2mul1271(f2elm_t a, f2elm_t b, f2elm_t c)
{// GF(p^2) multiplication, c = a*b in GF((2^127-1)^2)

#if defined(ASM_SUPPORT)        
    fp2mul1271_a(a, b, c);
#else
    felm_t t1, t2, t3, t4;
    
    fpmul1271(a[0], b[0], t1);          // t1 = a0*b0
    fpmul1271(a[1], b[1], t2);          // t2 = a1*b1
    fpadd1271(a[0], a[1], t3);          // t3 = a0+a1
    fpadd1271(b[0], b[1], t4);          // t4 = b0+b1
    fpsub1271(t1, t2, c[0]);            // c[0] = a0*b0 - a1*b1
    fpmul1271(t3, t4, t3);              // t3 = (a0+a1)*(b0+b1)
    fpsub1271(t3, t1, t3);              // t3 = (a0+a1)*(b0+b1) - a0*b0
    fpsub1271(t3, t2, c[1]);            // c[1] = (a0+a1)*(b0+b1) - a0*b0 - a1*b1    
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(felm_t)/sizeof(unsigned int));
    clear_words((void*)t2, sizeof(felm_t)/sizeof(unsigned int));
    clear_words((void*)t3, sizeof(felm_t)/sizeof(unsigned int));
    clear_words((void*)t4, sizeof(felm_t)/sizeof(unsigned int));
#endif
#endif
}


__inline void fp2add1271(f2elm_t a, f2elm_t b, f2elm_t c)
{// GF(p^2) addition, c = a+b in GF((2^127-1)^2)
    fpadd1271(a[0], b[0], c[0]);
    fpadd1271(a[1], b[1], c[1]);
}


__inline void fp2sub1271(f2elm_t a, f2elm_t b, f2elm_t c)
{// GF(p^2) subtraction, c = a-b in GF((2^127-1)^2) 
    fpsub1271(a[0], b[0], c[0]);
    fpsub1271(a[1], b[1], c[1]);
}


static __inline void fp2addsub1271(f2elm_t a, f2elm_t b, f2elm_t c)
{// GF(p^2) addition followed by subtraction, c = 2a-b in GF((2^127-1)^2)

#ifdef ASM_SUPPORT
    fp2addsub1271_a(a, b, c);
#else
    fp2add1271(a, a, a);
    fp2sub1271(a, b, c);
#endif
}


void fp2inv1271(f2elm_t a)
{// GF(p^2) inversion, a = (a0-i*a1)/(a0^2+a1^2)
    f2elm_t t1;

    fpsqr1271(a[0], t1[0]);             // t10 = a0^2
    fpsqr1271(a[1], t1[1]);             // t11 = a1^2
    fpadd1271(t1[0], t1[1], t1[0]);     // t10 = a0^2+a1^2
    fpinv1271(t1[0]);                   // t10 = (a0^2+a1^2)^-1
    fpneg1271(a[1]);                    // a = a0-i*a1
    fpmul1271(a[0], t1[0], a[0]);
    fpmul1271(a[1], t1[0], a[1]);       // a = (a0-i*a1)*(a0^2+a1^2)^-1
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(f2elm_t)/sizeof(unsigned int));
#endif
}


#ifdef TEMP_ZEROING
extern __inline void clear_words(void* mem, unsigned int nwords)
{ // Clear integer-size digits from memory. "nwords" indicates the number of integer digits to be zeroed.
  // This function uses the volatile type qualifier to inform the compiler not to optimize out the memory clearing.
  // It has been tested with MSVS 2013 and GNU GCC 4.6.3, 4.7.3, 4.8.2 and 4.8.4. Users are responsible for verifying correctness with different compilers.  
  // See "Compliant Solution (C99)" at https://www.securecoding.cert.org/confluence/display/c/MSC06-C.+Beware+of+compiler+optimizations 
    unsigned int i;
    volatile unsigned int *v = mem; 

    for (i = 0; i < nwords; i++)
        v[i] = 0;
}
#endif


/***********************************************/
/**********  CURVE/SCALAR FUNCTIONS  ***********/

void eccset(point_t P, PCurveStruct curve)
{ // Set generator  
  // Output: P = (x,y)
    
    fp2copy1271((felm_t*)&curve->generator_x, P->x);    // X1
    fp2copy1271((felm_t*)&curve->generator_y, P->y);    // Y1
}


void eccnorm(point_extproj_t P, point_t Q)
{ // Normalize a projective point (X1:Y1:Z1), including full reduction
  // Input: P = (X1:Y1:Z1) in twisted Edwards coordinates    
  // Output: Q = (X1/Z1,Y1/Z1), corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
    
    fp2inv1271(P->z);                      // Z1 = Z1^-1
    fp2mul1271(P->x, P->z, Q->x);          // X1 = X1/Z1
    fp2mul1271(P->y, P->z, Q->y);          // Y1 = Y1/Z1
    mod1271(Q->x[0]); mod1271(Q->x[1]); 
    mod1271(Q->y[0]); mod1271(Q->y[1]); 
}


extern __inline void R1_to_R2(point_extproj_t P, point_extproj_precomp_t Q, PCurveStruct curve) 
{ // Conversion from representation (X,Y,Z,Ta,Tb) to (X+Y,Y-X,2Z,2dT), where T = Ta*Tb
  // Input:  P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  // Output: Q = (X1+Y1,Y1-X1,2Z1,2dT1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
    
    fp2add1271(P->ta, P->ta, Q->t2);              // T = 2*Ta
    fp2add1271(P->x, P->y, Q->xy);                // QX = X+Y
    fp2sub1271(P->y, P->x, Q->yx);                // QY = Y-X 
    fp2mul1271(Q->t2, P->tb, Q->t2);              // T = 2*T
    fp2add1271(P->z, P->z, Q->z2);                // QZ = 2*Z
    fp2mul1271(Q->t2, (felm_t*)&curve->d, Q->t2); // QT = 2d*T
}


void R1_to_R2_ni(point_extproj_t P, point_extproj_precomp_t Q, PCurveStruct curve) 
{
    R1_to_R2(P, Q, curve);
}


__inline void R1_to_R3(point_extproj_t P, point_extproj_precomp_t Q)      
{ // Conversion from representation (X,Y,Z,Ta,Tb) to (X+Y,Y-X,Z,T), where T = Ta*Tb 
  // Input:  P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  // Output: Q = (X1+Y1,Y1-X1,Z1,T1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates 
    
    fp2add1271(P->x, P->y, Q->xy);         // XQ = (X1+Y1) 
    fp2sub1271(P->y, P->x, Q->yx);         // YQ = (Y1-X1) 
    fp2mul1271(P->ta, P->tb, Q->t2);       // TQ = T1
    fp2copy1271(P->z, Q->z2);              // ZQ = Z1 
}


void R2_to_R4(point_extproj_precomp_t P, point_extproj_t Q)      
{ // Conversion from representation (X+Y,Y-X,2Z,2dT) to (2X,2Y,2Z,2dT) 
  // Input:  P = (X1+Y1,Y1-X1,2Z1,2dT1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  // Output: Q = (2X1,2Y1,2Z1) corresponding to (X1:Y1:Z1) in twisted Edwards coordinates 
    
    fp2sub1271(P->xy, P->yx, Q->x);        // XQ = 2*X1
    fp2add1271(P->xy, P->yx, Q->y);        // YQ = 2*Y1
    fp2copy1271(P->z2, Q->z);              // ZQ = 2*Z1
}


__inline void eccdouble(point_extproj_t P)
{ // Point doubling 2P
  // Input: P = (X1:Y1:Z1) in twisted Edwards coordinates
  // Output: 2P = (Xfinal,Yfinal,Zfinal,Tafinal,Tbfinal), where Tfinal = Tafinal*Tbfinal,
  //         corresponding to (Xfinal:Yfinal:Zfinal:Tfinal) in extended twisted Edwards coordinates
    f2elm_t t1, t2;  

    fp2sqr1271(P->x, t1);                  // t1 = X1^2
    fp2sqr1271(P->y, t2);                  // t2 = Y1^2
    fp2add1271(P->x, P->y, P->x);          // t3 = X1+Y1
    fp2add1271(t1, t2, P->tb);             // Tbfinal = X1^2+Y1^2      
    fp2sub1271(t2, t1, t1);                // t1 = Y1^2-X1^2
    fp2sqr1271(P->z, t2);                  // t2 = Z1^2        
    fp2sqr1271(P->x, P->ta);               // Ta = (X1+Y1)^2 
    fp2sub1271(P->ta, P->tb, P->ta);       // Tafinal = 2X1*Y1 = (X1+Y1)^2-(X1^2+Y1^2)  
    fp2addsub1271(t2, t1, t2);             // t2 = 2Z1^2-(Y1^2-X1^2) 
    fp2mul1271(t1, P->tb, P->y);           // Yfinal = (X1^2+Y1^2)(Y1^2-X1^2)  
    fp2mul1271(t2, P->ta, P->x);           // Xfinal = 2X1*Y1*[2Z1^2-(Y1^2-X1^2)]
    fp2mul1271(t1, t2, P->z);              // Zfinal = (Y1^2-X1^2)[2Z1^2-(Y1^2-X1^2)]
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(f2elm_t)/sizeof(unsigned int));
    clear_words((void*)t2, sizeof(f2elm_t)/sizeof(unsigned int));
#endif
}


__inline void eccadd_core(point_extproj_precomp_t P, point_extproj_precomp_t Q, point_extproj_t R)      
{ // Basic point addition R = P+Q or R = P+P
  // Inputs: P = (X1+Y1,Y1-X1,2Z1,2dT1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  //         Q = (X2+Y2,Y2-X2,Z2,T2) corresponding to (X2:Y2:Z2:T2) in extended twisted Edwards coordinates    
  // Output: R = (Xfinal,Yfinal,Zfinal,Tafinal,Tbfinal), where Tfinal = Tafinal*Tbfinal,
  //         corresponding to (Xfinal:Yfinal:Zfinal:Tfinal) in extended twisted Edwards coordinates
    f2elm_t t1, t2; 
          
    fp2mul1271(P->t2, Q->t2, R->z);        // Z = 2dT1*T2 
    fp2mul1271(P->z2, Q->z2, t1);          // t1 = 2Z1*Z2  
    fp2mul1271(P->xy, Q->xy, R->x);        // X = (X1+Y1)(X2+Y2) 
    fp2mul1271(P->yx, Q->yx, R->y);        // Y = (Y1-X1)(Y2-X2) 
    fp2sub1271(t1, R->z, t2);              // t2 = theta
    fp2add1271(t1, R->z, t1);              // t1 = alpha
    fp2sub1271(R->x, R->y, R->tb);         // Tbfinal = beta
    fp2add1271(R->x, R->y, R->ta);         // Tafinal = omega
    fp2mul1271(R->tb, t2, R->x);           // Xfinal = beta*theta
    fp2mul1271(t1, t2, R->z);              // Zfinal = theta*alpha
    fp2mul1271(R->ta, t1, R->y);           // Yfinal = alpha*omega
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(f2elm_t)/sizeof(unsigned int));
    clear_words((void*)t2, sizeof(f2elm_t)/sizeof(unsigned int));
#endif
}


__inline void eccadd(point_extproj_precomp_t Q, point_extproj_t P)      
{ // Complete point addition P = P+Q or P = P+P
  // Inputs: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  //         Q = (X2+Y2,Y2-X2,2Z2,2dT2) corresponding to (X2:Y2:Z2:T2) in extended twisted Edwards coordinates   
  // Output: P = (Xfinal,Yfinal,Zfinal,Tafinal,Tbfinal), where Tfinal = Tafinal*Tbfinal, 
  //         corresponding to (Xfinal:Yfinal:Zfinal:Tfinal) in extended twisted Edwards coordinates
    point_extproj_precomp_t R;
    
    R1_to_R3(P, R);                        // R = (X1+Y1,Y1-Z1,Z1,T1)
    eccadd_core(Q, R, P);                  // P = (X2+Y2,Y2-X2,2Z2,2dT2) + (X1+Y1,Y1-Z1,Z1,T1)

#ifdef TEMP_ZEROING
    clear_words((void*)R, sizeof(point_extproj_precomp_t)/sizeof(unsigned int));
#endif
}


void eccadd_ni(point_extproj_precomp_t Q, point_extproj_t P)
{
    eccadd(Q, P);
}


void eccdouble_ni(point_extproj_t P)
{
    eccdouble(P);
}


__inline void point_setup(point_t P, point_extproj_t Q)
{ // Modular correction of input coordinates and conversion to representation (X,Y,Z,Ta,Tb) 
  // Input: P = (x,y) in affine coordinates
  // Output: P = (X,Y,1,Ta,Tb), where Ta=X, Tb=Y and T=Ta*Tb, corresponding to (X:Y:Z:T) in extended twisted Edwards coordinates, 
  //         such that 0 <= a,b,c,d <= 2^127-1 with X=a+b*i and Y=c+d*i

    P->x[0][NWORDS_FIELD-1] = (P->x[0][NWORDS_FIELD-1] << 1) >> 1;
    P->x[1][NWORDS_FIELD-1] = (P->x[1][NWORDS_FIELD-1] << 1) >> 1;
    P->y[0][NWORDS_FIELD-1] = (P->y[0][NWORDS_FIELD-1] << 1) >> 1;
    P->y[1][NWORDS_FIELD-1] = (P->y[1][NWORDS_FIELD-1] << 1) >> 1;
    fp2copy1271(P->x, Q->x);
    fp2copy1271(P->y, Q->y);
    fp2copy1271(Q->x, Q->ta);              // Ta = X1
    fp2copy1271(Q->y, Q->tb);              // Tb = Y1
    fp2zero1271(Q->z); Q->z[0][0]=1;       // Z1 = 1
}


void point_setup_ni(point_t P, point_extproj_t Q)
{
    point_setup(P, Q);
}


extern __inline bool ecc_point_validate(point_extproj_t P, PCurveStruct curve)
{ // Point validation: check if point lies on the curve
  // Input: P = (x,y) in affine coordinates, where x, y in [0, 2^127-1]. 
  // Output: TRUE (1) if point lies on the curve E: -x^2+y^2-1-dx^2*y^2 = 0, FALSE (0) otherwise.
  // Point_setup() corrects the input coordinates to be in [0, 2^127-1] as required by this function. 
    f2elm_t t1, t2, t3;

    fp2sqr1271(P->y, t1);  
    fp2sqr1271(P->x, t2);
    fp2sub1271(t1, t2, t3);                 // -x^2 + y^2 
    fp2mul1271(t1, t2, t1);                 // x^2*y^2
    fp2mul1271((felm_t*)&curve->d, t1, t2); // dx^2*y^2
    fp2zero1271(t1);  t1[0][0] = 1;         // t1 = 1
    fp2add1271(t2, t1, t2);                 // 1 + dx^2*y^2
    fp2sub1271(t3, t2, t1);                 // -x^2 + y^2 - 1 - dx^2*y^2
    
#if defined(GENERIC_IMPLEMENTATION)
    { unsigned int i, j;
    mod1271(t1[0]);
    mod1271(t1[1]);

    for (i = 0; i < 2; i++) {
        for (j = 0; j < NWORDS_FIELD; j++) {
            if (t1[i][j] != 0) return false;
        }
    }

    return true; }
#else
    return ((is_digit_zero_ct(t1[0][0] | t1[0][1]) || is_digit_zero_ct(t1[0][0]+1 | t1[0][1]+1)) &
            (is_digit_zero_ct(t1[1][0] | t1[1][1]) || is_digit_zero_ct(t1[1][0]+1 | t1[1][1]+1)));
#endif
}


#if defined(USE_FIXED_BASE_SM)

static __inline void R5_to_R1(point_precomp_t P, point_extproj_t Q)      
{ // Conversion from representation (x+y,y-x,2dt) to (X,Y,Z,Ta,Tb) 
  // Input:  P = (x1+y1,y1-x1,2dt1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates, where Z1=1
  // Output: Q = (x1,y1,z1,x1,y1), where z1=1, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates 
    
    fp2sub1271(P->xy, P->yx, Q->x);        // 2*x1
    fp2add1271(P->xy, P->yx, Q->y);        // 2*y1
    fp2div1271(Q->x);                      // XQ = x1
    fp2div1271(Q->y);                      // YQ = y1 
    fp2zero1271(Q->z); Q->z[0][0]=1;       // ZQ = 1
    fp2copy1271(Q->x, Q->ta);              // TaQ = x1
    fp2copy1271(Q->y, Q->tb);              // TbQ = y1
}


static __inline void eccmadd(point_precomp_t Q, point_extproj_t P)
{ // Mixed point addition P = P+Q or P = P+P
  // Inputs: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  //         Q = (x2+y2,y2-x2,2dt2) corresponding to (X2:Y2:Z2:T2) in extended twisted Edwards coordinates, where Z2=1  
  // Output: P = (Xfinal,Yfinal,Zfinal,Tafinal,Tbfinal), where Tfinal = Tafinal*Tbfinal, 
  //         corresponding to (Xfinal:Yfinal:Zfinal:Tfinal) in extended twisted Edwards coordinates
    f2elm_t t1, t2;
    
    fp2mul1271(P->ta, P->tb, P->ta);        // Ta = T1
    fp2add1271(P->z, P->z, t1);             // t1 = 2Z1        
    fp2mul1271(P->ta, Q->t2, P->ta);        // Ta = 2dT1*t2 
    fp2add1271(P->x, P->y, P->z);           // Z = (X1+Y1) 
    fp2sub1271(P->y, P->x, P->tb);          // Tb = (Y1-X1)
    fp2sub1271(t1, P->ta, t2);              // t2 = theta
    fp2add1271(t1, P->ta, t1);              // t1 = alpha
    fp2mul1271(Q->xy, P->z, P->ta);         // Ta = (X1+Y1)(x2+y2)
    fp2mul1271(Q->yx, P->tb, P->x);         // X = (Y1-X1)(y2-x2)
    fp2mul1271(t1, t2, P->z);               // Zfinal = theta*alpha
    fp2sub1271(P->ta, P->x, P->tb);         // Tbfinal = beta
    fp2add1271(P->ta, P->x, P->ta);         // Tafinal = omega
    fp2mul1271(P->tb, t2, P->x);            // Xfinal = beta*theta
    fp2mul1271(P->ta, t1, P->y);            // Yfinal = alpha*omega
#ifdef TEMP_ZEROING
    clear_words((void*)t1, sizeof(f2elm_t)/sizeof(unsigned int));
    clear_words((void*)t2, sizeof(f2elm_t)/sizeof(unsigned int));
#endif
}


void eccmadd_ni(point_precomp_t Q, point_extproj_t P)
{
    eccmadd(Q, P);
}


bool ecc_mul_fixed(point_precomp_t *P_table, digit64_256_t k, point_t Q, PCurveStruct curve)
{ // Fixed-base scalar multiplication Q = k*P, where the base point P is passed through P_table which contains multiples of P.
  // Inputs: precomputed table "P_table" containing v*2^(w-1) points that are generated by the function ecc_precomp_fixed(), 
  //         where v, w determine the size of P_table. The values for v and w are fixed and must be in the range [1, 10] (see FourQ.h).
  //         Scalar "k" in [0, 2^256-1].
  //         FourQ structure "curve".
  // Output: Q = k*P in affine coordinates (x,y).
  // The function is based on the modified LSB-set comb method, which converts the scalar to an odd signed representation
  // with (bitlength(order)+w*v) digits.
    unsigned int j, w = W_FIXEDBASE, v = V_FIXEDBASE, d = D_FIXEDBASE, e = E_FIXEDBASE;
    unsigned int digit = 0, digits[NBITS_ORDER_PLUS_ONE+(W_FIXEDBASE*V_FIXEDBASE)-1] = {0}; 
    uint64_t temp[NWORDS64_ORDER];
    point_extproj_t R;
    point_precomp_t S;
    int i, ii;
    
    modulo_order((digit_t*)k, (digit_t*)k, curve);              // k = k mod (order) 
    conversion_to_odd((digit_t*)k, (digit_t*)temp, curve);      // Converting scalar to odd using the prime subgroup order
    mLSB_set_recode(temp, digits);                              // Scalar recoding

    // Extracting initial digit 
    digit = digits[w*d-1];
    for (i = (int)((w-1)*d-1); i >= (int)(2*d-1); i = i-d)           
    {
        digit = 2*digit + digits[i];
    }
    // Initialize R = (x+y,y-x,2dt) with a point from the table
    table_lookup_fixed_base(P_table+(v-1)*(1 << (w-1)), S, digit, digits[d-1]);
    R5_to_R1(S, R);                                             // Converting to representation (X:Y:1:Ta:Tb)

    for (j = 0; j < (v-1); j++)
    {
        digit = digits[w*d-(j+1)*e-1];
        for (i = (int)((w-1)*d-(j+1)*e-1); i >= (int)(2*d-(j+1)*e-1); i = i-d)           
        {
            digit = 2*digit + digits[i];
        }
        // Extract point in (x+y,y-x,2dt) representation
        table_lookup_fixed_base(P_table+(v-j-2)*(1 << (w-1)), S, digit, digits[d-(j+1)*e-1]);  
        eccmadd(S, R);                                          // R = R+S using representations (X,Y,Z,Ta,Tb) <- (X,Y,Z,Ta,Tb) + (x+y,y-x,2dt) 
    }

    for (ii = (e-2); ii >= 0; ii--)
    {
        eccdouble(R);                                           // R = 2*R using representations (X,Y,Z,Ta,Tb) <- 2*(X,Y,Z)
        for (j = 0; j < v; j++)
        {
            digit = digits[w*d-j*e+ii-e];
            for (i = (int)((w-1)*d-j*e+ii-e); i >= (int)(2*d-j*e+ii-e); i = i-d)           
            {
                digit = 2*digit + digits[i];
            }
            // Extract point in (x+y,y-x,2dt) representation
            table_lookup_fixed_base(P_table+(v-j-1)*(1 << (w-1)), S, digit, digits[d-j*e+ii-e]); 
            eccmadd(S, R);                                      // R = R+S using representations (X,Y,Z,Ta,Tb) <- (X,Y,Z,Ta,Tb) + (x+y,y-x,2dt)
        }        
    }     
    eccnorm(R, Q);                                              // Conversion to affine coordinates (x,y) and modular correction. 
    
#ifdef TEMP_ZEROING
    clear_words((void*)digits, NBITS_ORDER_PLUS_ONE+(W_FIXEDBASE*V_FIXEDBASE)-1);
    clear_words((void*)S, sizeof(point_precomp_t)/sizeof(unsigned int));
#endif
    return true;
}


void mLSB_set_recode(digit64_256_t scalar, unsigned int *digits)
{ // Computes the modified LSB-set representation of a scalar
  // Inputs: scalar in [0, order-1], where the order of FourQ's subgroup is 246 bits.
  // Output: digits, where the first "d" values (from index 0 to (d-1)) store the signs for the recoded values using the convention: -1 (negative), 0 (positive), and
  //         the remaining values (from index d to (l-1)) store the recoded values in mLSB-set representation, excluding their sign, 
  //         where l = d*w and d = ceil(bitlength(order)/(w*v))*v. The values v and w are fixed and must be in the range [1, 10] (see FourQ.h); they determine the size 
  //         of the precomputed table "P_table" used by ecc_mul_fixed(). 
    unsigned int i, j, d = D_FIXEDBASE, l = L_FIXEDBASE;
    uint64_t temp, carry;
    
    digits[d-1] = 0;

    // Shift scalar to the right by 1   
    for (j = 0; j < (NWORDS64_ORDER-1); j++) {
        SHIFTR(scalar[j+1], scalar[j], 1, scalar[j], RADIX64);
    }
    scalar[NWORDS64_ORDER-1] >>= 1;

    for (i = 0; i < (d-1); i++)
    {
        digits[i] = (unsigned int)((scalar[0] & 1) - 1);  // Convention for the "sign" row: 
                                                          // if scalar_(i+1) = 0 then digit_i = -1 (negative), else if scalar_(i+1) = 1 then digit_i = 0 (positive)
        // Shift scalar to the right by 1   
        for (j = 0; j < (NWORDS64_ORDER-1); j++) {
            SHIFTR(scalar[j+1], scalar[j], 1, scalar[j], RADIX64);
        }
        scalar[NWORDS64_ORDER-1] >>= 1;
    } 

    for (i = d; i < l; i++)
    {
        digits[i] = (unsigned int)(scalar[0] & 1);        // digits_i = k mod 2. Sign is determined by the "sign" row

        // Shift scalar to the right by 1  
        for (j = 0; j < (NWORDS64_ORDER-1); j++) {
            SHIFTR(scalar[j+1], scalar[j], 1, scalar[j], RADIX64);
        }
        scalar[NWORDS64_ORDER-1] >>= 1;

        temp = (0 - digits[i-(i/d)*d]) & digits[i];       // if (digits_i=0 \/ 1) then temp = 0, else if (digits_i=-1) then temp = 1 
            
        // floor(scalar/2) + temp
        scalar[0] = scalar[0] + temp;
        carry = (temp & (uint64_t)is_digit_zero_ct((digit_t)scalar[0]));       // carry = (scalar[0] < temp);
        for (j = 1; j < NWORDS64_ORDER; j++)
        {
            scalar[j] = scalar[j] + carry; 
            carry = (carry & (uint64_t)is_digit_zero_ct((digit_t)scalar[j]));  // carry = (scalar[j] < temp);
        }
    } 
    return;              
}


point_precomp_t* ecc_allocate_precomp(void)
{ // Allocates memory dynamically for precomputation table "T_fixed" used during fixed-base scalar multiplications.
  // This function must be called before using ecc_precomp_fixed(), which generates a precomputed table with v*2(w-1) points.

    return (point_precomp_t*)calloc(NPOINTS_FIXEDBASE, sizeof(point_precomp_t));
}


bool ecc_precomp_fixed(point_t P, point_precomp_t* Table, bool clear_cofactor, PCurveStruct curve)
{ // Generation of the precomputation table used by the fixed-base scalar multiplication function ecc_mul_fixed(). 
  // Inputs: point P in affine representation (x,y),
  //         Table with storage for v*2(w-1) points. Allocation for this space must be done by calling ecc_allocate_precomp(), 
  //         clear_cofactor = 1 (TRUE) or 0 (FALSE) whether cofactor clearing is required or not, respectively,
  //         FourQ structure "curve".
  // Output: Table containing multiples of the base point P using affine coordinates with representation (x+y,y-x,2dt). 
  // This function performs point validation and (if selected) cofactor clearing.
    point_t S;
    point_extproj_t A, R, base[W_FIXEDBASE]; 
    point_extproj_precomp_t baseb[W_FIXEDBASE], RR, T[NPOINTS_FIXEDBASE];
    unsigned int i, j, k, index, w = W_FIXEDBASE, v = V_FIXEDBASE, d = D_FIXEDBASE, e = E_FIXEDBASE;;
    unsigned long index_group;
    
    point_setup(P, A);                                         // Clear most significant bit of input coordinates and convert to representation (X,Y,1,Ta,Tb)

    if (ecc_point_validate(A, curve) == false) {               // Check if point lies on the curve
        return false;
    }

    if (clear_cofactor == true) {
        cofactor_clearing(A, curve);
        eccnorm(A, S);
        point_setup(S, A);
    }  
    ecccopy(A, base[0]);                                      // base[0] = A = (X:Y:1:Ta:Tb) 

    // Compute base point for each w (or row)
    for (i = 0; i < (w-1); i++) {
        ecccopy(base[i], base[i+1]);
        R1_to_R2(base[i], baseb[i], curve);                   // baseb in representation (X+Y,Y-X,2Z,2dT)
        for (j = 0; j < d; j++) eccdouble_ni(base[i+1]);      // base[i+1] = 2^d*base[i+1] using representations (X,Y,Z,Ta,Tb) <- 2*(X,Y,Z)
    }

    R1_to_R2(base[w-1], baseb[w-1], curve);                   // baseb in representation (X+Y,Y-X,2Z,2dT)        
    fp2copy1271(A->x, T[0]->xy);                              // T[0] = A in (x,y)
    fp2copy1271(A->y, T[0]->yx); 
    
    // Compute precomputed points for the first table
    index = 0;
    index_group = 1;
    for (i = 0; i < (w-1); i++)                               // T[index] = (1 + u_0.2^d + ... + u_{w-2}.2^((w-1)d)) A
    {
        for (j = 0; j < index_group; j++)
        {
            fp2add1271(T[j]->xy, T[j]->yx, RR->xy); 
            fp2sub1271(T[j]->yx, T[j]->xy, RR->yx); 
            fp2zero1271(RR->z2); RR->z2[0][0] = 1;                           
            fp2mul1271(T[j]->xy, T[j]->yx, RR->t2);           // RR in representation (X+Y,Y-X,1,T)
            eccadd_core(baseb[i+1], RR, R);                   // R in (X,Y,Z,Ta,Tb)
            index++; 
            eccnorm(R, S);                                    // R in (x,y,1,ta,tb)
            point_setup(S, R);
            fp2copy1271(R->x, T[index]->xy);                             
            fp2copy1271(R->y, T[index]->yx);                  // Precomputed points T[] in (x,y)
        }
        index_group = 2*index_group;
    }
                
    // Compute precomputed points for the remaining tables
    index++;
    for (i = 0; i < (v-1); i++)                               // T[index] = 2^(ev) (1 + u_0.2^d + ... + u_{w-2}.2^((w-1)d)) A
    {
        for (j = 0; j < index; j++)
        {
            fp2copy1271(T[i*index + j]->xy, R->x);                             
            fp2copy1271(T[i*index + j]->yx, R->y); 
            fp2zero1271(R->z); R->z[0][0] = 1; 
            for (k = 0; k < e; k++) eccdouble_ni(R);          // 2^(ev) * x * A using representations (X,Y,Z,Ta,Tb) <- 2*(X,Y,Z)   
            eccnorm(R, S);                                    // R in (x,y,1,ta,tb)
            point_setup(S, R);
            fp2copy1271(R->x, T[(i+1)*index + j]->xy);                             
            fp2copy1271(R->y, T[(i+1)*index + j]->yx);        // Precomputed points T[] in (x,y)
        }
    }

    for (i = 0; i < NPOINTS_FIXEDBASE; i++)
    {
        fp2mul1271(T[i]->xy, T[i]->yx, Table[i]->xy);         // Precomputed points T[] in coordinates (x+y,y-x,2dt)
        fp2mul1271((felm_t*)&curve->d, Table[i]->xy, Table[i]->t2);
        fp2add1271(Table[i]->t2, Table[i]->t2, Table[i]->t2);
        fp2add1271(T[i]->xy, T[i]->yx, Table[i]->xy);
        fp2sub1271(T[i]->yx, T[i]->xy, Table[i]->yx); 
    }

    return true;
}

#endif
