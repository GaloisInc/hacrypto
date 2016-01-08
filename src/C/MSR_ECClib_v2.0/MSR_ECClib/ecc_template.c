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
* Abstract: template for elliptic curve and scalar arithmetic functions
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
******************************************************************************/  

#include <malloc.h>
#include "msr_ecclib.h"


/*******************************************************************************************/
/***************** POINT/SCALAR FUNCTIONS FOR TWISTED EDWARDS a=1 CURVES *******************/

void ECCSET_TE(POINT_TE P, PCurveStruct TedCurve)
{ // Set generator (x,y) on twisted Edwards a=1 curve
    dig i, num_words = NBITS_TO_NWORDS(TedCurve->pbits);

    for (i = 0; i < num_words; i++) 
    {
        P->x[i] = TedCurve->generator_x[i]; 
        P->y[i] = TedCurve->generator_y[i]; 
    }
    return;
}


BOOL ECC_IS_NEUTRAL_AFF_TE(POINT_TE P, PCurveStruct TedCurve)
{ // Check if affine point P is the neutral point (0,1) 
    dig i, c, num_words = NBITS_TO_NWORDS(TedCurve->pbits);

    c = P->x[0] | (P->y[0] ^ 1);
    for (i = 1; i < num_words; i++)
    {
        c = c | P->x[i] | P->y[i]; 
    }

    return (BOOL)is_digit_zero_ct(c);
}


BOOL ECC_IS_NEUTRAL_EXT_TE(POINT_EXT_TE P, PCurveStruct TedCurve)
{ // Check if projective point P is the neutral point (0:1:1) 
    dig i, c, num_words = NBITS_TO_NWORDS(TedCurve->pbits);
    
    c = P->X[0] | (P->Y[0] ^ 1) | (P->Z[0] ^ 1);
    for (i = 1; i < num_words; i++)
    {
        c = c | P->X[i] | P->Y[i] | P->Z[i];
    }

    return (BOOL)is_digit_zero_ct(c);
}


void ECCNORM_TE(POINT_EXT_TE Q, POINT_TE P, PCurveStruct TedCurve)
{ // Normalize a projective twisted Edwards point Q = (X:Y:Z) -> P = (x,y)
    BASE_ELM t1, t2; 
    UNREFERENCED_PARAMETER(TedCurve);
    
    FP_COPY(Q->Z, t1);  
    FP_INV(t1);                      // t1 = Z^-1
    FP_MUL(Q->X, t1, t2);            // t2 = X/Z
    FP_COPY(t2, P->x);               // x = X/Z
    FP_MUL(Q->Y, t1, t2);            // t2 = Y/Z
    FP_COPY(t2, P->y);               // y = Y/Z
    
// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1);
    FP_ZERO(t2);
#endif
    return;
}


STATIC_INLINE void ECCCONVERT_R1_TO_R2(POINT_EXT_TE P, POINT_PRECOMP_EXT_TE Q, PCurveStruct TedCurve) 
{ // Conversion from representation (X,Y,Z,Ta,Tb) to (X,Y,Z,dT), where T = Ta*Tb
  // Input:  P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  // Output: Q = (X1,Y1,Z1,dT1) corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates 
    BASE_ELM t1;

    FP_MUL(P->Ta, P->Tb, t1);
    FP_COPY(P->X, Q->X);
    FP_COPY(P->Y, Q->Y);
    FP_COPY(P->Z, Q->Z);
    FP_MUL(t1, TedCurve->parameter2, Q->Td); 

// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1);
#endif

    return;
}


STATIC_INLINE void ECCDOUBLE_EXT_INTERNAL_TE(POINT_EXT_TE P, PCurveStruct TedCurve)
{ // Point doubling 2P
  // Twisted Edwards a=1 curve
  // Input: P = (X1,Y1,Z1) in twisted Edwards coordinates
  // Output: 2P = (X2,Y2,Z2,Ta,Tb), where T2 = Ta*Tb, corresponding to extended twisted Edwards coordinates (X2:Y2:Z2:T2)
    BASE_ELM t1[2]; 
    UNREFERENCED_PARAMETER(TedCurve); 
          
    // SECURITY NOTE: this function does not produce exceptions. 
        
    FP_SQR(P->X, t1[0]);               // t0 = X1^2
    FP_SQR(P->Y, t1[1]);               // t1 = Y1^2
    FP_SQR(P->Z, P->Ta);               // Ta = Z1^2 
    FP_SUB(t1[1], t1[0], P->Tb);       // Tbfinal = Y1^2-X1^2
    FP_ADD(t1[0], t1[1], t1[0]);       // t0 = X1^2+Y1^2    
    FP_ADD(P->Ta, P->Ta, P->Ta);       // Ta = 2*Z1^2         
    FP_ADD(P->Y, P->Y, P->Y);          // Y = 2*Y1
    FP_SUB(P->Ta, t1[0], t1[1]);       // t1 = 2*Z1^2-(X1^2+Y1^2)
    FP_MUL(P->X, P->Y, P->Ta);         // Tafinal = 2*X1*Y1
    FP_MUL(t1[0], P->Tb, P->Y);        // Yfinal = (X1^2+Y1^2)(Y1^2-X1^2)   
    FP_MUL(t1[1], P->Ta, P->X);        // Xfinal = 2*X1*Y1*[2*Z1^2-(X1^2+Y1^2)]
    FP_MUL(t1[0], t1[1], P->Z);        // Zfinal = (X1^2+Y1^2)[2*Z1^2-(X1^2+Y1^2)] 
    
// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1[0]);
    FP_ZERO(t1[1]);
#endif
    return;
}


void ECCDOUBLE_EXT_TE(POINT_EXT_TE P, PCurveStruct TedCurve)
{
    ECCDOUBLE_EXT_INTERNAL_TE(P, TedCurve);
}


STATIC_INLINE void ECCUADD_EXT_INTERNAL_TE(POINT_PRECOMP_EXT_TE Q, POINT_EXT_TE P, PCurveStruct TedCurve)      
{ // Complete point addition P = P+Q, including the cases P!=Q, P=Q, P=-Q, P=neutral and Q=neutral
  // Twisted Edwards a=1 curve
  // Inputs: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to extended twisted Edwards coordinates (X1:Y1:Z1:T1)
  //         Q = (X2,Y2,Z2,dT2), corresponding to extended twisted Edwards coordinates (X2:Y2:Z2:T2)
  // Output: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to extended twisted Edwards coordinates (X1:Y1:Z1:T1)
    BASE_ELM t1, t2, t3;
    UNREFERENCED_PARAMETER(TedCurve); 
        
    FP_MUL(P->Z, Q->Z, t3);             // t3 = Z1*Z2 
    FP_MUL(P->Ta, P->Tb, t1);           // t1 = T1  
    FP_ADD(P->X, P->Y, P->Ta);          // Ta = (X1+Y1)     
    FP_MUL(t1, Q->Td, t2);              // t2 = dT1*T2   
    FP_ADD(Q->X, Q->Y, P->Tb);          // Tb = (X2+Y2)  
    FP_SUB(t3, t2, t1);                 // t1 = theta
    FP_ADD(t3, t2, t3);                 // t3 = alpha
    FP_MUL(P->Ta, P->Tb, t2);           // t2 = (X1+Y1)(X2+Y2)
    FP_MUL(P->X, Q->X, P->Z);           // Z = X1*X2
    FP_MUL(P->Y, Q->Y, P->X);           // X = Y1*Y2
    FP_SUB(t2, P->Z, t2);              
    FP_SUB(P->X, P->Z, P->Ta);          // Tafinal = omega = Y1*Y2-X1*X2              
    FP_SUB(t2, P->X, P->Tb);            // Tbfinal = beta = (X1+Y1)(X2+Y2)-X1*X2-Y1*Y2
    FP_MUL(P->Ta, t3, P->Y);            // Yfinal = alpha*omega
    FP_MUL(P->Tb, t1, P->X);            // Xfinal = beta*theta
    FP_MUL(t3, t1, P->Z);               // Zfinal = theta*alpha
    
// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1);
    FP_ZERO(t2);
    FP_ZERO(t3);
#endif
    return;
}


void ECCUADD_EXT_TE(POINT_EXT_TE Q, POINT_EXT_TE P, PCurveStruct TedCurve)      
{ // Complete point addition P = P+Q, including the cases P!=Q, P=Q, P=-Q, P=neutral and Q=neutral
  // Twisted Edwards a=1 curve
  // Inputs: P = (X1,Y1,Z1,T1a,T1b), where T1 = T1a*T1b, corresponding to extended twisted Edwards coordinates (X1:Y1:Z1:T1)
  //         Q = (X2,Y2,Z2,T2a,T2b), where T2 = T2a*T2b, corresponding to extended twisted Edwards coordinates (X2:Y2:Z2:T2)    
  // Output: P = (X1,Y1,Z1,T1a,T1b), where T1 = T1a*T1b, corresponding to extended twisted Edwards coordinates (X1:Y1:Z1:T1)
    POINT_PRECOMP_EXT_TE QQ;
            
    ECCCONVERT_R1_TO_R2(Q, QQ, TedCurve);
    ECCUADD_EXT_INTERNAL_TE(QQ, P, TedCurve);
    
// cleanup
#ifdef TEMP_ZEROING
    ECCZERO_PRECOMP_EXT_TE(QQ);
#endif
    return;
}


void ECC_PRECOMP_EXT_TE(POINT_EXT_TE P, POINT_PRECOMP_EXT_TE *T, unsigned int npoints, PCurveStruct TedCurve)
{ // Precomputation function, points are stored using representation (X,Y,Z,dT)
  // Twisted Edwards a=1 curve
    POINT_PRECOMP_EXT_TE P2;
    POINT_EXT_TE Q;
    unsigned int i;  

    // Generating P2 = 2(X1,Y1,Z1,T1a,T1b) -> (XP2,YP2,ZP2,d*TP2) and T[0] = P = (X1,Y1,Z1,T1a,T1b) 
    ECCCOPY_EXT_TE(P, Q);
    ECCCONVERT_R1_TO_R2(P, T[0], TedCurve);
    ECCDOUBLE_EXT_INTERNAL_TE(Q, TedCurve);
    ECCCONVERT_R1_TO_R2(Q, P2, TedCurve);
    ECCCOPY_EXT_TE(P, Q);
    
    for (i = 1; i < npoints; i++) {
        // T[i] = 2P+T[i-1] = (2*i+1)P = (XP2,Y2P,ZP2,d*TP2) + (X_(2*i-1), Y_(2*i-1), Z_(2*i-1), Ta_(2*i-1), Tb_(2*i-1)) = (X_(2*i+1), Y_(2*i+1), Z_(2*i+1), d*T_(2*i+1))
        ECCUADD_EXT_INTERNAL_TE(P2, Q, TedCurve);
        ECCCONVERT_R1_TO_R2(Q, T[i], TedCurve);
    }
    
// cleanup
#ifdef TEMP_ZEROING
    ECCZERO_PRECOMP_EXT_TE(P2);
    ECCZERO_EXT_TE(Q);
#endif
    return;
}


STATIC_INLINE ECCRYPTO_STATUS ECC_VALIDATION_TE(POINT_TE P, PCurveStruct TedCurve)
{ // Point validation
  // Check if point P=(x,y) lies on the curve and if x,y are in [0, p-1]
    BASE_ELM t1, t2, t3, t4;  

    if (ECC_IS_NEUTRAL_AFF_TE(P, TedCurve) == TRUE) {    // Check if P is the neutral point (0,1)                                       
        return ECCRYPTO_ERROR_INVALID_PARAMETER;   
    } 
    // Are (x,y) in [0,p-1]?
    if (MOD_EVAL(P->x, TedCurve->prime) == FALSE || MOD_EVAL(P->y, TedCurve->prime) == FALSE) {  
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    // Does P lie on the curve?
    FP_SQR(P->y, t3);           
    FP_SQR(P->x, t2);
    FP_ADD(t2, t3, t1);             // x^2 + y^2 
    FP_MUL(t2, t3, t4);
    FP_MUL(TedCurve->parameter2, t4, t3);
    FP_ZERO(t4);  t4[0] = 1;        // t4 = 1
    FP_ADD(t3, t4, t2);             // 1 + dx^2y^2
    FP_SUB(t1, t2, t1); 
    if (FP_ISZERO(t1) == FALSE) {   
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    return ECCRYPTO_SUCCESS;
}


STATIC_INLINE ECCRYPTO_STATUS ECC_CLEARING_TE(POINT_TE P, POINT_EXT_TE Q, PCurveStruct TedCurve)
{ // Co-factor clearing
  // Outputs Q = 4*P = (X,Y,Z,Ta,Tb), assuming co-factor 4

    ECCCONVERT_AFF_TO_EXTPROJ_TE(P, Q);
    ECCDOUBLE_EXT_INTERNAL_TE(Q, TedCurve);
    ECCDOUBLE_EXT_INTERNAL_TE(Q, TedCurve);              // Q = 4*P = (X_Q:Y_Q:Z_Q:Ta_Q:Tb_Q)
    // Is the new point the neutral point (0:1:1)?
    if (ECC_IS_NEUTRAL_EXT_TE(Q, TedCurve) == TRUE) {    // Assuming that input point is public so this does not leak info  
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    return ECCRYPTO_SUCCESS;
}


STATIC_INLINE void CONVERSION_TO_ODD(dig *k, BASE_ELM k_odd, dig* oddity, PCurveStruct Curve)
{ // Convert scalar to odd if even using the prime subgroup order r
    unsigned int num_words = NBITS_TO_NWORDS(Curve->nbits);     // Number of words to represent field elements or elements in Z_r
    dig i;

    *oddity = 0 - (k[0] & 1);     
    FP_SUB(Curve->order, k, k_odd);                             // Converting scalar to odd (r-k if even)
    for (i = 0; i < num_words; i++)                             // If (odd) then k = k_odd else k = k 
    {
        k_odd[i] = (*oddity & (k[i] ^ k_odd[i])) ^ k_odd[i];
    }

    return;
}


STATIC_INLINE void OUTPUT_CORRECTION(BASE_ELM coordinate, dig oddity, PCurveStruct Curve)
{ // Output correction: if original scalar was even then negate point (negate "coordinate")
    unsigned int num_words = NBITS_TO_NWORDS(Curve->nbits);  // Number of words to represent field elements or elements in Z_r
    BASE_ELM t1;
    dig i;

    FP_COPY(coordinate, t1);
    FP_NEG(Curve->prime, t1);                                // t1 = -coordinate
    for (i = 0; i < num_words; i++)                          // If (even) then coordinate = -coordinate 
    {
        coordinate[i] = (oddity & (coordinate[i] ^ t1[i])) ^ t1[i];
    }

// cleanup
    FP_ZERO(t1);
    return;
}


ECCRYPTO_STATUS ECC_MUL_TE(POINT_TE P, dig *k, POINT_TE Q, PCurveStruct TedCurve)
{ // Variable-base scalar multiplication Q = k.P using fixed-window method 
  // Twisted Edwards a=1 curve
    unsigned int t = (TedCurve->rbits+(W_VARBASE-2))/(W_VARBASE-1);     // Fixed length of the fixed window representation 
    unsigned int npoints = 1 << (W_VARBASE-2);
    int digits[((BASE_ELM_NBYTES*8)+W_VARBASE-2)/(W_VARBASE-1) + 1] = {0};
    sdig i;
    dig j, oddity;
    BASE_ELM k_odd;
    POINT_EXT_TE T; 
    POINT_PRECOMP_EXT_TE table[1 << (W_VARBASE-2)], R;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
        
    // SECURITY NOTE: the crypto sensitive part of this function is protected against timing attacks and runs in constant-time. 
    //                Conditional if-statements evaluate public data only and the number of iterations for all loops is public. 
    // DISCLAIMER:    the protocol designer is responsible for guaranteeing that early termination produced after detecting errors during input validation
    //                (of scalar k or base point P) does not leak any secret information. 

    if (P == NULL || k == NULL || Q == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    // Is scalar k in [1,r-1]?                
    if ((FP_ISZERO(k) == TRUE) || (MOD_EVAL(k, TedCurve->order) == FALSE)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    // Point validation and co-factor clearing
    if (ECC_VALIDATION_TE(P, TedCurve) != ECCRYPTO_SUCCESS || ECC_CLEARING_TE(P, T, TedCurve) != ECCRYPTO_SUCCESS) {
        Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
        goto cleanup; 
    }

    ECC_PRECOMP_EXT_TE(T, table, npoints, TedCurve);            // Precomputation of points T[0],...,T[npoints-1]
    CONVERSION_TO_ODD(k, k_odd, &oddity, TedCurve);             // Converting scalar to odd using the prime subgroup order 
    fixed_window_recode(k_odd, TedCurve->rbits, W_VARBASE, digits); 

    LUT_EXT_TE(table, R, digits[t], npoints, TedCurve); 
    FP_COPY(R->X, T->X);                                        // Initialize T = (X_T:Y_T:Z_T:Ta_T:Tb_T) with a point from the precomputed table
    FP_COPY(R->Y, T->Y); 
    FP_COPY(R->Z, T->Z); 

    for (i = (t-1); i >= 0; i--)
    {
        for (j = 0; j < (W_VARBASE-1); j++)
        {
            ECCDOUBLE_EXT_INTERNAL_TE(T, TedCurve);             // Double (X_T:Y_T:Z_T:Ta_T:Tb_T) = 2(X_T:Y_T:Z_T:Ta_T:Tb_T)
        }
        LUT_EXT_TE(table, R, digits[i], npoints, TedCurve);     // Load R = (X_R:Y_R:Z_R:Td_R) with a point from the precomputed table
        ECCUADD_EXT_INTERNAL_TE(R, T, TedCurve);                // Complete addition (X_T:Y_T:Z_T:Ta_T:Tb_T) = (X_T:Y_T:Z_T:Ta_T:Tb_T) + (X_R:Y_R:Z_R:Td_R)   
    }

    OUTPUT_CORRECTION(T->X, oddity, TedCurve);                  // Correct output (-X_T if original scalar is even)
    ECCNORM_TE(T, Q, TedCurve);                                 // Output Q = (x,y)
    Status = ECCRYPTO_SUCCESS;
       
cleanup:
    for (j = 0; j < ((BASE_ELM_NBYTES*8)+W_VARBASE-2)/(W_VARBASE-1) + 1; j++) {
        ((int volatile*)digits)[j] = 0;
    }
    ECCZERO_EXT_TE(T);
    ECCZERO_PRECOMP_EXT_TE(R);
    for (j = 0; j < (1 << (W_VARBASE-2)); j++) {
        ECCZERO_PRECOMP_EXT_TE(table[j]);
    }
    FP_ZERO(k_odd);
    oddity = 0;

    return Status;
}


STATIC_INLINE void ECCUMADD_EXT_INTERNAL_TE(POINT_PRECOMP_EXTAFF_TE Q, POINT_EXT_TE P, PCurveStruct TedCurve)      
{ // Unified mixed point addition P = P+Q or P = P+P
  // Twisted Edwards a=1 curve
  // Inputs: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to extended twisted Edwards coordinates (X1:Y1:Z1:T1)
  //         Q = (X2,Y2,Z2,dT2), where Z2 = 1, corresponding to extended twisted Edwards coordinates (X2:Y2:Z2:T2)
  // Output: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to extended twisted Edwards coordinates (X1:Y1:Z1:T1)
    BASE_ELM t1, t2, t3; 
    UNREFERENCED_PARAMETER(TedCurve); 
        
    FP_MUL(P->Ta, P->Tb, t1);           // t1 = T1  
    FP_ADD(P->X, P->Y, P->Ta);          // Ta = (X1+Y1)     
    FP_MUL(t1, Q->td, t2);              // t2 = dT1.T2   
    FP_ADD(Q->x, Q->y, P->Tb);          // Tb = (X2+Y2)  
    FP_SUB(P->Z, t2, t1);               // t1 = theta
    FP_ADD(P->Z, t2, t3);               // t3 = alpha
    FP_MUL(P->Ta, P->Tb, t2);           // t2 = (X1+Y1)(X2+Y2)
    FP_MUL(P->X, Q->x, P->Z);           // Z = X1.X2
    FP_MUL(P->Y, Q->y, P->X);           // X = Y1.Y2
    FP_SUB(t2, P->Z, t2);              
    FP_SUB(P->X, P->Z, P->Ta);          // Tafinal = omega = Y1.Y2-X1.X2              
    FP_SUB(t2, P->X, P->Tb);            // Tbfinal = beta = (X1+Y1)(X2+Y2)-X1.X2-Y1.Y2
    FP_MUL(P->Ta, t3, P->Y);            // Yfinal = alpha.omega
    FP_MUL(P->Tb, t1, P->X);            // Xfinal = beta.theta
    FP_MUL(t3, t1, P->Z);               // Zfinal = theta. alpha
    
// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1);
    FP_ZERO(t2);
    FP_ZERO(t3);
#endif
    return;
}


void ECCUMADD_EXT_TE(POINT_PRECOMP_EXTAFF_TE Q, POINT_EXT_TE P, PCurveStruct TedCurve)
{
    ECCUMADD_EXT_INTERNAL_TE(Q, P, TedCurve);
}


ECCRYPTO_STATUS ECC_MUL_FIXED_TE(POINT_PRECOMP_EXTAFF_TE *P_table, dig *k, POINT_TE Q, PCurveStruct TedCurve)
{ // Wrapper for fixed-base scalar multiplication Q = k.P, where P = P_table 
  // Twisted Edwards a=1 curve
    unsigned int w, v;

    if (P_table == NULL || k == NULL || Q == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }    
    w = TedCurve->w_fixedbase;
    v = TedCurve->v_fixedbase;

    return ECC_MUL_FIXED_INTERNAL_TE(P_table, k, Q, w, v, TedCurve);
}



ECCRYPTO_STATUS ECC_MUL_FIXED_INTERNAL_TE(POINT_PRECOMP_EXTAFF_TE *P_table, dig *k, POINT_TE Q, unsigned int w, unsigned int v, PCurveStruct TedCurve)
{ // Fixed-base scalar multiplication Q = k.P, where P = P_table, using the Modified LSB-set Comb method 
  // Twisted Edwards a=1 curve
    unsigned int j, npoints, d, e, l;
    int i, ii, digits[BASE_ELM_NBYTES*8 + 48] = {0};   // max(e*w*v) is obtained using WMAX and VMAX (to determine the max number of digits required by the recoding) 
    BASE_ELM k_odd;
    POINT_EXT_TE T; 
    POINT_PRECOMP_EXTAFF_TE R;
    dig oddity;
    signed long digit = 0;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
        
    // SECURITY NOTE: the crypto sensitive part of this function is protected against timing attacks and runs in constant-time. 
    //                Conditional if-statements evaluate public data only and the number of iterations for all loops is public. 
    // DISCLAIMER:    the protocol designer is responsible for guaranteeing that early termination produced after detecting errors during input validation
    //                (of scalar k) does not leak any secret information. 
                      
    // Is scalar k in [1,r-1]?                
    if ((FP_ISZERO(k) == TRUE) || (MOD_EVAL(k, TedCurve->order) == FALSE)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    if (P_table == NULL) {    // Full point validation is done during offline precomputation
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    e = (TedCurve->rbits+w*v-1)/(w*v);  
    if (TedCurve->rbits-e*w*v == 0) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;          // This parameter selection is not allowed   
    }
    d = e*v;     
    l = d*w;                                              // Fixed length of the mLSB-set representation
    npoints = v*(1 << (w-1));

    CONVERSION_TO_ODD(k, k_odd, &oddity, TedCurve);       // Converting scalar to odd using the prime subgroup order 
    mLSB_set_recode(k_odd, TedCurve->rbits, l, d, digits); 

    // Extracting initial digit 
    digit = digits[w*d-1];
    for (i = (int)((w-1)*d-1); i >= (int)(2*d-1); i = i-d) { digit = 2*digit + digits[i]; }
    
    // Initialize T = (x,y,dt) with a point from the table
    LUT_EXTAFF_TE(P_table+(v-1)*(1 << (w-1)), R, digit, digits[d-1], 1 << (w-1), TedCurve);

    FP_COPY(R->x, T->X);                     
    FP_COPY(R->y, T->Y); 
    FP_ZERO(T->Z); T->Z[0] = 1; 
    FP_COPY(T->X, T->Ta); 
    FP_COPY(T->Y, T->Tb);                            // Initial point T = (X:Y:1:Ta:Tb)

    for (j = 0; j < (v-1); j++)
    {
        digit = digits[w*d-(j+1)*e-1];
        for (i = (int)((w-1)*d-(j+1)*e-1); i >= (int)(2*d-(j+1)*e-1); i = i-d) { digit = 2*digit + digits[i]; }
        LUT_EXTAFF_TE(P_table+(v-j-2)*(1 << (w-1)), R, digit, digits[d-(j+1)*e-1], 1 << (w-1), TedCurve);  // Load R = (xR:yR:tdR) with a point from the precomputed table
        ECCUMADD_EXT_INTERNAL_TE(R, T, TedCurve);    // Complete mixed addition (X_T:Y_T:Z_T:Ta_T:Tb_T) = (X_T:Y_T:Z_T:Ta_T:Tb_T) + (xR:yR:tdR)
    }

    for (ii = (e-2); ii >= 0; ii--)
    {
        ECCDOUBLE_EXT_INTERNAL_TE(T, TedCurve); 
        for (j = 0; j <= (v-1); j++)
        {
            digit = digits[w*d-j*e+ii-e];
            for (i = (int)((w-1)*d-j*e+ii-e); i >= (int)(2*d-j*e+ii-e); i = i-d) { digit = 2*digit + digits[i]; }
            LUT_EXTAFF_TE(P_table+(v-j-1)*(1 << (w-1)), R, digit, digits[d-j*e+ii-e], 1 << (w-1), TedCurve);  // Load R = (xy_R:yx_R:t2_R) with a point from the precomputed table
            ECCUMADD_EXT_INTERNAL_TE(R, T, TedCurve);            // Complete mixed addition (X_T:Y_T:Z_T:Ta_T:Tb_T) = (X_T:Y_T:Z_T:Ta_T:Tb_T) + (xy_R:yx_R:t2_R)                            
        }        
    } 
    
    OUTPUT_CORRECTION(T->X, oddity, TedCurve);                   // Correct output (-X_T if original scalar is even)
    ECCNORM_TE(T, Q, TedCurve);                                  // Output Q = (x,y)
    Status = ECCRYPTO_SUCCESS;
    
// cleanup
    for (j = 0; j < (BASE_ELM_NBYTES*8 + 48); j++) {
        ((int volatile*)digits)[j] = 0;
    }
    ECCZERO_EXT_TE(T);
    ECCZERO_PRECOMP_EXTAFF_TE(R);  
    FP_ZERO(k_odd);
    oddity = 0;
    
    return Status;
}


ECCRYPTO_STATUS ECC_PRECOMP_FIXED_TE(POINT_TE P, POINT_PRECOMP_EXTAFF_TE* T, PCurveStruct TedCurve)
{ // Wrapper for precomputation scheme using extended affine coordinates (x+y,y-x,2dt) for fixed-base scalar multiplication
  // Twisted Edwards a=1 curve
    unsigned int w, v, d, e; 

    if (P == NULL || T == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    w = TedCurve->w_fixedbase;
    v = TedCurve->v_fixedbase;

    e = (TedCurve->rbits+w*v-1)/(w*v);    
    if (TedCurve->rbits-e*w*v == 0)     // This parameter selection is not allowed
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    d = e*v;                             

    return ECC_PRECOMP_FIXED_INTERNAL_TE(P, T, w, v, d, e, TedCurve);
}


ECCRYPTO_STATUS ECC_PRECOMP_FIXED_INTERNAL_TE(POINT_TE P, POINT_PRECOMP_EXTAFF_TE* T, unsigned int w, unsigned int v, unsigned int d, unsigned int e, PCurveStruct TedCurve)
{ // Precomputation scheme using affine coordinates (x,y,dt) for fixed-base scalar multiplication
  // Twisted Edwards a=1 curve
    POINT_TE A;       
    POINT_EXT_TE R, B, base[WMAX]; 
    POINT_PRECOMP_EXT_TE baseb[WMAX];
    unsigned int i, j, k, npoints, index;
    unsigned long index_group;
    BASE_ELM t1, t2;
                
    // SECURITY NOTE: precomputation for fixed-base scalar multiplication uses public inputs. 
    
    // Input validation and co-factor clearing
    if (ECC_VALIDATION_TE(P, TedCurve) != ECCRYPTO_SUCCESS || ECC_CLEARING_TE(P, B, TedCurve) != ECCRYPTO_SUCCESS) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
        
    if (TedCurve->rbits-e*w*v == 0) {                        // This parameter selection is not allowed
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    npoints = v*(1 << (w-1));
    
    ECCNORM_TE(B, A, TedCurve);
    ECCCONVERT_AFF_TO_EXTPROJ_TE(A, base[0]);                // base[0] = A = (X:Y:1:Ta:Tb)
    
    FP_COPY(TedCurve->parameter2, t1); 

    // Compute base point for each w (or row)
    for (i = 0; i < (w-1); i++) {
        ECCCOPY_EXT_TE(base[i], base[i+1]);
        ECCCONVERT_R1_TO_R2(base[i], baseb[i], TedCurve);                  // baseb in coordinates (x,y,z,dt)
        for (j = 0; j < d; j++) ECCDOUBLE_EXT_TE(base[i+1], TedCurve);     // base[i+1] = 2^d base[i]
    }
 
    ECCCONVERT_R1_TO_R2(base[w-1], baseb[w-1], TedCurve);    // baseb in (x,y,z,dt)        
    FP_COPY(A->x, T[0]->x);                                  // T[0] = A in (x,y)
    FP_COPY(A->y, T[0]->y); 
    
    // Compute precomputed points for the first table
    index = 0;
    index_group = 1;
    for (i = 0; i < (w-1); i++)                              // T[index] = (1 + u_0.2^d + ... + u_{w-2}.2^((w-1)d)) B
    {
        for (j = 0; j < index_group; j++)
        {
            FP_COPY(T[j]->x, R->X); 
            FP_COPY(T[j]->y, R->Y); 
            FP_ZERO(R->Z); R->Z[0] = 1; 
            FP_COPY(R->X, R->Ta); 
            FP_COPY(R->Y, R->Tb);               
            ECCUADD_EXT_INTERNAL_TE(baseb[i+1], R, TedCurve);
            index++;                                         // R in (x,y,z)  
            ECCNORM_TE(R, A, TedCurve);   
            ECCCONVERT_AFF_TO_EXTPROJ_TE(A, R);             
            FP_COPY(R->X, T[index]->x);                             
            FP_COPY(R->Y, T[index]->y);                      // T[] in (x,y)
        }
        index_group = 2*index_group;
    }
                
    // Compute precomputed points for the remaining tables
    index++;
    for (i = 0; i < (v-1); i++)                              // T[index] = 2^(ev) (1 + u_0.2^d + ... + u_{w-2}.2^((w-1)d)) B
    {
        for (j = 0; j < index; j++)
        {
            FP_COPY(T[i*index + j]->x, R->X);                             
            FP_COPY(T[i*index + j]->y, R->Y); 
            FP_ZERO(R->Z); R->Z[0] = 1; 
            for (k = 0; k < e; k++) ECCDOUBLE_EXT_TE(R, TedCurve);     // 2^(ev) * X * B
            ECCNORM_TE(R, A, TedCurve);   
            ECCCONVERT_AFF_TO_EXTPROJ_TE(A, R);          
            FP_COPY(R->X, T[(i+1)*index + j]->x);                             
            FP_COPY(R->Y, T[(i+1)*index + j]->y);                      // Precomputed points T[] in (x,y)
        }
    }

    for (i = 0; i < npoints; i++)
    {
        FP_MUL(T[i]->x, T[i]->y, t2);
        FP_MUL(t2, t1, T[i]->td);                            // Precomputed points T[] in coordinates (x,y,dt)
    }

    return ECCRYPTO_SUCCESS;
}


ECCRYPTO_STATUS ECC_DBLMUL_TE(POINT_PRECOMP_EXTAFF_TE *P_table, dig *k, POINT_TE Q, dig *l, POINT_TE R, PCurveStruct TedCurve)
{ // Wrapper for double-base scalar multiplication R = k.P + l.Q, where P = P_table
  // P is a fixed-base and Q is a variable-base
  // Twisted Edwards a=1 curve
    unsigned int w_P;

    if (P_table == NULL || k == NULL || Q == NULL || l == NULL || R == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    w_P = TedCurve->w_doublescalar;

    return ECC_DBLMUL_INTERNAL_TE(P_table, k, Q, l, R, w_P, TedCurve);
}


ECCRYPTO_STATUS ECC_DBLMUL_INTERNAL_TE(POINT_PRECOMP_EXTAFF_TE *P_table, dig *k, POINT_TE Q, dig *l, POINT_TE R, unsigned int w_P, PCurveStruct TedCurve)
{ // Double-base scalar multiplication R = k.P + l.Q using wNAF with Interleaving
  // P is a fixed-base and Q is a variable-base
  // Twisted Edwards a=1 curve
    unsigned int npoints, position;
    int i, digits_P[BASE_ELM_NBYTES*8 + 1]={0}, digits_Q[BASE_ELM_NBYTES*8 + 1]={0};
    POINT_EXT_TE T; 
    POINT_PRECOMP_EXT_TE table[1 << (W_VARBASE-2)], S;
    POINT_PRECOMP_EXTAFF_TE SS;
            
    // SECURITY NOTE: this function is intended for a non-constant-time operation such as signature verification. 
    
    // Are scalars k, l in [1,r-1]?                
    if ((FP_ISZERO(k) == TRUE) || (MOD_EVAL(k, TedCurve->order) == FALSE) || (FP_ISZERO(l) == TRUE) || (MOD_EVAL(l, TedCurve->order) == FALSE)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    if (P_table == NULL) {                                     // Full point validation for P is done during offline precomputation
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    } 
    if (ECC_VALIDATION_TE(Q, TedCurve) != ECCRYPTO_SUCCESS) {  // Point validation of Q
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    ECCCONVERT_AFF_TO_EXTPROJ_TE(Q, T);                        // T = (X_T,Y_T,Z_T,Ta_T,Tb_T) <- Q

    npoints = 1 << (W_VARBASE-2); 

    ECC_PRECOMP_EXT_TE(T, table, npoints, TedCurve);    // Precomputation of points table[0],...,table[npoints-1]
    wNAF_recode(k, TedCurve->rbits, w_P, digits_P);     // Recode k and l to the wNAF representation
    wNAF_recode(l, TedCurve->rbits, W_VARBASE, digits_Q);
    FP_ZERO(T->X); FP_ZERO(T->Y); T->Y[0] = 1; FP_ZERO(T->Z); T->Z[0] = 1;  // Initialize T as the neutral point (0:1:1)   

    for (i = TedCurve->rbits; i >= 0; i--)
    {   
        ECCDOUBLE_EXT_INTERNAL_TE(T, TedCurve);        // Double (X_T,Y_T,Z_T,Ta_T,Tb_T) = 2(X_T,Y_T,Z_T,Ta_T,Tb_T)
        if (digits_Q[i] < 0) {
            position = (-digits_Q[i])/2;               // Load S = (X_S,Y_S,Z_S,T_S) = (X,Y,Z,dT) from a point in the precomputed table
            ECCCOPY_EXT2_TE(table[position], S);
            FP_NEG(TedCurve->prime, S->X);             
            FP_NEG(TedCurve->prime, S->Td);            // Negate S 
            ECCUADD_EXT_INTERNAL_TE(S, T, TedCurve);   // Complete addition (X_T,Y_T,Z_T,Ta_T,Tb_T) = (X_T,Y_T,Z_T,Ta_T,Tb_T) + (X_S,Y_S,Z_S,Td_S) 
        } else if (digits_Q[i] > 0) {            
            position = (digits_Q[i])/2;                // Load S = (X_S,Y_S,Z_S,Td_S) = (X,Y,2,d*T) from a point in the precomputed table
            ECCCOPY_EXT2_TE(table[position], S);
            ECCUADD_EXT_INTERNAL_TE(S, T, TedCurve);   // Complete addition (X_T,Y_T,Z_T,Ta_T,Tb_T) = (X_T,Y_T,Z_T,Ta_T,Tb_T) + (X_S,Y_S,Z_S,Td_S) 
        }
        if (digits_P[i] < 0) {                           
            position = (-digits_P[i])/2;               // Load SS = (x_SS,y_SS,td_SS) = (x,y,d*t) from a point in the precomputed table
            ECCCOPY_EXTAFF_TE(P_table[position], SS);
            FP_NEG(TedCurve->prime, SS->x);        
            FP_NEG(TedCurve->prime, SS->td);           // Negate SS
            ECCUMADD_EXT_INTERNAL_TE(SS, T, TedCurve); // Complete mixed addition (X_T,Y_T,Z_T,Ta_T,Tb_T) = (X_T,Y_T,Z_T,Ta_T,Tb_T) + (x_SS,y_SS,td_SS)
        } else if (digits_P[i] > 0) { 
            position = (digits_P[i])/2;                // Load SS = (x_SS,y_SS,td_SS) = (x,y,d*t) from a point in the precomputed table
            ECCCOPY_EXTAFF_TE(P_table[position], SS);
            ECCUMADD_EXT_INTERNAL_TE(SS, T, TedCurve); // Complete mixed addition (X_T,Y_T,Z_T,Ta_T,Tb_T) = (X_T,Y_T,Z_T,Ta_T,Tb_T) + (x_S,y_SS,td_SS)
        }
    }
    ECCNORM_TE(T, R, TedCurve);                        // Output R = (x,y)
    
    return ECCRYPTO_SUCCESS;
}


ECCRYPTO_STATUS ECC_PRECOMP_DBLMUL_TE(POINT_TE P, POINT_PRECOMP_EXTAFF_TE* T, PCurveStruct TedCurve)
{ // Wrapper for precomputation scheme using extended affine coordinates (x+y,y-x,2dt) for the fixed-base in double-scalar multiplication
  // Twisted Edwards a=1 curve
    unsigned int w_P;

    if (P == NULL || T == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    w_P = TedCurve->w_doublescalar;

    return ECC_PRECOMP_DBLMUL_INTERNAL_TE(P, T, w_P, TedCurve);
}



ECCRYPTO_STATUS ECC_PRECOMP_DBLMUL_INTERNAL_TE(POINT_TE P, POINT_PRECOMP_EXTAFF_TE* T, unsigned int w_P, PCurveStruct TedCurve)
{ // Precomputation scheme using affine coordinates (x,y,dt) for the fixed base in double-scalar multiplication
  // Twisted Edwards a=1 curve
    POINT_PRECOMP_EXT_TE T_EXT[1 << (WMAX - 2)] = {0};
    POINT_EXT_TE B;
    unsigned int i, npoints; 
    BASE_ELM t1; 
                
    // SECURITY NOTE: precomputation for double-scalar multiplication uses public inputs. 

    // Point validation
    if (ECC_VALIDATION_TE(P, TedCurve) != ECCRYPTO_SUCCESS) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    ECCCONVERT_AFF_TO_EXTPROJ_TE(P, B);                 // B = (X:Y:Z:Ta:Tb) <- P

    npoints = (1 << (w_P-2));

    ECC_PRECOMP_EXT_TE(B, T_EXT, npoints, TedCurve);         
    for (i = 0; i < npoints; i++)
    {
        FP_COPY(T_EXT[i]->Z, t1);
        FP_INV(t1);
        FP_MUL(T_EXT[i]->X, t1, T[i]->x);
        FP_MUL(T_EXT[i]->Y, t1, T[i]->y);
        FP_MUL(T_EXT[i]->Td, t1, T[i]->td);
    }

    return ECCRYPTO_SUCCESS;
}


POINT_PRECOMP_EXTAFF_TE* ECC_ALLOCATE_PRECOMP_TE(OpType scalarmultype, PCurveStruct TedCurve)
{ // Allocates memory dynamically for precomputation table "T_fixed" used during fixed-base or double-scalar multiplications.
  // This function must be called before using a table generated by ecc_precomp_fixed_Tedxxx or ecc_precomp_dblmul_Tedxxx. 
  // Twisted Edwards a=1 curve
    unsigned int npoints;

    if (is_ecc_curve_null(TedCurve) || scalarmultype < 0 || scalarmultype >= OpTypeSize) {
        return NULL;
    }

    if (scalarmultype == OP_FIXEDBASE) {
        npoints = (TedCurve->v_fixedbase)*(1 << (TedCurve->w_fixedbase - 1));
    } else if (scalarmultype == OP_DOUBLESCALAR) {
        npoints = 1 << (TedCurve->w_doublescalar - 2);
    } else {
        return NULL;
    }

    return (POINT_PRECOMP_EXTAFF_TE*)calloc(npoints, sizeof(POINT_PRECOMP_EXTAFF_TE));    // Allocating memory for table
}


#if (defined(AVX_SUPPORT) == FALSE) || (TARGET_GENERIC == TRUE) 

void LUT_EXT_TE(POINT_PRECOMP_EXT_TE* table, POINT_PRECOMP_EXT_TE P, int digit, unsigned int npoints, PCurveStruct TedCurve)
{ // Constant-time table lookup to extract a twisted Edwards point (X,Y,Z,dT) from the precomputed table
  // Twisted Edwards a=1 curve
  // Operation: P = sign * table[(|digit|-1)/2], where sign=1 if digit>0 and sign=-1 if digit<0
    unsigned int i, j, nwords = NBITS_TO_NWORDS(BASE_ELM_NBYTES*8);
    dig sign, mask, pos;
    POINT_PRECOMP_EXT_TE point, temp_point;

    sign = ((dig)digit >> (ML_WORD - 1)) - 1;                              // if digit<0 then sign = 0x00...0 else sign = 0xFF...F
    pos = ((sign & ((dig)digit ^ (dig)-digit)) ^ (dig)-digit) >> 1;        // position = (|digit|-1)/2  
    ECCCOPY_EXT2_TE(table[0], point);                                      // point = table[0] 

    for (i = 1; i < npoints; i++)
    {
        pos--;
        // If match then mask = 0xFF...F else sign = 0x00...0
        mask = (dig)is_digit_nonzero_ct(pos) - 1;
        ECCCOPY_EXT2_TE(table[i], temp_point);                             // temp_point = table[i+1] 
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        for (j = 0; j < nwords; j++) {
            point->X[j]  = (mask & (point->X[j]  ^ temp_point->X[j]))  ^ point->X[j];
            point->Y[j]  = (mask & (point->Y[j]  ^ temp_point->Y[j]))  ^ point->Y[j];
            point->Z[j]  = (mask & (point->Z[j]  ^ temp_point->Z[j]))  ^ point->Z[j];
            point->Td[j] = (mask & (point->Td[j] ^ temp_point->Td[j])) ^ point->Td[j];
        }
    }

    FP_COPY(point->X, temp_point->X);
    FP_COPY(point->Td, temp_point->Td);
    FP_NEG(TedCurve->prime, temp_point->X);                                // point: coordinates x,dt, temp_point: coordinates -x,-dt
    FP_NEG(TedCurve->prime, temp_point->Td);                            
    for (j = 0; j < nwords; j++) {                                         // if sign = 0x00...0 then choose negative of the point
        point->X[j]  = (sign & (point->X[j]  ^ temp_point->X[j]))  ^ temp_point->X[j];
        point->Td[j] = (sign & (point->Td[j] ^ temp_point->Td[j])) ^ temp_point->Td[j];
    }
    FP_COPY(point->X, P->X);
    FP_COPY(point->Y, P->Y);
    FP_COPY(point->Z, P->Z);
    FP_COPY(point->Td, P->Td);

// cleanup
#ifdef TEMP_ZEROING
    ECCZERO_PRECOMP_EXT_TE(point);
    ECCZERO_PRECOMP_EXT_TE(temp_point);
#endif
    return;
}


void LUT_EXTAFF_TE(POINT_PRECOMP_EXTAFF_TE * table, POINT_PRECOMP_EXTAFF_TE P, int digit, int sign, unsigned int npoints, PCurveStruct TedCurve)
{ // Constant-time table lookup to extract a affine point (x,y,dt) from the precomputed table
  // Twisted Edwards a=1 curve
  // Operation: if sign=0 then P = table[digit], else if (sign=-1) then P = -table[digit]
    unsigned int i, j, nwords = NBITS_TO_NWORDS(BASE_ELM_NBYTES*8);
    dig pos, mask;
    POINT_PRECOMP_EXTAFF_TE point, temp_point;

    pos = (dig)digit;                                                      // Load digit position 
    ECCCOPY_EXTAFF_TE(table[0], point);                                    // point = table[0] 

    for (i = 1; i < npoints; i++)
    {
        pos--;
        // If match then mask = 0xFF...F else sign = 0x00...0
        mask = (dig)is_digit_nonzero_ct(pos) - 1;
        ECCCOPY_EXTAFF_TE(table[i], temp_point);                           // temp_point = table[i+1] 
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        for (j = 0; j < nwords; j++) {
            point->x[j]  = (mask & (point->x[j]  ^ temp_point->x[j]))  ^ point->x[j];
            point->y[j]  = (mask & (point->y[j]  ^ temp_point->y[j]))  ^ point->y[j];
            point->td[j] = (mask & (point->td[j] ^ temp_point->td[j])) ^ point->td[j];
        }
    }

    FP_COPY(point->x, temp_point->x);
    FP_COPY(point->td, temp_point->td);
    FP_NEG(TedCurve->prime, temp_point->x);                                // point: coordinates x,dt, temp_point: coordinates -x,-dt
    FP_NEG(TedCurve->prime, temp_point->td);                               
    for (j = 0; j < nwords; j++) {                                         // if sign = 0xFF...F then choose negative of the point
        point->x[j]  = ((dig)sign & (point->x[j]  ^ temp_point->x[j]))  ^ point->x[j];
        point->td[j] = ((dig)sign & (point->td[j] ^ temp_point->td[j])) ^ point->td[j];
    }
    FP_COPY(point->x, P->x);
    FP_COPY(point->y, P->y);
    FP_COPY(point->td, P->td);

// cleanup
#ifdef TEMP_ZEROING
    ECCZERO_PRECOMP_EXTAFF_TE(point);
    ECCZERO_PRECOMP_EXTAFF_TE(temp_point);
#endif
    return;
}

#endif



/***************************************************************************************/
/****************** POINT/SCALAR FUNCTIONS FOR WEIERSTRASS a=-3 CURVES *****************/

void ECCSET_W(POINT_WAFF P, PCurveStruct JacCurve)
{ // Set generator P = (x,y) on Weierstrass a=-3 curve
    dig i, num_words = NBITS_TO_NWORDS(JacCurve->pbits); 

    for (i = 0; i < num_words; i++) 
    {
        P->x[i] = JacCurve->generator_x[i]; 
        P->y[i] = JacCurve->generator_y[i]; 
    }
    return;
}


BOOL ECC_IS_INFINITY_WAFF(POINT_WAFF P, PCurveStruct JacCurve)
{ // Check if point P is the point at infinity (0,0) 
    dig i, c, num_words = NBITS_TO_NWORDS(JacCurve->pbits);

    c = P->x[0] | P->y[0];
    for (i = 1; i < num_words; i++)
    {
        c = c | P->x[i] | P->y[i]; 
    }

    return (BOOL)is_digit_zero_ct(c);
}


BOOL ECC_IS_INFINITY_WJAC(POINT_WJAC P, PCurveStruct JacCurve)
{ // Check if Jacobian point P is the point at infinity (0:Y:0) 
    dig i, c, num_words = NBITS_TO_NWORDS(JacCurve->pbits);

    c = P->X[0] | P->Z[0];
    for (i = 1; i < num_words; i++)
    {
        c = c | P->X[i] | P->Z[i]; 
    }

    return (BOOL)is_digit_zero_ct(c);
}


void ECCNORM_W(POINT_WJAC Q, POINT_WAFF P, PCurveStruct JacCurve)
{ // Normalize a Jacobian point Q = (X:Y:Z) -> P = (x,y)
    BASE_ELM t1, t2, t3; 
    
    // Check if Q is the point at infinity (0:Y:0)
    // SECURITY NOTE: this if-statement evaluates over public information when the function is called from constant-time scalar multiplications, i.e.,
    //                Q is never the point at infinity when the call is from ecc_scalar_mul_<NUMS_Weierstrass_curve>() or ecc_scalar_mul_fixed_internal_<NUMS_Weierstrass_curve>(). 
    //                For more information, refer to "Selecting elliptic curves for cryptography: an efficiency and security analysis", http://eprint.iacr.org/2014/130
    if (ECC_IS_INFINITY_WJAC(Q, JacCurve) == TRUE) {
        FP_ZERO(P->x); FP_ZERO(P->y);    // Output the point at infinity P = (0,0)   
        return;
    }
    
    FP_COPY(Q->Z, t1);  
    FP_INV(t1);                      // t1 = Z^-1
    FP_SQR(t1, t2);                  // t2 = Z^-2
    FP_MUL(Q->X, t2, t3);            // t3 = X/Z^2
    FP_COPY(t3, P->x);               // x = X/Z^2
    FP_MUL(t1, t2, t3);              // t3 = Z^-3
    FP_MUL(Q->Y, t3, t1);            // t1 = Y/Z^3 
    FP_COPY(t1, P->y);               // y = Y/Z^3

// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1);
    FP_ZERO(t2);
    FP_ZERO(t3);
#endif
    return;
}


STATIC_INLINE void ECCDOUBLE_INTERNAL_WJAC(POINT_WJAC P, PCurveStruct JacCurve)      
{ // Point doubling P = 2P
  // Weierstrass a=-3 curve
  // Input:  P = (X,Y,Z) in Jacobian coordinates
  // Output: 2P = (X,Y,Z) in Jacobian coordinates
    BASE_ELM t1, t2, t3, t4;
    UNREFERENCED_PARAMETER(JacCurve);
     
    // SECURITY NOTE: this function does not produce exceptions on prime-order Weierstrass curves. For more information, refer to
    //                "Selecting elliptic curves for cryptography: an efficiency and security analysis", http://eprint.iacr.org/2014/130

    FP_SQR(P->Z, t1);           // t1 = z^2
    FP_MUL(P->Z, P->Y, t4);     // t4 = zy
    FP_ADD(P->X, t1, t2);       // t2 = x + z^2
    FP_SUB(P->X, t1, t1);       // t1 = x - z^2
    FP_COPY(t4, P->Z);          // Zfinal = zy
    FP_MUL(t1, t2, t3);         // t3 = (x + z^2)(x - z^2)
    FP_DIV2(t3, t2);            // t2 = (x + u.z^2)(x - u.z^2)/2
    FP_ADD(t3, t2, t1);         // t1 = alpha = 3(x + u.z^2)(x - u.z^2)/2               
    FP_SQR(P->Y, t2);           // t2 = y^2
    FP_SQR(t1, t4);             // t4 = alpha^2
    FP_MUL(P->X, t2, t3);       // t3 = beta = xy^2
    FP_SUB(t4, t3, t4);         // t4 = alpha^2-beta
    FP_SUB(t4, t3, P->X);       // Xfinal = alpha^2-2beta
    FP_SUB(t3, P->X, t4);       // t4 = beta-Xfinal
    FP_SQR(t2, t3);             // t3 = y^4
    FP_MUL(t1, t4, t2);         // t2 = alpha.(beta-Xfinal)
    FP_SUB(t2, t3, P->Y);       // Yfinal = alpha.(beta-Xfinal)-y^4
    
// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1);
    FP_ZERO(t2);
    FP_ZERO(t3);
    FP_ZERO(t4);
#endif
    return;
}


void ECCDOUBLE_WJAC(POINT_WJAC P, PCurveStruct JacCurve)
{
    ECCDOUBLE_INTERNAL_WJAC(P, JacCurve);
}


void ECCDOUBLEADD_WJAC(POINT_PRECOMP_WCHU Q, POINT_WJAC P, PCurveStruct JacCurve)      
{ // Point addition P = 2P+Q
  // Weierstrass a=-3 curve
  // Inputs: P = (X1,Y1,Z1) in Jacobian coordinates
  //         Q = (X2,Y2,Z2,Z2^2,Z2^3) in Chudnovsky coordinates 
  // Output: P = (X1,Y1,Z1) in Jacobian coordinates
    BASE_ELM t1, t2, t3, t4, t5, t6, t7; 
    UNREFERENCED_PARAMETER(JacCurve);
     
    // SECURITY NOTE: this function does not produce exceptions when P!=inf, Q!=inf, P!=Q, P!=-Q or Q!=-2P. In particular, it works when called from scalar multiplications 
    //                ecc_scalar_mul_<NUMS_Weierstrass_curve>() and ecc_scalar_mul_fixed_<NUMS_Weierstrass_curve>(). For more information, refer to "Selecting elliptic curves  
    //                for cryptography: an efficiency and security analysis", http://eprint.iacr.org/2014/130
    
    FP_SQR(P->Z, t2);               // t2 = z1^2
    FP_MUL(Q->Z3, P->Y, t3);        // t3 = z2^3*y1
    FP_MUL(P->Z, t2, t4);           // t4 = z1^3
    FP_MUL(t2, Q->X, t1);           // t1 = z1^2*x2                      
    FP_MUL(Q->Y, t4, t2);           // t2 = z1^3*y2
    FP_MUL(Q->Z2, P->X, t6);        // t6 = z2^2*x1
    FP_SUB(t2, t3, t2);             // t2 = alpha = z1^3*y2-z2^3*y1
    FP_SUB(t1, t6, t1);             // t1 = beta = z1^2*x2-z2^2*x1
    FP_SQR(t2, t4);                 // t4 = alpha^2
    FP_SQR(t1, t5);                 // t5 = beta^2
    FP_MUL(P->Z, Q->Z, t7);         // t5 = z1*z2
    FP_MUL(t6, t5, P->X);           // x1 = x1' = z2^2*x1*beta^2
    FP_MUL(t1, t5, t6);             // t6 = beta^3
    FP_SUB(t4, t6, t4);             // t4 = alpha^2 - beta^3
    FP_SUB(t4, P->X, t4);           // t4 = alpha^2 - beta^3 - x1'
    FP_SUB(t4, P->X, t4);           // t4 = alpha^2 - beta^3 - 2*x1'
    FP_SUB(t4, P->X, t4);           // t4 = omega = alpha^2 - beta^3 - 3*x1'
    FP_MUL(t6, t3, P->Y);           // y1 = y1' = z2^3*y1*beta^3 
    FP_MUL(t1, t7, t3);             // t3 = z1' = z1*z2*beta
    FP_MUL(t2, t4, t1);             // t1 = alpha.omega
    FP_SQR(t4, t2);                 // t2 = omega^2                      
    FP_ADD(t1, P->Y, t1);           // t1 = alpha.omega + y1'
    FP_ADD(t1, P->Y, t1);           // t1 = theta = alpha.omega + 2y1'    
    FP_MUL(t3, t4, P->Z);           // Zfinal = z1'*omega
    FP_MUL(t2, t4, t5);             // t5 = omega^3
    FP_MUL(t2, P->X, t4);           // t4 = x1'*omega^2
    FP_SQR(t1, t3);                 // t3 = theta^2
    FP_SUB(t3, t5, t3);             // t3 = theta^2 - omega^3
    FP_SUB(t3, t4, t3);             // t3 = theta^2 - omega^3 - x1'*omega^2
    FP_SUB(t3, t4, P->X);           // Xfinal = theta^2 - omega^3 - 2*x1'*omega^2
    FP_SUB(P->X, t4, t3);           // t3 = Xfinal-x1'*omega^2
    FP_MUL(P->Y, t5, t2);           // t2 = y1'*omega^3
    FP_MUL(t3, t1, t5);             // t5 = theta.(Xfinal-x1'*omega^2)
    FP_SUB(t5, t2, P->Y);           // Yfinal = theta.(Xfinal-x1'*omega^2) - y1'*omega^3
    
// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1);
    FP_ZERO(t2);
    FP_ZERO(t3);
    FP_ZERO(t4);
    FP_ZERO(t5);
    FP_ZERO(t6);
    FP_ZERO(t7);
#endif
    return;
}


// Functions for the precomputation (Weierstrass a=-3 curves)

static void ECCADD_PRECOMP_WJAC(POINT_WJAC P, POINT_PRECOMP_WCHU Q, POINT_PRECOMP_WCHU R)      
{ // Special point addition R = P+Q with identical Z-coordinate for the precomputation
  // Weierstrass a=-3 curve
  // Inputs:  P = (X1,Y1,Z) in Jacobian coordinates with the same Z-coordinate
  //          Q = (X2,Y2,Z,Z^2,Z^3) in Chudnovsky coordinates with the same Z-coordinate
  //          Values (X1',Y1')
  // Outputs: R = (X3,Y3,Z3,Z3^2,Z3^2) in Chudnovsky coordinates 
  //          new representation P  = (X1',Y1',Z1') = (X1.(X2-X1)^2, X1.(X2-X1)^3, Z.(X2-X1)) in Jacobian coordinates
    BASE_ELM t1, t2, t3, t4; 
     
    // SECURITY NOTE: this function does not produce exceptions in the context of variable-base precomputation. For more information,
    //                refer to "Selecting elliptic curves for cryptography: an efficiency and security analysis", http://eprint.iacr.org/2014/130
    
    FP_SUB(Q->X, P->X, t1);         // t1 = x2-x1
    FP_MUL(P->Z, t1, R->Z);         // Zfinal = z.(x2-x1)
    FP_COPY(R->Z, P->Z);            // Z1' = z.(x2-x1)
    FP_SQR(t1, t2);                 // t2 = (x2-x1)^2
    FP_SQR(R->Z, R->Z2);            // Z2final = Zfinal^2
    FP_MUL(t1, t2, t3);             // t3 = (x2-x1)^3
    FP_MUL(P->X, t2, t4);           // t4 = X1' = x1.(x2-x1)^2
    FP_COPY(t4, P->X);              // X1'
    FP_SUB(Q->Y, P->Y, t1);         // t1 = y2-y1
    FP_SQR(t1, R->X);               // X3 = (y2-y1)^2
    FP_MUL(R->Z, R->Z2, R->Z3);     // Z3final = Zfinal^3
    FP_SUB(R->X, t3, R->X);         // X3 = (y2-y1)^2 - (x2-x1)^3
    FP_SUB(R->X, t4, R->X);         // X3 = (y2-y1)^2 - (x2-x1)^3 - x1.(x2-x1)^2
    FP_SUB(R->X, t4, R->X);         // X3final = (y2-y1)^2 - (x2-x1)^3 - 2*x1.(x2-x1)^2
    FP_SUB(t4, R->X, t2);           // t2 = x1.(x2-x1)^2-X3
    FP_MUL(t1, t2, t4);             // t4 = (y2-y1)[x1.(x2-x1)^2-X3]
    FP_MUL(P->Y, t3, t2);           // t2 = Y1' = y1*(x2-x1)^3
    FP_COPY(t2, P->Y);              // Y1'
    FP_SUB(t4, t2, R->Y);           // Yfinal = (y2-y1)[x1.(x2-x1)^2-X3] - y1*(x2-x1)^3
    
// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1);
    FP_ZERO(t2);
    FP_ZERO(t3);
    FP_ZERO(t4);
#endif
    return;
}


void ECC_PRECOMP_WJAC(POINT_WAFF P, POINT_PRECOMP_WCHU *T, unsigned int npoints, PCurveStruct JacCurve)
{ // Precomputation scheme using Jacobian coordinates
  // Weierstrass a=-3 curve
  // Input:   P = (x,y)
  // Outputs: T[0] = P, T[1] = 3*P, ... , T[npoints-1] = (2*npoints-1)*P in coordinates (X:Y:Z:Z^2:Z^3)
    POINT_WJAC P2;
    BASE_ELM t1, t2, t3; 
    unsigned int i;
    UNREFERENCED_PARAMETER(JacCurve);
    
    // SECURITY NOTE: this function does not produce exceptions in the context of variable-base scalar multiplication and double-scalar multiplication.
    //                For more information, refer to "Selecting elliptic curves for cryptography: an efficiency and security analysis", http://eprint.iacr.org/2014/130

    // Generating 2P = 2(x,y) = (X2,Y2,Z2) and P = (x,y) = (X1',Y1',Z1',Z1^2',Z1^3') = (x*y^2, y*y^3, y, y^2, y^3)
    FP_ZERO(t2); t2[0] = 1;             // t2 = 1
    FP_SQR(P->x, t1);                   // t1 = x^2
    FP_SUB(t1, t2, t1);                 // t1 = x^2-1
    FP_DIV2(t1, t2);                    // t2 = (x^2-1)/2
    FP_ADD(t1, t2, t1);                 // t1 = alpha = 3(x^2-1)/2
    FP_SQR(P->y, T[0]->Z2);             // Z1^2' = y^2
    FP_MUL(T[0]->Z2, P->x, T[0]->X);    // X1' = beta = xy^2
    FP_MUL(T[0]->Z2, P->y, T[0]->Z3);   // Z1^3' = y^3
    FP_SQR(t1, t2);                     // t2 = alpha^2
    FP_SUB(t2, T[0]->X, t2);            // t2 = alpha^2-beta
    FP_SUB(t2, T[0]->X, P2->X);         // X2final = alpha^2-2beta
    FP_COPY(P->y, P2->Z);               // Z2final = y
    FP_COPY(P->y, T[0]->Z);             // Z1' = y
    FP_SQR(T[0]->Z2, T[0]->Y);          // Y1' = y^4
    FP_SUB(T[0]->X, P2->X, t2);         // t2 = beta-Xfinal
    FP_MUL(t1, t2, t3);                 // t3 = alpha.(beta-Xfinal)
    FP_SUB(t3, T[0]->Y, P2->Y);         // Y2final = alpha.(beta-Xfinal)-y^4
    
    for (i = 1; i < npoints; i++) {
        // T[i] = 2P'+T[i-1] = (2*i+1)P = (X_(2*i+1),Y_(2*i+1),Z_(2*i+1),Z_(2*i+1)^2,Z_(2*i+1)^3) and new 2P' s.t. Z(2P')=Z_(2*i+1)
        ECCADD_PRECOMP_WJAC(P2, T[i-1], T[i]);
    }
    
// cleanup
#ifdef TEMP_ZEROING
    ECCZERO_WJAC(P2);
    FP_ZERO(t1);
    FP_ZERO(t2);
    FP_ZERO(t3);
#endif
    return;
}


STATIC_INLINE void ECCUADD_NO_INIT_WJAC(POINT_WJAC Q, POINT_WJAC P, POINT_WJAC *table, PCurveStruct JacCurve)      
{ // Complete point addition: if P=-Q then P=0, else if P=0 then P=Q, else if P=Q then P=2P, else P=P+Q 
  // Constant-time extraction over 5-LUT: table[0] = inf, table[1] = Q, table[2] = 2P, table[3] = P+Q, table[4] = P. First two entries and last one are assumed to be pre-loaded. 
  // Weierstrass a=-3 curve
  // Inputs: P = (X1,Y1,Z1) in Jacobian coordinates
  //         Q = (X2,Y2,Z2) in Jacobian coordinates 
  // Output: P = P+Q = (X1,Y1,Z1) + (X2,Y2,Z2) in Jacobian coordinates
    BASE_ELM t1, t2, t3, t4, t5, t6, t7, t8; 
    unsigned int index = 0;
    dig mask = 0, mask1;
    UNREFERENCED_PARAMETER(JacCurve);
        
    // SECURITY NOTE: this constant-time addition function is complete (i.e., it works for any possible inputs, including the cases P!=Q, P=Q, P=-Q and P=inf) on prime-order Weierstrass curves.
    //                For more information, refer to "Selecting elliptic curves for cryptography: an efficiency and security analysis", http://eprint.iacr.org/2014/130
    
    FP_SQR(P->Z, t2);                         // t2 = z1^2
    FP_MUL(P->Z, t2, t3);                     // t3 = z1^3
    FP_MUL(t2, Q->X, t1);                     // t1 = z1^2*x2
    FP_MUL(t3, Q->Y, t4);                     // t4 = z1^3*y2
    FP_SQR(Q->Z, t3);                         // t3 = z2^2
    FP_MUL(Q->Z, t3, t5);                     // t5 = z2^3
    FP_MUL(t3, P->X, t7);                     // t7 = z2^2*x1
    FP_MUL(t5, P->Y, t8);                     // t8 = z2^3*y1
    FP_SUB(t1, t7, t1);                       // t1 = beta2 = z1^2*x2-z2^2*x1               
    FP_SUB(t4, t8, t4);                       // t4 = alpha2 = z1^3*y2-z2^3*y1
    index = COMPLETE_EVAL(t1, P->Z, t4, &mask);    // if t1=0 (P=-Q) then index=0, if Z1=0 (P inf) then index=1, if t4=0 (P=Q) then index=2, else index=3
                                                   // if index=3 then mask = 0xff...ff, else mask = 0
    mask1 = ~(-FP_ISZERO(Q->Z)) ;                  // if Z2=0 (Q inf) then mask1 = 0, else mask1 = 0xff...ff
    index = (mask1 & (index ^ 4)) ^ 4;        // if mask1 = 0 then index=4, else if mask1 = 0xff...ff then keep previous index  
    FP_ADD(P->X, t2, t3);                     // t3 = x1+z1^2
    FP_SUB(P->X, t2, t6);                     // t6 = x1-z1^2
    COMPLETE_SELECT(P->Y, t1, t2, mask);      // If mask=0 (DBL) then t2=y1, else if mask=-1 (ADD) then t2=beta2 
    FP_SQR(t2, t5);                           // t5 = y1^2 (DBL) or beta2^2 (ADD)
    COMPLETE_SELECT(P->X, t7, t7, mask);      // If mask=0 (DBL) then t7=x1, else if mask=-1 (ADD) then t7=z2^2*x1 
    FP_MUL(t5, t7, t1);                       // t1 = x1y1^2 = beta1 (DBL) or z2^2*x1*beta2^2 (ADD)
    FP_MUL(P->Z, t2, table[2]->Z);            // Z2Pfinal = z1y1
    FP_MUL(Q->Z, table[2]->Z, table[3]->Z);   // ZPQfinal = z1*z2*beta2
    COMPLETE_SELECT(t3, t2, t3, mask);        // If mask=0 (DBL) then t3=x1+z1^2, else if mask=-1 (ADD) then t3=beta2 
    COMPLETE_SELECT(t6, t5, t6, mask);        // If mask=0 (DBL) then t6=x1-z1^2, else if mask=-1 (ADD) then t6=beta2^2
    FP_MUL(t3, t6, t2);                       // t2 = (x1+z1^2)(x1-z1^2) (DBL) or beta2^3 (ADD)
    FP_DIV2(t2, t3);                          // t3 = (x1+z1^2)(x1-z1^2)/2
    FP_ADD(t2, t3, t3);                       // t3 = alpha1 = 3(x1+z1^2)(x1-z1^2)/2
    COMPLETE_SELECT(t3, t4, t3, mask);        // If mask=0 (DBL) then t3=alpha1, else if mask=-1 (ADD) then t3=alpha2
    FP_SQR(t3, t4);                           // t4 = alpha1^2 (DBL) or alpha2^2 (ADD)
    FP_SUB(t4, t1, t4);                       // t4 = alpha1^2-beta1 (DBL) or alpha2^2-z2^2*x1*beta2^2
    FP_SUB(t4, t1, table[2]->X);              // X2Pfinal = alpha1^2-2beta1 (DBL) or alpha2^2-2z2^2*x1*beta2^2 (ADD)
    FP_SUB(table[2]->X, t2, table[3]->X);     // XPQfinal = alpha^2-beta2^3-2z2^2*x1*beta2^2
    COMPLETE_SELECT(table[2]->X, table[3]->X, t4, mask);   // If mask=0 (DBL) then t4=X2Pfinal, else if mask=-1 (ADD) then t4=XPQfinal
    FP_SUB(t1, t4, t1);                       // t1 = beta1-X2Pfinal (DBL) or (ADD) z2^2*x1*beta2^2-XPQfinal
    FP_MUL(t3, t1, t4);                       // t4 = alpha1.(beta1-X2Pfinal) or alpha2.(z2^2*x1*beta2^2-XPQfinal)
    COMPLETE_SELECT(t5, t8, t1, mask);        // If mask=0 (DBL) then t1=y1^2, else if mask=-1 (ADD) then t1=z2^3*y1
    COMPLETE_SELECT(t5, t2, t2, mask);        // If mask=0 (DBL) then t2=y1^2, else if mask=-1 (ADD) then t2=beta2^3
    FP_MUL(t1, t2, t3);                       // t3 = y1^4 (DBL) or z2^3*y1*beta2^3 (ADD)
    FP_SUB(t4, t3, table[2]->Y);              // Y2Pfinal = alpha1.(beta1-X2Pfinal)-y1^4 (DBL) or alpha2.(z2^2*x1*beta2^2-XPQfinal)-z2^3*y1*beta2^3 (ADD)
    FP_COPY(table[2]->Y, table[3]->Y);        // YPQfinal = alpha2.(z2^2*x1*beta2^2-XPQfinal)-z2^3*y1*beta2^3
    COMPLETE_LUT5(table, index, P);           // P = table[index]
    
// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1);
    FP_ZERO(t2);
    FP_ZERO(t3);
    FP_ZERO(t4);
    FP_ZERO(t5);
    FP_ZERO(t6);
    FP_ZERO(t7);
    FP_ZERO(t8);
#endif        
    return;
}


void ECCUADD_WJAC(POINT_WJAC Q, POINT_WJAC P, PCurveStruct JacCurve)      
{ // Complete point addition: if P=-Q then P=0, else if P=0 then P=Q, else if P=Q then P=2P, else P=P+Q 
  // Constant-time extraction over 5-LUT: table[0] = inf, table[1] = Q, table[2] = 2P, table[3] = P+Q, table[4] = P. 
  // Weierstrass a=-3 curve
  // Inputs: P = (X1,Y1,Z1) in Jacobian coordinates
  //         Q = (X2,Y2,Z2) in Jacobian coordinates 
  // Output: P = P+Q = (X1,Y1,Z1) + (X2,Y2,Z2) in Jacobian coordinates
    POINT_WJAC table[5] = {0};
         
    table[0]->Y[0] = 1;                       // Initialize table[0] with the point at infinity (0:1:0)
    ECCCOPY_WJAC(Q, table[1]);                // Initialize table[1] with Q
    ECCCOPY_WJAC(P, table[4]);                // Initialize table[4] with P
    ECCUADD_NO_INIT_WJAC(Q, P, table, JacCurve);
    
// cleanup
#ifdef TEMP_ZEROING
    ECCZERO_WJAC(table[0]);
    ECCZERO_WJAC(table[1]);
    ECCZERO_WJAC(table[2]);
    ECCZERO_WJAC(table[3]);
    ECCZERO_WJAC(table[4]);
#endif    
    return;
}


STATIC_INLINE ECCRYPTO_STATUS ECC_VALIDATION_W(POINT_WAFF P, PCurveStruct JacCurve)
{ // Point validation
  // Check if point P=(x,y) lies on the curve and if x,y are in [0, p-1]
    BASE_ELM t1, t2, t3;  
            
    if (ECC_IS_INFINITY_WAFF(P, JacCurve) == TRUE) {     
        return ECCRYPTO_ERROR_INVALID_PARAMETER;   
    } 
    // Are (x,y) in [0,p-1]?
    if (MOD_EVAL(P->x, JacCurve->prime) == FALSE || MOD_EVAL(P->y, JacCurve->prime) == FALSE) {  
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    // Does P lie on the curve?
    FP_SQR(P->y, t1);           // y^2
    FP_SQR(P->x, t2);
    FP_MUL(P->x, t2, t3); 
    FP_ADD(t3, JacCurve->parameter2, t2);
    FP_ADD(P->x, P->x, t3); 
    FP_ADD(P->x, t3, t3); 
    FP_SUB(t2, t3, t2);         // x^3 - 3x + b
    FP_SUB(t1, t2, t1); 
    if (FP_ISZERO(t1) == FALSE) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    return ECCRYPTO_SUCCESS;
}


ECCRYPTO_STATUS ECC_MUL_W(POINT_WAFF P, dig *k, POINT_WAFF Q, PCurveStruct JacCurve)
{ // Variable-base scalar multiplication Q = k.P using fixed-window method 
  // Weierstrass a=-3 curve
    unsigned int t = (JacCurve->rbits+(W_VARBASE-2))/(W_VARBASE-1);           // Fixed length of the fixed window representation  
    unsigned int npoints = 1 << (W_VARBASE-2);
    int digits[((BASE_ELM_NBYTES*8)+W_VARBASE-2)/(W_VARBASE-1) + 1] = {0};
    sdig i;
    dig j, oddity;
    BASE_ELM k_odd;
    POINT_WJAC T, TT;
    POINT_PRECOMP_WCHU table[1 << (W_VARBASE-2)], R;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
        
    // SECURITY NOTE: the crypto sensitive part of this function is protected against timing attacks and runs in constant-time on prime-order Weierstrass curves. 
    //                Conditional if-statements evaluate public data only and the number of iterations for all loops is public. Refer to "Selecting elliptic curves 
    //                for cryptography: an efficiency and security analysis", http://eprint.iacr.org/2014/130, for the full proof demonstrating exception-less, 
    //                constant-time execution of scalar multiplication.
    // DISCLAIMER:    the protocol designer is responsible for guaranteeing that early termination produced after detecting errors during input validation
    //                (of scalar k or base point P) does not leak any secret information. 


    if (P == NULL || k == NULL || Q == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    // Is scalar k in [1,r-1]?               
    if ((FP_ISZERO(k) == TRUE) || (MOD_EVAL(k, JacCurve->order) == FALSE)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    // Point validation
    if (ECC_VALIDATION_W(P, JacCurve) != ECCRYPTO_SUCCESS) {
        Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
        goto cleanup; 
    }

    ECC_PRECOMP_WJAC(P, table, npoints, JacCurve);                // Precomputation of points T[0],...,T[npoints-1]
    CONVERSION_TO_ODD(k, k_odd, &oddity, JacCurve);               // Converting scalar to odd using the prime subgroup order    
    fixed_window_recode(k_odd, JacCurve->rbits, W_VARBASE, digits); 
    
    LUT_WCHU(table, R, digits[t], npoints, JacCurve); 
    FP_COPY(R->X, T->X);                                          // Initialize T = (X_T:Y_T:Z_T) with a point from the precomputed table
    FP_COPY(R->Y, T->Y); 
    FP_COPY(R->Z, T->Z); 
    
    for (i = (t-1); i >= 1; i--)
    {
        for (j = 0; j < (W_VARBASE-2); j++)
        {
            ECCDOUBLE_INTERNAL_WJAC(T, JacCurve);                // Double (X_T:Y_T:Z_T) = 2(X_T:Y_T:Z_T) 
        }
        LUT_WCHU(table, R, digits[i], npoints, JacCurve);        // Load R = (X_R:Y_R:Z_R:Z_R^2:Z_R^3) with a point from the precomputed table
        ECCDOUBLEADD_WJAC(R, T, JacCurve);                       // Double-add (X_T:Y_T:Z_T) = 2(X_T:Y_T:Z_T) + (X_R:Y_R:Z_R:Z_R^2:Z_R^3) 
    }
    
    // Perform last iteration
    for (j = 0; j < (W_VARBASE-1); j++)
    {
        ECCDOUBLE_INTERNAL_WJAC(T, JacCurve);                    // Double (X_T:Y_T:Z_T) = 2(X_T:Y_T:Z_T)
    }
    LUT_WCHU(table, R, digits[0], npoints, JacCurve);            // Load R = (X_R:Y_R:Z_R:Z_R^2:Z_R^3) with a point from the precomputed table
    FP_COPY(R->X, TT->X);                                        // TT = R = (X_R:Y_R:Z_R)
    FP_COPY(R->Y, TT->Y);
    FP_COPY(R->Z, TT->Z);
    ECCUADD_WJAC(TT, T, JacCurve);                               // Complete addition (X_T:Y_T:Z_T) = (X_T:Y_T:Z_T) + (X_R:Y_R:Z_R)
    
    OUTPUT_CORRECTION(T->Y, oddity, JacCurve);                   // Correct output (-Y_T if original scalar is even)
    ECCNORM_W(T, Q, JacCurve);                                   // Output Q = (x,y)
    Status = ECCRYPTO_SUCCESS;
    
cleanup:
    for (j = 0; j < ((BASE_ELM_NBYTES*8)+W_VARBASE-2)/(W_VARBASE-1) + 1; j++) {
        ((int volatile*)digits)[j] = 0;
    }
    ECCZERO_WJAC(T);
    ECCZERO_WJAC(TT);
    ECCZERO_WCHU(R);
    for (j = 0; j < (1 << (W_VARBASE-2)); j++) {
        ECCZERO_WCHU(table[j]);
    }
    FP_ZERO(k_odd);
    oddity = 0;

    return Status;
}


void ECCUMADD_WJAC(POINT_WAFF Q, POINT_WJAC P, POINT_WJAC *table, PCurveStruct JacCurve)      
{ // Complete mixed point addition: if P=-Q then P=0, else if P=0 then P=Q, else if P=Q then P=2P, else P=P+Q 
  // Constant-time extraction over 4-LUT: table[0] = inf, table[1] = Q, table[2] = 2P, table[3] = P+Q. First two entries are pre-loaded. 
  // Weierstrass a=-3 curve
  // Inputs: P = (X1,Y1,Z1) in Jacobian coordinates
  //         Q = (x,y) in affine coordinates 
  // Output: P = P+Q = (X1,Y1,Z1) + (x,y) in Jacobian coordinates
    BASE_ELM t1, t2, t3, t4, t5, t6; 
    unsigned int index = 0;
    dig mask = 0;
    UNREFERENCED_PARAMETER(JacCurve);
        
    // SECURITY NOTE: this constant-time addition function is complete (i.e., it works for any possible inputs, including the cases P!=Q, P=Q, P=-Q and P=inf) on prime-order Weierstrass curves.
    //                For more information, refer to "Selecting elliptic curves for cryptography: an efficiency and security analysis", http://eprint.iacr.org/2014/130
    
    FP_SQR(P->Z, t2);                         // t2 = z1^2
    FP_MUL(P->Z, t2, t3);                     // t3 = z1^3
    FP_MUL(t2, Q->x, t1);                     // t1 = z1^2*x2
    FP_MUL(t3, Q->y, t4);                     // t4 = z1^3*y2
    FP_SUB(t1, P->X, t1);                     // t1 = beta2 = z1^2*x2-x1                
    FP_SUB(t4, P->Y, t4);                     // t4 = alpha2 = z1^3*y2-y1
    index = COMPLETE_EVAL(t1, P->Z, t4, &mask);
    FP_ADD(P->X, t2, t3);                     // t3 = x1+z1^2
    FP_SUB(P->X, t2, t6);                     // t6 = x1-z1^2
    COMPLETE_SELECT(P->Y, t1, t2, mask);      // If mask=0 (DBL) then t2=y1, else if mask=-1 (ADD) then t2=beta2 
    FP_SQR(t2, t5);                           // t5 = y1^2 (DBL) or beta2^2 (ADD)
    FP_MUL(P->X, t5, t1);                     // t1 = x1y1^2 = beta1 (DBL) or x1*beta2^2 (ADD)
    FP_MUL(P->Z, t2, table[2]->Z);            // Z2Pfinal = z1y1
    FP_COPY(table[2]->Z, table[3]->Z);        // ZPQfinal = z1*beta2
    COMPLETE_SELECT(t3, t2, t3, mask);        // If mask=0 (DBL) then t3=x1+z1^2, else if mask=-1 (ADD) then t3=beta2 
    COMPLETE_SELECT(t6, t5, t6, mask);        // If mask=0 (DBL) then t6=x1-z1^2, else if mask=-1 (ADD) then t6=beta2^2
    FP_MUL(t3, t6, t2);                       // t2 = (x1+z1^2)(x1-z1^2) (DBL) or beta2^3 (ADD)
    FP_DIV2(t2, t3);                          // t3 = (x1+z1^2)(x1-z1^2)/2
    FP_ADD(t2, t3, t3);                       // t3 = alpha1 = 3(x1+z1^2)(x1-z1^2)/2
    COMPLETE_SELECT(t3, t4, t3, mask);        // If mask=0 (DBL) then t3=alpha1, else if mask=-1 (ADD) then t3=alpha2
    FP_SQR(t3, t4);                           // t4 = alpha1^2 (DBL) or alpha2^2 (ADD)
    FP_SUB(t4, t1, t4);                       // t4 = alpha1^2-beta1 (DBL) or alpha2^2-x1*beta2^2
    FP_SUB(t4, t1, table[2]->X);              // X2Pfinal = alpha1^2-2beta1 (DBL) or alpha2^2-2x1*beta2^2 (ADD)
    FP_SUB(table[2]->X, t2, table[3]->X);     // XPQfinal = alpha^2-beta2^3-2x1*beta2^2
    COMPLETE_SELECT(table[2]->X, table[3]->X, t4, mask);   // If mask=0 (DBL) then t4=X2Pfinal, else if mask=-1 (ADD) then t4=XPQfinal
    FP_SUB(t1, t4, t1);                       // t1 = beta1-X2Pfinal (DBL) or (ADD) x1*beta2^2-XPQfinal
    FP_MUL(t3, t1, t4);                       // t4 = alpha1.(beta1-X2Pfinal) or alpha2.(x1*beta2^2-XPQfinal)
    COMPLETE_SELECT(t5, P->Y, t1, mask);      // If mask=0 (DBL) then t1=y1^2, else if mask=-1 (ADD) then t1=y1
    COMPLETE_SELECT(t5, t2, t2, mask);        // If mask=0 (DBL) then t2=y1^2, else if mask=-1 (ADD) then t2=beta2^3
    FP_MUL(t1, t2, t3);                       // t3 = y1^4 (DBL) or y1*beta2^3 (ADD)
    FP_SUB(t4, t3, table[2]->Y);              // Y2Pfinal = alpha1.(beta1-X2Pfinal)-y1^4 (DBL) or alpha2.(x1*beta2^2-XPQfinal)-y1*beta2^3 (ADD)
    FP_COPY(table[2]->Y, table[3]->Y);        // YPQfinal = alpha2.(x1*beta2^2-XPQfinal)-y1*beta2^3
    COMPLETE_LUT4(table, index, P);           // P = table[index]
    
// cleanup
#ifdef TEMP_ZEROING
    FP_ZERO(t1);
    FP_ZERO(t2);
    FP_ZERO(t3);
    FP_ZERO(t4);
    FP_ZERO(t5);
    FP_ZERO(t6);
#endif        
    return;
}


ECCRYPTO_STATUS ECC_MUL_FIXED_W(POINT_WAFF *P_table, dig *k, POINT_WAFF Q, PCurveStruct JacCurve)
{ // Wrapper for fixed-base scalar multiplication Q = k.P, where P = P_table 
  // Weierstrass a=-3 curve
    unsigned int w, v;

    if (P_table == NULL || k == NULL || Q == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    w = JacCurve->w_fixedbase;
    v = JacCurve->v_fixedbase;

    return ECC_MUL_FIXED_INTERNAL_W(P_table, k, Q, w, v, JacCurve);
}


ECCRYPTO_STATUS ECC_MUL_FIXED_INTERNAL_W(POINT_WAFF *P_table, dig *k, POINT_WAFF Q, unsigned int w, unsigned int v, PCurveStruct JacCurve)
{ // Fixed-base scalar multiplication Q = k.P, where P = P_table, using the Modified LSB-set Comb method 
  // Weierstrass a=-3 curve
    unsigned int j, npoints, d, e, l;
    int i, ii, digits[BASE_ELM_NBYTES*8 + 48] = {0};      // max(e*w*v) is obtained using WMAX and VMAX (to determine the max number of digits required by the recoding)                                      
    BASE_ELM k_odd;
    POINT_WJAC T, complete_table[4] = {0};                // Table to store {inf, Q, 2P, P+Q}. This is used in the "complete" addition.
    POINT_WAFF R;
    dig oddity;
    signed long digit = 0;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
        
    // SECURITY NOTE: the crypto sensitive part of this function is protected against timing attacks and runs in constant-time on prime-order Weierstrass curves. 
    //                Conditional if-statements evaluate public data only and the number of iterations for all loops is public. Refer to "Selecting elliptic curves 
    //                for cryptography: an efficiency and security analysis", http://eprint.iacr.org/2014/130, for the full proof demonstrating exception-less, 
    //                constant-time execution of scalar multiplication.
    // DISCLAIMER:    the protocol designer is responsible for guaranteeing that early termination produced after detecting errors during input validation
    //                (of scalar k) does not leak any secret information. 
    
    // Is scalar k in [1,r-1]?                
    if ((FP_ISZERO(k) == TRUE) || (MOD_EVAL(k, JacCurve->order) == FALSE)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    if (P_table == NULL) {    // Full point validation is done during offline precomputation
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    e = (JacCurve->rbits+w*v-1)/(w*v);     
    if (JacCurve->rbits-e*w*v == 0) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;       // This parameter selection is not allowed
    }
    d = e*v;     
    l = d*w;                                           // Fixed length of the mLSB-set representation
    npoints = v*(1 << (w-1));

    CONVERSION_TO_ODD(k, k_odd, &oddity, JacCurve);    // Converting scalar to odd using the prime subgroup order  
    mLSB_set_recode(k_odd, JacCurve->rbits, l, d, digits); 

    // Extracting initial digit 
    digit = digits[w*d-1];
    for (i = (int)((w-1)*d-1); i >= (int)(2*d-1); i = i-d) { digit = 2*digit + digits[i]; }

    // Initialize T = (X_T:Y_T:1) with a point from the precomputed table
    LUT_WAFF(P_table+(v-1)*(1 << (w-1)), R, digit, digits[d-1], 1 << (w-1), JacCurve);
    ECCCONVERT_AFF_TO_JAC_W(R, T);

    // Initialize complete_table[0] with the point at infinity (0:1:0)
    complete_table[0]->Y[0] = 1;     

    for (j = 0; j < (v-1); j++)
    {
        digit = digits[w*d-(j+1)*e-1];
        for (i = (int)((w-1)*d-(j+1)*e-1); i >= (int)(2*d-(j+1)*e-1); i = i-d) { digit = 2*digit + digits[i]; }
        LUT_WAFF(P_table+(v-j-2)*(1 << (w-1)), R, digit, digits[d-(j+1)*e-1], 1 << (w-1), JacCurve);  // Load R = (X_R:Y_R) with point from precomputed table
        ECCCONVERT_AFF_TO_JAC_W(R, complete_table[1]);                 // Load complete_table[1] with (X_R:Y_R:1)
        ECCUMADD_WJAC(R, T, complete_table, JacCurve);                 // "Complete" mixed addition (X_T:Y_T:Z_T) = (X_T:Y_T:Z_T) + (X_R:Y_R)
    }

    for (ii = (e-2); ii >= 0; ii--)
    {
        ECCDOUBLE_INTERNAL_WJAC(T, JacCurve);                          // Double (X_T:Y_T:Z_T) = 2(X_T:Y_T:Z_T)
        for (j = 0; j <= (v-1); j++)
        {
            digit = digits[w*d-j*e+ii-e];

            for (i = (int)((w-1)*d-j*e+ii-e); i >= (int)(2*d-j*e+ii-e); i = i-d) { digit = 2*digit + digits[i]; }
            LUT_WAFF(P_table+(v-j-1)*(1 << (w-1)), R, digit, digits[d-j*e+ii-e], 1 << (w-1), JacCurve);  // Load R = (X_R:Y_R) with point from precomputed table
            ECCCONVERT_AFF_TO_JAC_W(R, complete_table[1]);             // Load complete_table[1] with (X_R:Y_R:1)
            ECCUMADD_WJAC(R, T, complete_table, JacCurve);             // "Complete" mixed addition (X_T:Y_T:Z_T) = (X_T:Y_T:Z_T) + (X_R:Y_R)
        }        
    } 
    
    OUTPUT_CORRECTION(T->Y, oddity, JacCurve);                         // Correct output (-Y_T if original scalar is even)
    ECCNORM_W(T, Q, JacCurve);                                         // Output Q = (x,y)
    Status = ECCRYPTO_SUCCESS;
    
// cleanup
    for (j = 0; j < (BASE_ELM_NBYTES*8 + 48); j++) {
        ((int volatile*)digits)[j] = 0;
    }
    ECCZERO_WJAC(T);
    for (j = 0; j < 4; j++) {
        ECCZERO_WJAC(complete_table[j]);
    }
    ECCZERO_WAFF(R);
    FP_ZERO(k_odd);
    oddity = 0;
    
    return Status;
}


ECCRYPTO_STATUS ECC_PRECOMP_FIXED_W(POINT_WAFF P, POINT_WAFF* T, PCurveStruct JacCurve)
{ // Precomputation scheme using affine coordinates for fixed-base scalar multiplication
  // Weierstrass a=-3 curve
    unsigned int w, v, d, e;

    if (P == NULL || T == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    w = JacCurve->w_fixedbase;
    v = JacCurve->v_fixedbase;

    e = (JacCurve->rbits+w*v-1)/(w*v);    
    if (JacCurve->rbits-e*w*v == 0) {    // This parameter selection is not allowed
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    d = e*v;                             

    return ECC_PRECOMP_FIXED_INTERNAL_W(P, T, w, v, d, e, JacCurve);
}


ECCRYPTO_STATUS ECC_PRECOMP_FIXED_INTERNAL_W(POINT_WAFF P, POINT_WAFF* T, unsigned int w, unsigned int v, unsigned int d, unsigned int e, PCurveStruct JacCurve)
{ // Precomputation scheme using affine coordinates for fixed-base scalar multiplication
  // Weierstrass a=-3 curve
    POINT_WJAC R, base[WMAX], complete_table[5] = {0};                // Table to store {inf, Q, 2P, P+Q, P}. This is used in the "complete" addition.
    unsigned int i, j, k, index;
    unsigned long index_group; 
                
    // SECURITY NOTE: precomputation for fixed-base scalar multiplication uses public inputs. 

    // Point validation
    if (ECC_VALIDATION_W(P, JacCurve) != ECCRYPTO_SUCCESS) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
        
    if (JacCurve->rbits - e*w*v == 0) {    // This parameter selection is not allowed 
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    // Initialize complete_table[0] with the point at infinity (0:1:0) 
    complete_table[0]->Y[0] = 1;  
    
    ECCCONVERT_AFF_TO_JAC_W(P, base[0]);                             // base[0] = P in coordinates (X:Y:1)

    // Compute base point for each w (or row)
    for (i = 0; i < (w-1); i++) {
        ECCCOPY_WJAC(base[i], R);
        for (j = 0; j < d; j++) ECCDOUBLE_WJAC(R, JacCurve);         // base[i+1] = 2^d base[i] in coordinates (X:Y:Z)
        ECCCOPY_WJAC(R, base[i+1]);
    }
    ECCCOPY_W(P, T[0]);                                              // T[0] = P
    
    // Compute precomputed points for the first table
    index = 0;
    index_group = 1;
    for (i = 0; i < (w-1); i++)                                      // T[index] = (1 + u_0.2^d + ... + u_{w-2}.2^((w-1)d)) P
    {
        for (j = 0; j < index_group; j++)
        {
            ECCCONVERT_AFF_TO_JAC_W(T[j], R);
            ECCCOPY_WJAC(base[i+1], complete_table[1]);                      // Load complete_table[1] with base[i+1]
            ECCCOPY_WJAC(R, complete_table[4]);                              // Load complete_table[4] with (X_R:Y_R:Z_R)
            ECCUADD_NO_INIT_WJAC(base[i+1], R, complete_table, JacCurve);    // Complete addition R = R + base[i+1]  
            index++;
            ECCNORM_W(R, T[index], JacCurve);
        }
        index_group = 2*index_group;
    }
        
    // Compute precomputed points for the remaining tables
    index++;
    for (i = 0; i < (v-1); i++)                                      // T[index] = 2^(ev) (1 + u_0.2^d + ... + u_{w-2}.2^((w-1)d)) P
    {
        for (j = 0; j < index; j++)
        {
            ECCCONVERT_AFF_TO_JAC_W(T[i*index + j], R);
            for (k = 0; k < e; k++) ECCDOUBLE_WJAC(R, JacCurve);     // 2^(ev) * X * P
            ECCNORM_W(R, T[(i+1)*index + j], JacCurve);
        }
    } 

    return ECCRYPTO_SUCCESS;
}


static void ECCDOUBLEADD_CONDITIONALS_WJAC(POINT_PRECOMP_WCHU Q, POINT_WJAC P, PCurveStruct JacCurve)      
{ // Point addition P = 2P+Q containing conditionals (if-statements)
  // Weierstrass a=-3 curve
  // Inputs: P = (X1,Y1,Z1) in Jacobian coordinates
  //         Q = (X2,Y2,Z2,Z2^2,Z2^3) in Chudnovsky coordinates 
  // Output: P = (X1,Y1,Z1) in Jacobian coordinates
    BASE_ELM t1, t2, t3, t4, t5, t6, t7; 
    POINT_WJAC T;
    
    // SECURITY NOTE: this function should only be called from functions not requiring constant-time execution such as double-scalar multiplications 
    //                ecc_double_scalar_mul_internal_<NUMS_Weierstrass_curve>() used in signature verification.

    // Check if P is the point at infinity (0:Y:0)
    if (ECC_IS_INFINITY_WJAC(P, JacCurve) == TRUE) { 
        FP_COPY(Q->X, P->X); FP_COPY(Q->Y, P->Y); FP_COPY(Q->Z, P->Z);  // Output P = Q
        return;   
    }    
    // Check if Q is the point at infinity (0:Y:0)
    FP_COPY(Q->X, T->X); FP_COPY(Q->Y, T->Y); FP_COPY(Q->Z, T->Z);
    if (ECC_IS_INFINITY_WJAC(T, JacCurve) == TRUE) {        
        ECCDOUBLE_WJAC(P, JacCurve);                                    // Output P = 2*P
        return;
    }
    
    FP_SQR(P->Z, t2);               // t2 = z1^2
    FP_MUL(Q->Z3, P->Y, t3);        // t3 = z2^3*y1
    FP_MUL(P->Z, t2, t4);           // t4 = z1^3
    FP_MUL(t2, Q->X, t1);           // t1 = z1^2*x2                      
    FP_MUL(Q->Y, t4, t2);           // t2 = z1^3*y2
    FP_MUL(Q->Z2, P->X, t6);        // t6 = z2^2*x1
    FP_SUB(t2, t3, t2);             // t2 = alpha = z1^3*y2-z2^3*y1
    FP_SUB(t1, t6, t1);             // t1 = beta = z1^2*x2-z2^2*x1
    
    if ((FP_ISZERO(t1) & FP_ISZERO(t2)) == TRUE) {
        FP_COPY(P->X, T->X); FP_COPY(P->Y, T->Y); FP_COPY(P->Z, T->Z);
        FP_NEG(JacCurve->prime, T->Y);         // T = -P  
        ECCDOUBLE_WJAC(P, JacCurve);
        ECCDOUBLEADD_WJAC(Q, P, JacCurve);     // Output P = 2*(2P)-P = 3*P
        return;
    } 
    if (FP_ISZERO(t1) == TRUE) return;        // Output P

    FP_SQR(t2, t4);                 // t4 = alpha^2
    FP_SQR(t1, t5);                 // t5 = beta^2
    FP_MUL(P->Z, Q->Z, t7);         // t5 = z1*z2
    FP_MUL(t6, t5, P->X);           // x1 = x1' = z2^2*x1*beta^2
    FP_MUL(t1, t5, t6);             // t6 = beta^3
    FP_SUB(t4, t6, t4);             // t4 = alpha^2 - beta^3
    FP_SUB(t4, P->X, t4);           // t4 = alpha^2 - beta^3 - x1'
    FP_SUB(t4, P->X, t4);           // t4 = alpha^2 - beta^3 - 2*x1'
    FP_SUB(t4, P->X, t4);           // t4 = omega = alpha^2 - beta^3 - 3*x1'
    
    if (FP_ISZERO(t4) == TRUE) {
        FP_ZERO(P->X); FP_ZERO(P->Z);   // Output point at infinity (0:Y:0)  
        return;                                    
    }

    FP_MUL(t6, t3, P->Y);           // y1 = y1' = z2^3*y1*beta^3 
    FP_MUL(t1, t7, t3);             // t3 = z1' = z1*z2*beta
    FP_MUL(t2, t4, t1);             // t1 = alpha.omega
    FP_SQR(t4, t2);                 // t2 = omega^2                      
    FP_ADD(t1, P->Y, t1);           // t1 = alpha.omega + y1'
    FP_ADD(t1, P->Y, t1);           // t1 = theta = alpha.omega + 2y1'    
    FP_MUL(t3, t4, P->Z);           // Zfinal = z1'*omega
    FP_MUL(t2, t4, t5);             // t5 = omega^3
    FP_MUL(t2, P->X, t4);           // t4 = x1'*omega^2
    FP_SQR(t1, t3);                 // t3 = theta^2
    FP_SUB(t3, t5, t3);             // t3 = theta^2 - omega^3
    FP_SUB(t3, t4, t3);             // t3 = theta^2 - omega^3 - x1'*omega^2
    FP_SUB(t3, t4, P->X);           // Xfinal = theta^2 - omega^3 - 2*x1'*omega^2
    FP_SUB(P->X, t4, t3);           // t3 = Xfinal-x1'*omega^2
    FP_MUL(P->Y, t5, t2);           // t2 = y1'*omega^3
    FP_MUL(t3, t1, t5);             // t5 = theta.(Xfinal-x1'*omega^2)
    FP_SUB(t5, t2, P->Y);           // Yfinal = theta.(Xfinal-x1'*omega^2) - y1'*omega^3
    
    return;
}


static void ECCMADD_CONDITIONALS_WJAC(POINT_WAFF Q, POINT_WJAC P, PCurveStruct JacCurve)      
{ // Point addition P = P+Q
  // Weierstrass a=-3 curve
  // Inputs: P = (X1,Y1,Z1) in Jacobian coordinates
  //         Q = (x,y) in affine coordinates 
  // Output: P = (X1,Y1,Z1) in Jacobian coordinates
    BASE_ELM t1, t2, t3, t4; 
    
    // SECURITY NOTE: this function should only be called from functions not requiring constant-time execution such as double-scalar multiplications 
    //                ecc_double_scalar_mul_internal_<NUMS_Weierstrass_curve>() used in signature verification.

    // Check if P is the point at infinity (0:Y:0)
    if (ECC_IS_INFINITY_WJAC(P, JacCurve) == TRUE) {   
        ECCCONVERT_AFF_TO_JAC_W(Q, P);                       // Output P = Q = (X:Y:1)
        return;   
    }       
    // Check if Q is the point at infinity (0,0)
    if (ECC_IS_INFINITY_WAFF(Q, JacCurve) == TRUE) {
        return;                                             // Output P
    }

    FP_SQR(P->Z, t2);               // t2 = z1^2
    FP_MUL(P->Z, t2, t3);           // t3 = z1^3
    FP_MUL(t2, Q->x, t1);           // t1 = z1^2*x2
    FP_MUL(Q->y, t3, t2);           // t2 = z1^3*y2
    FP_SUB(t2, P->Y, t2);           // t2 = alpha = z1^3*y2-y1
    FP_SUB(t1, P->X, t1);           // t1 = beta = z1^2*x2-x1

    if ((FP_ISZERO(t1) & FP_ISZERO(t2)) == TRUE) {
        ECCDOUBLE_WJAC(P, JacCurve);     // Output P = 2*P since P=Q   
        return;
    } 
    if (FP_ISZERO(t1) == TRUE) {
        FP_ZERO(P->X); FP_ZERO(P->Z);    // Output the point at infinity P = (0:Y:0) since P=-Q  
        return;
    }

    FP_COPY(P->Z, t4);              // t4 = z1
    FP_MUL(t1, t4, P->Z);           // Zfinal = z1*beta
    FP_SQR(t1, t4);                 // t4 = beta^2
    FP_MUL(t1, t4, t3);             // t3 = beta^3
    FP_MUL(P->X, t4, t1);           // t1 = x1*beta^2
    FP_SQR(t2, t4);                 // t4 = alpha^2
    FP_SUB(t4, t3, t4);             // t4 = alpha^2 - beta^3
    FP_SUB(t4, t1, t4);             // t4 = alpha^2 - beta^3 - z2^2*x1*beta^2
    FP_SUB(t4, t1, P->X);           // Xfinal = alpha^2 - beta^3 - 2*z2^2*x1*beta^2
    FP_SUB(t1, P->X, t1);           // t1 = z2^2*x1*beta^2-Xfinal
    FP_MUL(t2, t1, t4);             // t4 = alpha.(z2^2*x1*beta^2-Xfinal)
    FP_MUL(P->Y, t3, t2);           // t2 = y1*beta^3
    FP_SUB(t4, t2, P->Y);           // Yfinal = alpha.(z2^2*x1*beta^2-Xfinal) - y1*beta^3
    
    return;
}


ECCRYPTO_STATUS ECC_DBLMUL_W(POINT_WAFF *P_table, dig *k, POINT_WAFF Q, dig *l, POINT_WAFF R, PCurveStruct JacCurve)
{ // Wrapper for double-base scalar multiplication R = k.P + l.Q, where P = P_table
  // P is a fixed-base and Q is a variable-base
  // Weierstrass a=-3 curve
    unsigned int w_P;

    if (P_table == NULL || k == NULL || Q == NULL || l == NULL || R == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }       
    w_P = JacCurve->w_doublescalar;

    return ECC_DBLMUL_INTERNAL_W(P_table, k, Q, l, R, w_P, JacCurve);
}


ECCRYPTO_STATUS ECC_DBLMUL_INTERNAL_W(POINT_WAFF *P_table, dig *k, POINT_WAFF Q, dig *l, POINT_WAFF R, unsigned int w_P, PCurveStruct JacCurve)
{ // Double-base scalar multiplication R = k.P + l.Q, where P = P_table[0], using wNAF with Interleaving
  // P is a fixed-base and Q is a variable-base
  // Weierstrass a=-3 curve
    unsigned int npoints, position;
    int i, digits_P[BASE_ELM_NBYTES*8 + 1]={0}, digits_Q[BASE_ELM_NBYTES*8 + 1]={0};         
    POINT_WJAC T; 
    POINT_PRECOMP_WCHU table[1 << (W_VARBASE-2)], S;
    POINT_WAFF SS;
            
    // SECURITY NOTE: this function is intended for an operation not requiring constant-time execution such as signature verification. 
     
    // Are scalars k, l in [1,r-1]?                
    if ((FP_ISZERO(k) == TRUE) || (MOD_EVAL(k, JacCurve->order) == FALSE) || (FP_ISZERO(l) == TRUE) || (MOD_EVAL(l, JacCurve->order) == FALSE)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    } 
    if (P_table == NULL) {                                    // Full point validation for P is done during offline precomputation
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }  
    if (ECC_VALIDATION_W(Q, JacCurve) != ECCRYPTO_SUCCESS) {  // Point validation of Q
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    npoints = 1 << (W_VARBASE-2); 

    ECC_PRECOMP_WJAC(Q, table, npoints, JacCurve);              // Precomputation of points table[0],...,table[npoints-1]
    wNAF_recode(k, JacCurve->rbits, w_P, digits_P);             // Recode k and l to the wNAF representation
    wNAF_recode(l, JacCurve->rbits, W_VARBASE, digits_Q);
    FP_ZERO(T->X); FP_ZERO(T->Y); T->Y[0] = 1; FP_ZERO(T->Z);   // Initialize T as the point at infinity (0:1:0)  

    for (i = JacCurve->rbits; i >= 0; i--)
    {
        if (digits_Q[i] == 0) {
            ECCDOUBLE_INTERNAL_WJAC(T, JacCurve);               // Double (T_X:T_Y:T_Z) = 2(T_X:T_Y:T_Z)
        } else if (digits_Q[i] < 0) {
            position = (-digits_Q[i])/2;                        // Load S = (X_S:Y_S:Z_S:Z_S^2:Z_S^3) with a point from the precomputed table
            ECCCOPY_WCHU(table[position], S);               
            FP_NEG(JacCurve->prime, S->Y);                      // Negate S
            ECCDOUBLEADD_CONDITIONALS_WJAC(S, T, JacCurve);     // Double-add (X_T:Y_T:Z_T) = 2(X_T:Y_T:Z_T) + (X_S:Y_S:Z_S:Z_S^2:Z_S^3)
        } else if (digits_Q[i] > 0) {            
            position = (digits_Q[i])/2;                         // Load S = (X_S:Y_S:Z_S:Z_S^2:Z_S^3) with a point from the precomputed table
            ECCCOPY_WCHU(table[position], S);               
            ECCDOUBLEADD_CONDITIONALS_WJAC(S, T, JacCurve);     // Double-add (X_T:Y_T:Z_T) = 2(X_T:Y_T:Z_T) + (X_S:Y_S:Z_S:Z_S^2:Z_S^3)
        }
        if (digits_P[i] < 0) {                           
            position = (-digits_P[i])/2;                        // Load SS = (x_SS:y_SS) with a point from the precomputed table
            ECCCOPY_W(P_table[position], SS);
            FP_NEG(JacCurve->prime, SS->y);                     // Negate SS
            ECCMADD_CONDITIONALS_WJAC(SS, T, JacCurve);         // Mixed double-add (X_T:Y_T:Z_T) = 2(X_T:Y_T:Z_T) + (x_SS:y_SS)
        } else if (digits_P[i] > 0) { 
            position = (digits_P[i])/2;                         // Load SS = (x_SS:y_SS) with a point from the precomputed table
            ECCCOPY_W(P_table[position], SS);
            ECCMADD_CONDITIONALS_WJAC(SS, T, JacCurve);         // Mixed double-add (X_T:Y_T:Z_T) = 2(X_T:Y_T:Z_T) + (x_SS:y_SS)
        }
    }
    ECCNORM_W(T, R, JacCurve);                                  // Output R = (x,y)
    
    return ECCRYPTO_SUCCESS;
}


ECCRYPTO_STATUS ECC_PRECOMP_DBLMUL_W(POINT_WAFF P, POINT_WAFF* T, PCurveStruct JacCurve)
{ // Wrapper for precomputation scheme using affine coordinates for the fixed-base in double-scalar multiplication
  // Weierstrass a=-3 curve
    unsigned int w_P;

    if (P == NULL || T == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }       
    w_P = JacCurve->w_doublescalar;

    return ECC_PRECOMP_DBLMUL_INTERNAL_W(P, T, w_P, JacCurve);
}



ECCRYPTO_STATUS ECC_PRECOMP_DBLMUL_INTERNAL_W(POINT_WAFF P, POINT_WAFF* T, unsigned int w_P, PCurveStruct JacCurve)
{ // Precomputation scheme using affine coordinates for the fixed base in double-scalar multiplication.
  // Weierstrass a=-3 curve
    POINT_PRECOMP_WCHU T_CHU[1 << (WMAX - 2)] = {0};
    unsigned int i, npoints; 
    BASE_ELM t1, t2, t3;
                
    // SECURITY NOTE: precomputation for double-scalar multiplication uses public inputs. 

    // Point validation
    if (ECC_VALIDATION_W(P, JacCurve) != ECCRYPTO_SUCCESS) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    npoints = (1 << (w_P-2));

    ECC_PRECOMP_WJAC(P, T_CHU, npoints, JacCurve);
    for (i = 0; i < npoints; i++)
    {            
        FP_COPY(T_CHU[i]->Z, t1);  
        FP_INV(t1);                          // t1 = Z^-1
        FP_SQR(t1, t2);                      // t2 = Z^-2
        FP_MUL(T_CHU[i]->X, t2, T[i]->x);    // x = X/Z^2
        FP_MUL(t1, t2, t3);                  // t3 = Z^-3
        FP_MUL(T_CHU[i]->Y, t3, T[i]->y);    // y = Y/Z^3 
    }

    return ECCRYPTO_SUCCESS;
}


POINT_WAFF* ECC_ALLOCATE_PRECOMP_W(OpType scalarmultype, PCurveStruct JacCurve)
{ // Allocates memory dynamically for precomputation table "T_fixed" used during fixed-base or double-scalar multiplications.
  // This function must be called before using a table generated by ecc_precomp_fixed_<NUMS_Weierstrass_curve> or ecc_precomp_dblmul_<NUMS_Weierstrass_curve>. 
  // Weierstrass a=-3 curve
    unsigned int npoints;

    if (is_ecc_curve_null(JacCurve) || scalarmultype < 0 || scalarmultype >= OpTypeSize) {
        return NULL;
    }

    if (scalarmultype == OP_FIXEDBASE) {
        npoints = (JacCurve->v_fixedbase)*(1 << (JacCurve->w_fixedbase - 1));
    } else if (scalarmultype == OP_DOUBLESCALAR) {
        npoints = 1 << (JacCurve->w_doublescalar - 2);
    } else {
        return NULL;
    }

    return (POINT_WAFF*)calloc(npoints, sizeof(POINT_WAFF));    // Allocating memory for table
}


#if (defined(AVX_SUPPORT) == FALSE) || (TARGET_GENERIC == TRUE) 

void LUT_WCHU(POINT_PRECOMP_WCHU* table, POINT_PRECOMP_WCHU P, int digit, unsigned int npoints, PCurveStruct JacCurve)
{ // Constant-time table lookup to extract a Chudnovsky point (X:Y:Z:Z^2:Z^3) from the precomputed table
  // Weierstrass a=-3 curve
  // Operation: P = sign * table[(|digit|-1)/2], where sign=1 if digit>0 and sign=-1 if digit<0
    unsigned int i, j, nwords = NBITS_TO_NWORDS(BASE_ELM_NBYTES*8);
    dig sign, mask, pos;
    POINT_PRECOMP_WCHU point, temp_point;

    sign = ((dig)digit >> (ML_WORD - 1)) - 1;                             // if digit<0 then sign = 0x00...0 else sign = 0xFF...F
    pos = ((sign & ((dig)digit ^ (dig)-digit)) ^ (dig)-digit) >> 1;       // position = (|digit|-1)/2  
    ECCCOPY_WCHU(table[0], point);                                        // point = table[0] 

    for (i = 1; i < npoints; i++)
    {
        pos--;
        // If match then mask = 0xFF...F else sign = 0x00...0
        mask = (dig)is_digit_nonzero_ct(pos) - 1;
        ECCCOPY_WCHU(table[i], temp_point);                               // temp_point = table[i+1] 
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        for (j = 0; j < nwords; j++) {
            point->X[j] = (mask & (point->X[j] ^ temp_point->X[j])) ^ point->X[j];
            point->Y[j] = (mask & (point->Y[j] ^ temp_point->Y[j])) ^ point->Y[j];
            point->Z[j] = (mask & (point->Z[j] ^ temp_point->Z[j])) ^ point->Z[j];
            point->Z2[j] = (mask & (point->Z2[j] ^ temp_point->Z2[j])) ^ point->Z2[j];
            point->Z3[j] = (mask & (point->Z3[j] ^ temp_point->Z3[j])) ^ point->Z3[j];
        }
    }

    ECCCOPY_WCHU(point, P);
    FP_NEG(JacCurve->prime, P->Y);                                      // point->Y: y coordinate  
    FP_COPY(P->Y, temp_point->Y);                                       // temp_point->Y: -y coordinate
    for (j = 0; j < nwords; j++) {                                      // if sign = 0x00...0 then choose negative of the point
        point->Y[j] = (sign & (point->Y[j] ^ temp_point->Y[j])) ^ temp_point->Y[j];
    }
    FP_COPY(point->Y, P->Y);
    
// cleanup
#ifdef TEMP_ZEROING
    ECCZERO_WCHU(point);
    ECCZERO_WCHU(temp_point);
#endif
    return;
}


void LUT_WAFF(POINT_WAFF* table, POINT_WAFF P, int digit, int sign, unsigned int npoints, PCurveStruct JacCurve)
{ // Constant-time table lookup to extract an affine point from the precomputed table
  // If (sign = 0x00...0) then final digit is positive, else if (sign = 0xFF...F) then final digit is negative
  // Weierstrass a=-3 curve
  // Operation: if sign=0 then P = table[digit], else if (sign=-1) then P = -table[digit]
    unsigned int i, j, nwords = ((BASE_ELM_NBYTES*8) + ML_WORD - 1) / ML_WORD;
    dig pos, mask;
    POINT_WAFF point, temp_point;

    pos = (dig)digit;                                                  // Load digit position
    ECCCOPY_W(table[0], point);                                        // point = table[0] 

    for (i = 1; i < npoints; i++)
    {
        pos--;
        // If match then mask = 0xFF...F else sign = 0x00...0
        mask = (dig)is_digit_nonzero_ct(pos) - 1;
        ECCCOPY_W(table[i], temp_point);                              // temp_point = table[i+1] 
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        for (j = 0; j < nwords; j++) {
            point->x[j] = (mask & (point->x[j] ^ temp_point->x[j])) ^ point->x[j];
            point->y[j] = (mask & (point->y[j] ^ temp_point->y[j])) ^ point->y[j];
        }
    }

    ECCCOPY_W(point, P);
    FP_NEG(JacCurve->prime, P->y);                                      // point->y: y coordinate  
    FP_COPY(P->y, temp_point->y);                                       // temp_point->y: -y coordinate
    for (j = 0; j < nwords; j++) {                                      // if sign = 0xFF...F then choose negative of the point
        point->y[j] = ((dig)sign & (point->y[j] ^ temp_point->y[j])) ^ point->y[j];
    }
    FP_COPY(point->y, P->y);

// cleanup
#ifdef TEMP_ZEROING
    ECCZERO_WAFF(point);
    ECCZERO_WAFF(temp_point);
#endif
    return;
}

#endif


#if (USE_ASM == FALSE) || (TARGET_GENERIC == TRUE)

unsigned int COMPLETE_EVAL(BASE_ELM val1, BASE_ELM val2, BASE_ELM val3, dig *mask)
{ // Evaluation for the complete addition
  // Determines the index for table lookup and the mask for element selections using complete_select_<NUMS_Weierstrass_curve>
    dig index_temp = 0, index = 3;
    dig eval1, eval2;

    eval1 = (dig)(FP_ISZERO(val1) - 1);                               // if val1 = 0 then eval1 = 0, else eval1 = -1
    index = (eval1 & (index ^ index_temp)) ^ index_temp;              // if val1 = 0 then index = 0

    index_temp = 2;
    eval2 = (dig)(FP_ISZERO(val3) - 1);                               // if val3 = 0 then eval2 = 0, else eval2 = -1
    index = ((eval1 | eval2) & (index ^ index_temp)) ^ index_temp;    // if (val1 = 0 & val3 = 0) then index = 2

    index_temp = 1;
    eval1 = (dig)(FP_ISZERO(val2) - 1);                               // if val2 = 0 then eval1 = 0, else eval1 = -1
    index = (eval1 & (index ^ index_temp)) ^ index_temp;              // if val2 = 0 then index = 1

    // If index=3 then mask = 0xFF...F else mask = 0x00...0
    *mask = (dig)is_digit_nonzero_ct(index-3) - 1;

    return (unsigned int)index;
}


void COMPLETE_SELECT(BASE_ELM in1, BASE_ELM in2, BASE_ELM out, dig mask)
{ // Field element selection for the complete addition
  // Operation: if mask = 0 then out = in1, else if mask = 0xff...ff then out = in2
    dig i, nwords = NBITS_TO_NWORDS(BASE_ELM_NBYTES*8);

    for (i = 0; i < nwords; i++) {
        out[i] = (mask & (in1[i] ^ in2[i])) ^ in1[i];
    }
    return;
}


void COMPLETE_LUT(POINT_WJAC *table, unsigned int index, POINT_WJAC P, unsigned int npoints)
{ // Point extraction from LUT for the complete addition
    unsigned int i, j, nwords = NBITS_TO_NWORDS(BASE_ELM_NBYTES*8);
    dig pos, mask;
    POINT_WJAC point, temp_point;

    pos = (dig)index;                                                    // Load digit position
    ECCCOPY_WJAC(table[0], point);                                       // point = table[0] 

    for (i = 1; i < npoints; i++)
    {
        pos--;
        // If match then mask = 0xFF...F else sign = 0x00...0
        mask = (dig)is_digit_nonzero_ct(pos) - 1;
        ECCCOPY_WJAC(table[i], temp_point);                              // temp_point = table[i+1] 
        // If mask = 0x00...0 then point = point, else if mask = 0xFF...F then point = temp_point
        for (j = 0; j < nwords; j++) {
            point->X[j] = (mask & (point->X[j] ^ temp_point->X[j])) ^ point->X[j];
            point->Y[j] = (mask & (point->Y[j] ^ temp_point->Y[j])) ^ point->Y[j];
            point->Z[j] = (mask & (point->Z[j] ^ temp_point->Z[j])) ^ point->Z[j];
        }
    }
    ECCCOPY_WJAC(point, P);

// cleanup
#ifdef TEMP_ZEROING
    ECCZERO_WJAC(point);
    ECCZERO_WJAC(temp_point);
#endif
    return;
}

#endif
