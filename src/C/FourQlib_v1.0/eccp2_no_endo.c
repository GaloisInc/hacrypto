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
* Abstract: ECC operations over GF(p^2) without exploiting endomorphisms
*
* This code is based on the paper "FourQ: four-dimensional decompositions on a 
* Q-curve over the Mersenne prime" by Craig Costello and Patrick Longa, in Advances 
* in Cryptology - ASIACRYPT, 2015.
* Preprint available at http://eprint.iacr.org/2015/565.
************************************************************************************/

#include "FourQ.h"


#if (USE_ENDO == false)

/***********************************************/
/**********  CURVE/SCALAR FUNCTIONS  ***********/

void fixed_window_recode(digit64_256_t scalar, unsigned int* digits, unsigned int* sign_masks)
{ // Converting scalar to the fixed window representation used by the variable-base scalar multiplication
  // Inputs: scalar in [0, order-1], where the order of FourQ's subgroup is 246 bits.
  // Outputs: "digits" array with (t_VARBASE+1) nonzero entries. Each entry is in the range [0, 7], corresponding to one entry in the precomputed table.
  //          where t_VARBASE+1 = ((bitlength(order)+w-1)/(w-1))+1 represents the fixed length of the recoded scalar using window width w. 
  //          The value of w is fixed to W_VARBASE = 5, which corresponds to a precomputed table with 2^(W_VARBASE-2) = 8 entries (see FourQ.h)
  //          used by the variable base scalar multiplication ecc_mul(). 
  //          "sign_masks" array with (t_VARBASE+1) entries storing the signs for their corresponding digits in "digits". 
  //          Notation: if the corresponding digit > 0 then sign_mask = 0xFF...FF, else if digit < 0 then sign_mask = 0.
    unsigned int val1, val2, i, j;
    uint64_t res, borrow;
    int64_t temp;

    val1 = (1 << W_VARBASE) - 1;
    val2 = (1 << (W_VARBASE-1));

    for (i = 0; i < t_VARBASE; i++)
    {
        temp = (scalar[0] & val1) - val2;    // ki = (k mod 2^w)/2^(w-1)
        sign_masks[i] = ~((unsigned int)(temp >> (RADIX64-1)));
        digits[i] = ((sign_masks[i] & (unsigned int)(temp ^ -temp)) ^ (unsigned int)-temp) >> 1;        
                 
        res = scalar[0] - temp;              // k = (k - ki) / 2^(w-1) 
        borrow = ((temp >> (RADIX64-1)) - 1) & (uint64_t)is_digit_lessthan_ct((digit_t)scalar[0], (digit_t)temp);
        scalar[0] = res;
  
        for (j = 1; j < NWORDS64_ORDER; j++)
        {
            res = scalar[j];
            scalar[j] = res - borrow;
            borrow = (uint64_t)is_digit_lessthan_ct((digit_t)res, (digit_t)borrow); 
        }    
  
        for (j = 0; j < (NWORDS64_ORDER-1); j++) {           
            SHIFTR(scalar[j+1], scalar[j], (W_VARBASE-1), scalar[j], RADIX64);
        }
        scalar[NWORDS64_ORDER-1] = scalar[NWORDS64_ORDER-1] >> (W_VARBASE-1);

    } 
    sign_masks[t_VARBASE] = ~((unsigned int)(scalar[0] >> (RADIX64-1)));
    digits[t_VARBASE] = ((sign_masks[t_VARBASE] & (unsigned int)(scalar[0] ^ (0-scalar[0]))) ^ (unsigned int)(0-scalar[0])) >> 1;    // kt = k  (t_VARBASE+1 digits)
}


void ecc_precomp(point_extproj_t P, point_extproj_precomp_t *T, PCurveStruct curve)
{ // Generation of the precomputation table used by the variable-base scalar multiplication ecc_mul().
  // Input: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates.
  // Output: table T containing NPOINTS_VARBASE points: P, 3P, 5P, ... , (2*NPOINTS_VARBASE-1)P. NPOINTS_VARBASE is fixed to 8 (see FourQ.h).
  //         Precomputed points use the representation (X+Y,Y-X,2Z,2dT) corresponding to (X:Y:Z:T) in extended twisted Edwards coordinates.
    point_extproj_precomp_t P2;
    point_extproj_t Q;
    unsigned int i; 

    // Generating P2 = 2(X1,Y1,Z1,T1a,T1b) = (XP2+YP2,Y2P-X2P,ZP2,TP2) and T[0] = P = (X1+Y1,Y1-X1,2*Z1,2*d*T1)
    ecccopy(P, Q);
    R1_to_R2(P, T[0], curve);
    eccdouble(Q);
    R1_to_R3(Q, P2);

    for (i = 1; i < NPOINTS_VARBASE; i++) {
        // T[i] = 2P+T[i-1] = (2*i+1)P = (XP2+YP2,Y2P-X2P,ZP2,TP2) + (X_(2*i-1)+Y_(2*i-1), Y_(2*i-1)-X_(2*i-1), 2Z_(2*i-1), 2T_(2*i-1)) = (X_(2*i+1)+Y_(2*i+1), Y_(2*i+1)-X_(2*i+1), 2Z_(2*i+1), 2dT_(2*i+1))
        eccadd_core(P2, T[i-1], Q);
        R1_to_R2(Q, T[i], curve);
    }
}


void cofactor_clearing(point_extproj_t P, PCurveStruct curve)
{ // Co-factor clearing
  // Input: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to (X1:Y1:Z1:T1) in extended twisted Edwards coordinates
  // Output: P = 392*P = (Xfinal,Yfinal,Zfinal,Tafinal,Tbfinal), where Tfinal = Tafinal*Tbfinal,
  //         corresponding to (Xfinal:Yfinal:Zfinal:Tfinal) in extended twisted Edwards coordinates
    point_extproj_precomp_t Q;
     
    R1_to_R2(P, Q, curve);               // Converting from (X,Y,Z,Ta,Tb) to (X+Y,Y-X,2Z,2dT)
    eccdouble(P);                        // P = 2*P using representations (X,Y,Z,Ta,Tb) <- 2*(X,Y,Z)
    eccadd(Q, P);                        // P = P+Q using representations (X,Y,Z,Ta,Tb) <- (X,Y,Z,Ta,Tb) + (X+Y,Y-X,2Z,2dT)
    eccdouble(P);
    eccdouble(P);
    eccdouble(P);
    eccdouble(P);
    eccadd(Q, P);
    eccdouble(P);
    eccdouble(P);
    eccdouble(P);
}


bool ecc_mul(point_t P, digit64_256_t k, point_t Q, bool clear_cofactor, PCurveStruct curve)
{ // Scalar multiplication Q = k*P
  // Inputs: scalar "k" in [0, 2^256-1],
  //         point P = (x,y) in affine coordinates,
  //         clear_cofactor = 1 (TRUE) or 0 (FALSE) whether cofactor clearing is required or not, respectively,
  //         FourQ structure "curve".
  // Output: Q = k*P in affine coordinates (x,y).
  // This function performs point validation and (if selected) cofactor clearing.
    point_extproj_t R;
    point_extproj_precomp_t S, Table[NPOINTS_VARBASE];
    unsigned int digits[t_VARBASE+1] = {0}, sign_masks[t_VARBASE+1] = {0};
    uint64_t k_odd[NWORDS64_ORDER];
    int i;

    point_setup(P, R);                                         // Clear most significant bit of input coordinates and convert to representation (X,Y,1,Ta,Tb)

    if (ecc_point_validate(R, curve) == false) {               // Check if point lies on the curve
        return false;
    }

    if (clear_cofactor == true) {
        cofactor_clearing(R, curve);
    }

    modulo_order((digit_t*)k, (digit_t*)k, curve);             // k = k mod (order)      
    conversion_to_odd((digit_t*)k, (digit_t*)k_odd, curve);    // Converting scalar to odd using the prime subgroup order 
    ecc_precomp(R, Table, curve);                              // Precomputation of points T[0],...,T[npoints-1] 
    fixed_window_recode(k_odd, digits, sign_masks);            // Scalar recoding
    table_lookup_1x8(Table, S, digits[t_VARBASE], sign_masks[t_VARBASE]);       
    R2_to_R4(S, R);                                            // Conversion to representation (2X,2Y,2Z)
    
    for (i = (t_VARBASE-1); i >= 0; i--)
    {
        eccdouble(R);
        table_lookup_1x8(Table, S, digits[i], sign_masks[i]);  // Extract point in (X+Y,Y-X,2Z,2dT) representation
        eccdouble(R);
        eccdouble(R);
        eccdouble(R);                                          // P = 2*P using representations (X,Y,Z,Ta,Tb) <- 2*(X,Y,Z)
        eccadd(S, R);                                          // P = P+S using representations (X,Y,Z,Ta,Tb) <- (X,Y,Z,Ta,Tb) + (X+Y,Y-X,2Z,2dT)
    }
    eccnorm(R, Q);                                             // Convert to affine coordinates (x,y) 
    
#ifdef TEMP_ZEROING
    clear_words((void*)digits, t_VARBASE+1);
    clear_words((void*)sign_masks, t_VARBASE+1);
    clear_words((void*)S, sizeof(point_extproj_precomp_t)/sizeof(unsigned int));
#endif
    return true;
}

#endif
