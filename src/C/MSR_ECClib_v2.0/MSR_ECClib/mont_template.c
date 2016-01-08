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
* Abstract: template for Montgomery operations
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
******************************************************************************/  

#include "msr_ecclib.h"
#include "msr_ecclib_priv.h"


void MONTGOMERY_MUL_MOD_ORDER(BASE_ELM ma, BASE_ELM mb, BASE_ELM mc, PCurveStruct PCurve)
{ // Wrapper of the Montgomery multiplication using the order of a curve as modulus

    MONTGOMERY_MUL(ma, mb, mc, PCurve->order, PCurve->rprime, NBITS_TO_NWORDS(PCurve->rbits));
}


void TO_MONTGOMERY_MOD_ORDER(BASE_ELM a, BASE_ELM mc, PCurveStruct PCurve)
{ // Wrapper of the conversion to Montgomery representation using the order as modulus
  // mc = a*Rprime mod r, where a,mc in [0, r-1], a,mc,r < 2^nbits, nbits in {256,384,512}
    TO_MONTGOMERY(a, mc, PCurve->order, PCurve->Rprime, PCurve->rprime);
}


void TO_MONTGOMERY(BASE_ELM a, BASE_ELM mc, BASE_ELM modulus, BASE_ELM Montgomery_Rprime, BASE_ELM Montgomery_rprime)
{ // Conversion to Montgomery representation
  // mc = a*Rprime mod modulus, where a,mc in [0, modulus-1], a,mc,modulus < 2^nbits, nbits in {256,384,512}
    MONTGOMERY_MUL(a, Montgomery_Rprime, mc, modulus, Montgomery_rprime, NBITS_TO_NWORDS(BASE_ELM_NBYTES*8));
}

void FROM_MONTGOMERY_MOD_ORDER(BASE_ELM ma, BASE_ELM c, PCurveStruct PCurve)
{ // Wrapper of the conversion from Montgomery using the order as modulus
  // ma is assumed to be in Montgomery representation
    FROM_MONTGOMERY(ma, c, PCurve->order, PCurve->rprime);
}


void FROM_MONTGOMERY(BASE_ELM ma, BASE_ELM c, BASE_ELM modulus, BASE_ELM Montgomery_rprime)
{ // Conversion from Montgomery representation
  // c = ma*1*Rprime^(-1) mod modulus, where ma,c in [0, modulus-1], ma,c,modulus < 2^nbits, nbits in {256,384,512}
    BASE_ELM one = {0};

    one[0] = 1;
    MONTGOMERY_MUL(ma, one, c, modulus, Montgomery_rprime, NBITS_TO_NWORDS(BASE_ELM_NBYTES*8));
}


void MONTGOMERY_INV_MOD_ORDER(BASE_ELM ma, BASE_ELM mc, PCurveStruct PCurve)
{ // Wrapper of the Montgomery inversion using the order as modulus, a^(-1) = a^(r-2) mod r
    MONTGOMERY_INV(ma, mc, PCurve->order, PCurve->rprime);
}


void MONTGOMERY_INV(BASE_ELM ma, BASE_ELM mc, BASE_ELM modulus, BASE_ELM Montgomery_rprime)
{ // (Non-constant time) Montgomery inversion using a^(-1) = a^(modulus-2) mod modulus
  // It uses the sliding-window method
    sdig i = BASE_ELM_NBYTES*8;
    dig temp, bit = 0;
    unsigned int j, nwords = NBITS_TO_NWORDS(BASE_ELM_NBYTES*8);
    dig count, mod2, k_EXPON = 5;                    // Fixing parameter k to 5 for the sliding windows method
    BASE_ELM modulus2, input_a, table[16];           // Fixing the number of precomputed field elements to 16 (assuming k = 5)
    dig mask = ((dig)1 << (ML_WORD-1));              // 0x100...000
    dig mask2 = ~((dig)-1 >> k_EXPON);               // 0xF800...000, assuming k = 5
    dig npoints = 16;
          
    // SECURITY NOTE: this function does not run in constant time because the modulus is assumed to be public.

    FP_ZERO(modulus2); modulus2[0] = 2;
    subtract(modulus, modulus2, modulus2, nwords);   // modulus-2
     
    // Precomputation stage
    copy(ma, table[0], nwords);                                                              // table[0] = ma 
    MONTGOMERY_MUL(ma, ma, input_a, modulus, Montgomery_rprime, nwords);                     // ma^2
    for (j = 0; j < npoints-1; j++) {
        MONTGOMERY_MUL(table[j], input_a, table[j+1], modulus, Montgomery_rprime, nwords);   // table[j+1] = table[j] * ma^2
    }

    while (bit != 1) {                               // Shift (modulus-2) to the left until getting first bit 1
        i--;
        temp = 0;
        for (j = 0; j < nwords; j++) {
            bit = (modulus2[j] & mask) >> (ML_WORD-1);
            modulus2[j] = (modulus2[j] << 1) | temp;
            temp = bit;
        }
    }

    // Evaluation stage
    copy(ma, mc, nwords);   
    bit = (modulus2[nwords-1] & mask) >> (ML_WORD-1); 
    while (i > 0) {             
        if (bit == 0) {                              // Square accumulated value because bit == 0 and shift (modulus-2) one bit to the left
            MONTGOMERY_MUL(mc, mc, mc, modulus, Montgomery_rprime, nwords);        // mc = mc^2
            i--;
            for (j = (nwords-1); j > 0; j--) {
                SHIFTL(modulus2[j], modulus2[j-1], 1, modulus2[j]);
            }
            modulus2[0] = modulus2[0] << 1;
        } else {                                    // "temp" will store the longest odd bitstring with "count" bits s.t. temp <= 2^k - 1 
            count = k_EXPON;
            temp = (modulus2[nwords-1] & mask2) >> (ML_WORD-k_EXPON);              // Extracting next k bits to the left
            mod2 = temp & 1;
            while (mod2 == 0) {                     // if even then shift to the right and adjust count
                temp = (temp >> 1);
                mod2 = temp & 1;
                count--;
            }
            for (j = 0; j < count; j++) {                                          // mc = mc^count
                MONTGOMERY_MUL(mc, mc, mc, modulus, Montgomery_rprime, nwords);         
            }
            MONTGOMERY_MUL(mc, table[(temp-1)>>1], mc, modulus, Montgomery_rprime, nwords);   // mc = mc * table[(temp-1)/2] 
            i = i - count;

            for (j = (nwords-1); j > 0; j--) {        // Shift (modulus-2) "count" bits to the left
                SHIFTL(modulus2[j], modulus2[j-1], count, modulus2[j]);
            }
            modulus2[0] = modulus2[0] << count;
        }
        bit = (modulus2[nwords-1] & mask) >> (ML_WORD-1);
    }

    return;
}