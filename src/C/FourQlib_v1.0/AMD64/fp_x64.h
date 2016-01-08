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
* Abstract: modular arithmetic and other low-level operations for x64 platforms
*
* This code is based on the paper "FourQ: four-dimensional decompositions on a 
* Q-curve over the Mersenne prime" by Craig Costello and Patrick Longa, in Advances 
* in Cryptology - ASIACRYPT, 2015.
* Preprint available at http://eprint.iacr.org/2015/565.
************************************************************************************/

#ifndef __FP_X64_H__
#define __FP_X64_H__


// For C++
#ifdef __cplusplus
extern "C" {
#endif


#include "../table_lookup.h"


#if defined(UINT128_SUPPORT)
    static uint128_t prime1271 = ((uint128_t)1 << 127) - 1;
#elif defined(SCALAR_INTRIN_SUPPORT)
    static uint128_t prime1271 = {0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF};  
#endif 
#define mask63 0x7FFFFFFFFFFFFFFF


void mod1271(felm_t a)
{ // Modular correction, a = a mod (2^127-1)
    
#if defined(UINT128_SUPPORT)
    uint128_t* r = (uint128_t*)&a[0];

    *r = *r - prime1271;
    *r = *r + (((uint128_t)0 - (*r >> 127)) & prime1271);
#elif defined(SCALAR_INTRIN_SUPPORT)
    uint64_t mask;
    uint128_t prime;
    
    prime[0] = prime1271[0]; 
    prime[1] = prime1271[1];

    SUB128(a, prime1271, a);
    mask = 0 - (a[1] >> 63);
    prime[0] &= mask; prime[1] &= mask;
    ADD128(a, prime, a);
#endif
}


static __inline void fpcopy1271(felm_t a, felm_t c)
{ // Copy of a field element, c = a
    c[0] = a[0];
    c[1] = a[1];
}


static __inline void fpzero1271(felm_t a)
{ // Zeroing a field element, a = 0
    a[0] = 0;
    a[1] = 0;
}


static __inline void fpadd1271(felm_t a, felm_t b, felm_t c)
{ // Field addition, c = a+b mod (2^127-1)
    
#if defined(UINT128_SUPPORT)
    uint128_t* r = (uint128_t*)&a[0];
    uint128_t* s = (uint128_t*)&b[0];
    uint128_t* t = (uint128_t*)&c[0];

    *t = *r + *s;
    *t += (*t >> 127);
    *t &= prime1271;
#elif defined(SCALAR_INTRIN_SUPPORT)
    uint64_t temp;
    unsigned char carry;

    ADD128(a, b, c);
    temp = __ull_rshift(c[1], 63);
    c[1] &= mask63;
    carry = _addcarry_u64(0, c[0], temp, &c[0]);
    _addcarry_u64(carry, c[1], 0, &c[1]);
#endif
}


static __inline void fpsub1271(felm_t a, felm_t b, felm_t c)
{ // Field subtraction, c = a-b mod (2^127-1)
    
#if defined(UINT128_SUPPORT)
    uint128_t* r = (uint128_t*)&a[0];
    uint128_t* s = (uint128_t*)&b[0];
    uint128_t* t = (uint128_t*)&c[0];

    *t = *r - *s;
    *t -= (*t >> 127);
    *t &= prime1271;
#elif defined(SCALAR_INTRIN_SUPPORT)
    uint64_t temp;
    unsigned char borrow;

    SUB128(a, b, c);
    temp = __ull_rshift(c[1], 63);
    c[1] &= mask63;
    borrow = _subborrow_u64(0, c[0], temp, &c[0]);
    _subborrow_u64(borrow, c[1], 0, &c[1]);
#endif
} 


__inline void fpneg1271(felm_t a)
{ // Field negation, a = -a mod (2^127-1)
    
#if defined(UINT128_SUPPORT)
    uint128_t* r = (uint128_t*)&a[0];

    *r = prime1271 - *r;
#elif defined(SCALAR_INTRIN_SUPPORT)
    SUB128(prime1271, a, a);
#endif
}


static __inline void fpmul1271(felm_t a, felm_t b, felm_t c)
{ // Field multiplication, c = a*b mod (2^127-1)
    uint128_t tt1, tt2, tt3 = {0};
    
#if defined(UINT128_SUPPORT)
    tt1 = (uint128_t)a[0]*b[0];
    tt2 = (uint128_t)a[0]*b[1] + (uint128_t)a[1]*b[0] + (uint64_t)(tt1 >> 64);
    tt3 = (uint128_t)a[1]*(b[1]*2) + ((uint128_t)tt2 >> 63);
    tt1 = (uint64_t)tt1 | ((uint128_t)((uint64_t)tt2 & mask63) << 64);
    tt1 += tt3;
    tt1 = (tt1 >> 127) + (tt1 & prime1271); 
    c[0] = (uint64_t)tt1;
    c[1] = (uint64_t)(tt1 >> 64);
#elif defined(SCALAR_INTRIN_SUPPORT)
    uint128_t tt4;

    MUL128(a[0], b[0], tt1);   
    tt3[0] = tt1[1];
    MUL128(a[0], b[1], tt2); ADD128(tt2, tt3, tt2);
    MUL128(a[1], b[0], tt3); ADD128(tt2, tt3, tt2);
    MUL128(a[1], b[1], tt3);
    SHIFTR128(tt2, 63, tt4);
    SHIFTL128(tt3, 1, tt3);
    ADD128(tt4, tt3, tt3);
    tt1[1] = tt2[0] & mask63;
    ADD128(tt1, tt3, tt1);
    tt3[1] = 0; tt3[0] = __ull_rshift(tt1[1], 63);
    tt1[1] &= mask63; 
    ADD128(tt1, tt3, c);
#endif
}


void fpsqr1271(felm_t a, felm_t c)
{ // Field squaring, c = a^2 mod (2^127-1)
    uint128_t tt1, tt2, tt3 = {0};
  
#if defined(UINT128_SUPPORT)
    tt1 = (uint128_t)a[0]*a[0];
    tt2 = (uint128_t)a[0]*(a[1]*2) + (uint64_t)(tt1 >> 64);
    tt3 = (uint128_t)a[1]*(a[1]*2) + ((uint128_t)tt2 >> 63);
    tt1 = (uint64_t)tt1 | ((uint128_t)((uint64_t)tt2 & mask63) << 64);
    tt1 += tt3;
    tt1 = (tt1 >> 127) + (tt1 & prime1271); 
    c[0] = (uint64_t)tt1;
    c[1] = (uint64_t)(tt1 >> 64);
#elif defined(SCALAR_INTRIN_SUPPORT)
    uint128_t tt4;

    MUL128(a[0], a[0], tt1);   
    tt3[0] = tt1[1];
    MUL128(a[0], a[1], tt2); ADD128(tt2, tt3, tt3); ADD128(tt2, tt3, tt2);
    MUL128(a[1], a[1], tt3);
    SHIFTR128(tt2, 63, tt4);
    SHIFTL128(tt3, 1, tt3);
    ADD128(tt4, tt3, tt3);
    tt1[1] = tt2[0] & mask63;
    ADD128(tt1, tt3, tt1);
    tt3[1] = 0; tt3[0] = __ull_rshift(tt1[1], 63);
    tt1[1] &= mask63; 
    ADD128(tt1, tt3, c);
#endif
}


void fpinv1271(felm_t a)
{ // Field inversion, af = a^-1 = a^(p-2) mod p
  // Hardcoded for p = 2^127-1
    int i;
    felm_t t1, t2, t3, t4, t5;

    fpsqr1271(a, t2);                              
    fpmul1271(a, t2, t2); 
    fpsqr1271(t2, t3);  
    fpsqr1271(t3, t3);                          
    fpmul1271(t2, t3, t3);
    fpsqr1271(t3, t4);  
    fpsqr1271(t4, t4);   
    fpsqr1271(t4, t4);  
    fpsqr1271(t4, t4);                         
    fpmul1271(t3, t4, t4);  
    fpsqr1271(t4, t5);
    for (i=0; i<7; i++) fpsqr1271(t5, t5);                      
    fpmul1271(t4, t5, t5); 
    fpsqr1271(t5, t2); 
    for (i=0; i<15; i++) fpsqr1271(t2, t2);                    
    fpmul1271(t5, t2, t2); 
    fpsqr1271(t2, t1); 
    for (i=0; i<31; i++) fpsqr1271(t1, t1);                         
    fpmul1271(t2, t1, t1); 
    for (i=0; i<32; i++) fpsqr1271(t1, t1);    
    fpmul1271(t1, t2, t1); 
    for (i=0; i<16; i++) fpsqr1271(t1, t1);                         
    fpmul1271(t5, t1, t1);    
    for (i=0; i<8; i++) fpsqr1271(t1, t1);                           
    fpmul1271(t4, t1, t1);    
    for (i=0; i<4; i++) fpsqr1271(t1, t1);                          
    fpmul1271(t3, t1, t1);    
    fpsqr1271(t1, t1);                           
    fpmul1271(a, t1, t1);    
    fpsqr1271(t1, t1);     
    fpsqr1271(t1, t1);                             
    fpmul1271(a, t1, a); 
}


#if defined(USE_FIXED_BASE_SM) || (USE_ENDO == false)

static __inline void multiply(digit_t* a, digit_t* b, digit_t* c)
{ // Schoolbook multiprecision multiply, c = a*b   
    unsigned int i, j;
    digit_t u, v, UV[2];
    unsigned char carry = 0;

     for (i = 0; i < (2*NWORDS_ORDER); i++) c[i] = 0;

     for (i = 0; i < NWORDS_ORDER; i++) {
          u = 0;
          for (j = 0; j < NWORDS_ORDER; j++) {
               MUL(a[i], b[j], UV+1, UV[0]); 
               ADDC(0, UV[0], u, carry, v); 
               u = UV[1] + carry;
               ADDC(0, c[i+j], v, carry, v); 
               u = u + carry;
               c[i+j] = v;
          }
          c[NWORDS_ORDER+i] = u;
     }
}


static __inline unsigned char add(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords)
{ // Multiprecision addition, c = a+b. Returns the carry bit 
    unsigned int i;
    unsigned char carry = 0;

    for (i = 0; i < nwords; i++) {
        ADDC(carry, a[i], b[i], carry, c[i]);
    }
    
    return carry;
}


unsigned char subtract(digit_t* a, digit_t* b, digit_t* c, unsigned int nwords)
{ // Multiprecision subtraction, c = a-b. Returns the borrow bit 
    unsigned int i;
    unsigned char borrow = 0;

    for (i = 0; i < nwords; i++) {
        SUBC(borrow, a[i], b[i], borrow, c[i]);
    }

    return borrow;
}


static digit_t Montgomery_Rprime[4] = { 0xC81DB8795FF3D621, 0x173EA5AAEA6B387D, 0x3D01B7C72136F61C, 0x0006A5F16AC8F9D3 };  
static digit_t Montgomery_rprime[4] = { 0xE12FE5F079BC3929, 0xD75E78B8D1FCDCF3, 0xBCE409ED76B5DB21, 0xF32702FDAFC1C074 };   

void Montgomery_multiply(digit256_t ma, digit256_t mb, digit256_t mc, digit256_t modulus)
{ // 256-bit Montgomery multiplication, mc = ma*mb*r' mod modulus, where ma,mb,mc in [0, modulus-1], lng{ma,mb,mc,modulus} = nwords
  // ma, mb and mc are assumed to be in Montgomery representation
  // The Montgomery constant r' = -r^(-1) mod 2^(log_2(r)) is the global value "Montgomery_rprime", where r is the modulus   
    unsigned int i;
    digit_t mask, P[2*NWORDS_ORDER], Q[2*NWORDS_ORDER], temp[2*NWORDS_ORDER];
    unsigned char cout = 0, bout = 0;           

    multiply(ma, mb, P);                               // P = ma * mb
    multiply(P, Montgomery_rprime, Q);                 // Q = P * r' mod 2^(log_2(r))
    multiply(Q, modulus, temp);                        // temp = Q * r
    cout = add(P, temp, temp, 2*NWORDS_ORDER);         // (cout, temp) = P + Q * r     

    for (i = 0; i < NWORDS_ORDER; i++) {               // (cout, mc) = (P + Q * r)/2^(log_2(r))
        mc[i] = temp[NWORDS_ORDER + i];
    }

    // Final, constant-time subtraction     
    bout = subtract(mc, modulus, mc, NWORDS_ORDER);    // (cout, mc) = (cout, mc) - r
    mask = (digit_t)(cout - bout);                     // if (cout, mc) >= 0 then mask = 0x00..0, else if (cout, mc) < 0 then mask = 0xFF..F

    for (i = 0; i < NWORDS_ORDER; i++) {               // temp = mask & r
        temp[i] = (modulus[i] & mask);
    }
    add(mc, temp, mc, NWORDS_ORDER);                   //  mc = mc + (mask & r)

    return;
}


void modulo_order(digit256_t a, digit256_t c, PCurveStruct curve)
{ // Reduction modulo the order using Montgomery arithmetic
  // ma = a*Montgomery_Rprime mod r, where a,ma in [0, r-1], a,ma,r < 2^256
  // c = ma*1*Montgomery_Rprime^(-1) mod r, where ma,c in [0, r-1], ma,c,r < 2^256
    digit256_t ma, one = {0};
    
    one[0] = 1;
    Montgomery_multiply(a, Montgomery_Rprime, ma, curve->order);
    Montgomery_multiply(ma, one, c, curve->order);
}


void conversion_to_odd(digit256_t k, digit256_t k_odd, PCurveStruct curve)
{// Convert scalar to odd if even using the prime subgroup order r
    digit_t i, mask;
    unsigned char carry = 0;

    mask = ~(0 - (k[0] & 1));     

    for (i = 0; i < NWORDS_ORDER; i++) {  // If (k is odd) then k_odd = k else k_odd = k + r 
        ADDC(carry, curve->order[i] & mask, k[i], carry, k_odd[i]);
    }
}

#endif


#if defined(USE_FIXED_BASE_SM)

static __inline void fp2div1271(f2elm_t a)
{ // GF(p^2) division by two c = a/2 mod p
     digit_t mask, temp[2];
     unsigned char carry;

     mask = (0 - (1 & a[0][0]));
     ADDC(0,     a[0][0], mask, carry, temp[0]);
     ADDC(carry, a[0][1], (mask >> 1), carry, temp[1]);
     SHIFTR(temp[1], temp[0], 1, a[0][0], RADIX);
     a[0][1] = (temp[1] >> 1);
     
     mask = (0 - (1 & a[1][0]));
     ADDC(0,     a[1][0], mask, carry, temp[0]);
     ADDC(carry, a[1][1], (mask >> 1), carry, temp[1]);
     SHIFTR(temp[1], temp[0], 1, a[1][0], RADIX);
     a[1][1] = (temp[1] >> 1);
}

#endif


#ifdef __cplusplus
}
#endif


#endif
