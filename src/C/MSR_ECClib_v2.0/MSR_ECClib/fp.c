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
* Abstract: generic field operation functions in C
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
******************************************************************************/  

#include "msr_ecclib.h"
#include "msr_ecclib_priv.h"
#if TARGET == TARGET_AMD64
    #include <immintrin.h>
#endif
#if TARGET == TARGET_x86 && OS_TARGET == OS_WIN
    #include <intrin.h>
#endif

// Constants "c" for each prime of the form 2^m - c
#define gamma_189    0x00000000000000BDUL
#define gamma_317    0x000000000000013DUL
#define gamma_569    0x0000000000000239UL



#if TARGET_GENERIC == TRUE

BOOL dig_x_dig(dig a, dig b, dig* c)
{ // Digit multiplication, digit * digit -> 2-digit result    
    register dig al, ah, bl, bh;
    dig albl, albh, ahbl, ahbh, res1, res2, res3, carry;
    dig mask_low = (dig)(-1) >> (sizeof(dig) * 4), mask_high = (dig)(-1) << (sizeof(dig) * 4);
    register dig temp;

    al = a & mask_low;                    // low part
    ah = a >> (sizeof(dig) * 4);          // high part
    bl = b & mask_low;
    bh = b >> (sizeof(dig) * 4);

    albl = al*bl;
    albh = al*bh;
    ahbl = ah*bl;
    ahbh = ah*bh;
    c[0] = albl & mask_low;               // C00

    res1 = albl >> (sizeof(dig) * 4);
    res2 = ahbl & mask_low;
    res3 = albh & mask_low;  
    temp = res1 + res2 + res3;
    carry = temp >> (sizeof(dig) * 4);
    c[0] ^= temp << (sizeof(dig) * 4);    // C01   

    res1 = ahbl >> (sizeof(dig) * 4);
    res2 = albh >> (sizeof(dig) * 4);
    res3 = ahbh & mask_low;
    temp = res1 + res2 + res3 + carry;
    c[1] = temp & mask_low;               // C10 
    carry = temp & mask_high; 
    c[1] ^= (ahbh & mask_high) + carry;   // C11

    return TRUE;
}

#endif


#ifdef ECCURVES_256
//
// 256-bit field operations for curves "numsp256d1" and "numsp256t1" implemented using C only
//

BOOL fpzero256_c(dig256 a)
{ // Zeroing of a 256-bit field element, a = 0 
    dig i; 

    for (i = 0; i < ML_WORDS256; i++)
    {
        ((dig volatile*)a)[i] = 0;
    }

    return TRUE;
}


// Computation in fpadd256, fpadd384_c and fpadd512_c.
// Given a, b in [0, 2^m - gamma>, compute c = a+b mod p as follows:
//
// c = ((a + gamma) + b) mod 2^m - (mask * gamma),
// where: if ((a + gamma) + b) >= 2^m then mask = 0, else mask = 1

BOOL fpadd256_c(dig256 a, dig256 b, dig256 c)
{ // Field addition c = a+b mod p implemented in C

    dig correction, temp[ML_WORDS256];
    
#if TARGET_GENERIC == TRUE
     dig carry = 0, borrow = 0;
     dig res, tres, xa, xb, i;
     dig zfff = (dig)(-1) >> 1;

     temp[0] = a[0] + gamma_189;
     tres = (a[0] & zfff) + gamma_189;
     xa = a[0] >> (ML_WORD - 1);
     carry = xa & (tres >> (ML_WORD - 1));
     for (i = 1; i < ML_WORDS256; i++)
     {
          res = a[i] + carry;
          temp[i] = res;
          carry = carry & ~(res >> (ML_WORD - 1)) & (a[i] >> (ML_WORD - 1));
     }

     for (i = 0; i < ML_WORDS256; i++)
     {
          res = b[i] + carry;
          temp[i] = temp[i] + res;
          xa = temp[i] >> (ML_WORD - 1);
          xb = res >> (ML_WORD - 1);
          tres = (temp[i] & zfff) - (res & zfff);
          carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1))) | (carry & ~(res >> (ML_WORD - 1)) & (b[i] >> (ML_WORD - 1)));
     }

     correction = ~(0 - carry);
     res = gamma_189 & correction;
     tres = (temp[0] & zfff) - res;
     xa = temp[0] >> (ML_WORD - 1);
     borrow = (~xa) & (tres >> (ML_WORD - 1));
     temp[0] = temp[0] - res;
     c[0] = temp[0];
     for (i = 1; i < ML_WORDS256; i++)
     {
          res = temp[i] - borrow;
          borrow = borrow & ~(temp[i] >> (ML_WORD - 1)) & (~(0 - temp[i]) >> (ML_WORD - 1));
          c[i] = res;
     }
    
#elif TARGET == TARGET_AMD64
#if OS_TARGET == OS_WIN
    unsigned char carry = 0, borrow = 0;
#elif OS_TARGET == OS_LINUX
    uint128_t tempReg;
    dig carry = 0, borrow = 0;
#endif
    ADDC(0, a[0], gamma_189, carry, temp[0]);
    ADDC(carry, a[1], 0, carry, temp[1]);
    ADDC(carry, a[2], 0, carry, temp[2]);
    ADDC(carry, a[3], 0, carry, temp[3]);

    ADDC(carry, b[0], temp[0], carry, temp[0]);
    ADDC(carry, b[1], temp[1], carry, temp[1]);
    ADDC(carry, b[2], temp[2], carry, temp[2]);
    ADDC(carry, b[3], temp[3], carry, temp[3]);

    correction = ~(0 - carry);
    SUBC(0, temp[0], gamma_189 & correction, borrow, c[0]);
    SUBC(borrow, temp[1], 0, borrow, c[1]);
    SUBC(borrow, temp[2], 0, borrow, c[2]);
    SUBC(borrow, temp[3], 0, borrow, c[3]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
    unsigned char carry = 0, borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    dig carry = 0, borrow = 0;
    uint64_t tempReg;
#endif    
    ADDC(0, a[0], gamma_189, carry, temp[0]);
    ADDC(carry, a[1], 0, carry, temp[1]);
    ADDC(carry, a[2], 0, carry, temp[2]);
    ADDC(carry, a[3], 0, carry, temp[3]);
    ADDC(carry, a[4], 0, carry, temp[4]);
    ADDC(carry, a[5], 0, carry, temp[5]);
    ADDC(carry, a[6], 0, carry, temp[6]);
    ADDC(carry, a[7], 0, carry, temp[7]);
    
    ADDC(carry, b[0], temp[0], carry, temp[0]);
    ADDC(carry, b[1], temp[1], carry, temp[1]);
    ADDC(carry, b[2], temp[2], carry, temp[2]);
    ADDC(carry, b[3], temp[3], carry, temp[3]);
    ADDC(carry, b[4], temp[4], carry, temp[4]);
    ADDC(carry, b[5], temp[5], carry, temp[5]);
    ADDC(carry, b[6], temp[6], carry, temp[6]);
    ADDC(carry, b[7], temp[7], carry, temp[7]);

    correction = ~(0 - carry);
    SUBC(0, temp[0], gamma_189 & correction, borrow, c[0]);
    SUBC(borrow, temp[1], 0, borrow, c[1]);
    SUBC(borrow, temp[2], 0, borrow, c[2]);
    SUBC(borrow, temp[3], 0, borrow, c[3]);
    SUBC(borrow, temp[4], 0, borrow, c[4]);
    SUBC(borrow, temp[5], 0, borrow, c[5]);
    SUBC(borrow, temp[6], 0, borrow, c[6]);
    SUBC(borrow, temp[7], 0, borrow, c[7]); 
#endif

    return TRUE;
}


// Computation in fpsub256, fpsub384_c and fpsub512_c.
// Given a, b in [0, 2^m - gamma>, compute c = a-b mod p as follows:
//
// c = (a - b) mod 2^w - (borrow * gamma),
// where: if (a - b) < 0 then borrow = 1, else borrow = 0


BOOL fpsub256_c(dig256 a, dig256 b, dig256 c)
{ // Field subtraction c = a-b mod p implemented in C
    dig mask, temp[ML_WORDS256];
    
#if TARGET_GENERIC == TRUE
     unsigned char borrowReg, borrow = 0;
     dig i, tempReg;

     for (i = 0; i < ML_WORDS256; i++)
     {
         SUBC(borrow, a[i], b[i], borrow, temp[i]);
     }

     mask = (dig)(0 - borrow);
     mask = mask & gamma_189;
     SUBC(0, temp[0], mask, borrow, c[0]);
     for (i = 1; i < ML_WORDS256; i++)
     {
         SUBC(borrow, temp[i], 0, borrow, c[i]);
     }
     
#elif TARGET == TARGET_AMD64
#if OS_TARGET == OS_WIN
     unsigned char borrow = 0;
#elif OS_TARGET == OS_LINUX
     uint128_t tempReg;
     dig borrow = 0;
#endif
     SUBC(0,      a[0], b[0], borrow, temp[0]);
     SUBC(borrow, a[1], b[1], borrow, temp[1]);
     SUBC(borrow, a[2], b[2], borrow, temp[2]);
     SUBC(borrow, a[3], b[3], borrow, temp[3]);

     mask = (0 - borrow);
     mask = mask & gamma_189;
     SUBC(0,      temp[0], mask, borrow, c[0]);
     SUBC(borrow, temp[1], 0,    borrow, c[1]);
     SUBC(borrow, temp[2], 0,    borrow, c[2]);
     SUBC(borrow, temp[3], 0,    borrow, c[3]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
    unsigned char borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    dig borrow = 0;
    uint64_t tempReg;
#endif 
     SUBC(0,      a[0], b[0], borrow, temp[0]);
     SUBC(borrow, a[1], b[1], borrow, temp[1]);
     SUBC(borrow, a[2], b[2], borrow, temp[2]);
     SUBC(borrow, a[3], b[3], borrow, temp[3]);
     SUBC(borrow, a[4], b[4], borrow, temp[4]);
     SUBC(borrow, a[5], b[5], borrow, temp[5]);
     SUBC(borrow, a[6], b[6], borrow, temp[6]);
     SUBC(borrow, a[7], b[7], borrow, temp[7]);

     mask = (0 - borrow);
     mask = mask & gamma_189;
     SUBC(0,      temp[0], mask, borrow, c[0]);
     SUBC(borrow, temp[1], 0,    borrow, c[1]);
     SUBC(borrow, temp[2], 0,    borrow, c[2]);
     SUBC(borrow, temp[3], 0,    borrow, c[3]);
     SUBC(borrow, temp[4], 0,    borrow, c[4]);
     SUBC(borrow, temp[5], 0,    borrow, c[5]);
     SUBC(borrow, temp[6], 0,    borrow, c[6]);
     SUBC(borrow, temp[7], 0,    borrow, c[7]);
#endif

    return TRUE;
}


// Computation in fpdiv2_256, fpdiv2_384_c and fpdiv2_512_c.
// Given a in [0, 2^m - gamma>, compute c = a/2 mod p as follows:
//
// c = (a + odd*p) >> 1,
// where: if a is odd then odd = 1, else odd = 0


BOOL fpdiv2_256_c(dig256 a, dig256 c)
{ // Field division by two c = a/2 mod p implemented in C
     dig temp[ML_WORDS256];
     dig mask;

     mask = 0 - (1 & a[0]);

#if TARGET_GENERIC == TRUE
     dig i, res, carry;

     temp[0] = a[0] + (mask & (mask - (gamma_189 - 1)));
     carry = is_digit_lessthan_ct(temp[0], a[0]);
     for(i = 1; i < ML_WORDS256; i++)
     {
          res = a[i] + carry;
          temp[i] = res + mask;
          carry = is_digit_lessthan_ct(temp[i], res) | (carry & is_digit_zero_ct(res));
     }

     for (i = 0; i < ML_WORDS256 - 1; i++)
     {
          c[i] = (temp[i] >> 1) ^ (temp[i + 1] << (ML_WORD - 1));
     }
     
     c[ML_WORDS256 - 1] = (temp[ML_WORDS256 - 1] >> 1) ^ (carry << (ML_WORD - 1));

#elif TARGET == TARGET_AMD64
#if OS_TARGET == OS_WIN
     unsigned char carry = 0;
#elif OS_TARGET == OS_LINUX
     uint128_t tempReg;
     dig carry = 0;
#endif
     ADDC(0,     a[0], mask & (mask - (gamma_189 - 1)), carry, temp[0]);
     ADDC(carry, a[1], mask,                            carry, temp[1]);
     ADDC(carry, a[2], mask,                            carry, temp[2]);
     ADDC(carry, a[3], mask,                            carry, temp[3]);

     SHIFTR(temp[1], temp[0], 1, c[0]);
     SHIFTR(temp[2], temp[1], 1, c[1]);
     SHIFTR(temp[3], temp[2], 1, c[2]);
     SHIFTR(carry,   temp[3], 1, c[3]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
     unsigned char carry = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
     dig carry = 0;
     uint64_t tempReg;
#endif 
     ADDC(0,     a[0], mask & (mask - (gamma_189 - 1)), carry, temp[0]);
     ADDC(carry, a[1], mask,                            carry, temp[1]);
     ADDC(carry, a[2], mask,                            carry, temp[2]);
     ADDC(carry, a[3], mask,                            carry, temp[3]);
     ADDC(carry, a[4], mask,                            carry, temp[4]);
     ADDC(carry, a[5], mask,                            carry, temp[5]);
     ADDC(carry, a[6], mask,                            carry, temp[6]);
     ADDC(carry, a[7], mask,                            carry, temp[7]);

     SHIFTR(temp[1], temp[0], 1, c[0]);
     SHIFTR(temp[2], temp[1], 1, c[1]);
     SHIFTR(temp[3], temp[2], 1, c[2]);
     SHIFTR(temp[4], temp[3], 1, c[3]);
     SHIFTR(temp[5], temp[4], 1, c[4]);
     SHIFTR(temp[6], temp[5], 1, c[5]);
     SHIFTR(temp[7], temp[6], 1, c[6]);
     SHIFTR(carry,   temp[7], 1, c[7]);
#endif

    return TRUE;
}


// Computation in fpneg256, fpneg384_c and fpneg512_c.
// Given a in [0, 2^m - gamma>, compute c = -a mod p as follows:
//
// c = p-a mod 2^w,
// If c <= 0 returns "1" (TRUE), else returns "0" (FALSE) 


BOOL fpneg256_c(dig256 modulus, dig256 a)
{ // Field subtraction a = modulus-a, or field negation, a = -a (mod p) if modulus=p, implemented in C
  // If a <= modulus returns "1" (TRUE), else returns "0" (FALSE)
#if TARGET_GENERIC == TRUE
     dig i, res, carry = 0, borrow = 0;

     for (i = 0; i < ML_WORDS256; i++)
     {
          res = modulus[i] - a[i];
          carry = is_digit_lessthan_ct(modulus[i], a[i]);
          a[i] = res - borrow;
          borrow = carry | (borrow & is_digit_zero_ct(res));
     }

#elif TARGET == TARGET_AMD64
#if OS_TARGET == OS_WIN
    unsigned char borrow = 0;
#elif OS_TARGET == OS_LINUX
    uint128_t tempReg;
    dig borrow = 0;
#endif
     SUBC(borrow, modulus[0], a[0], borrow, a[0]);
     SUBC(borrow, modulus[1], a[1], borrow, a[1]);
     SUBC(borrow, modulus[2], a[2], borrow, a[2]);
     SUBC(borrow, modulus[3], a[3], borrow, a[3]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
    unsigned char borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    dig borrow = 0;
    uint64_t tempReg;
#endif 
     SUBC(borrow, modulus[0], a[0], borrow, a[0]);
     SUBC(borrow, modulus[1], a[1], borrow, a[1]);
     SUBC(borrow, modulus[2], a[2], borrow, a[2]);
     SUBC(borrow, modulus[3], a[3], borrow, a[3]);
     SUBC(borrow, modulus[4], a[4], borrow, a[4]);
     SUBC(borrow, modulus[5], a[5], borrow, a[5]);
     SUBC(borrow, modulus[6], a[6], borrow, a[6]);
     SUBC(borrow, modulus[7], a[7], borrow, a[7]);
#endif

    return (BOOL)(borrow ^ 1);
}


// Computation in fpmul256, fpmul384_c and fpmul512_c.
// Given a, b in [0, 2^m - gamma>, compute c = a*b mod p as follows:
//
// 1. a*b = yH*2^m + yL,
// 2. yL + gamma*yH = zH*2^m + zL
// 3. c = (zL + gamma*(zH+1)) mod 2^m - (mask * gamma),
//
// where: if (zL + gamma*(zH+1)) >= 2^m then mask = 0, else mask = 1

BOOL fpmul256_c(dig256 a, dig256 b, dig256 c)
{ // Field multiplication c=a*b mod p implemented in C
#if TARGET_GENERIC == TRUE
     dig i, j, u, v, carry = 0, borrow = 0;
     dig xa, xb, res, tres, rsi = 0, rdi = 0;
     dig partial[ML_WORDS256 + 1];
     dig temp[2 * ML_WORDS256] = { 0 };
     dig AB[4], UV[2];
     dig zfff = (dig)(-1);

     for (i = 0; i < ML_WORDS256; i++)
     {
          u = 0;
          for (j = 0; j < ML_WORDS256; j++)
          {
               dig_x_dig(a[i], b[j], UV);
               v = UV[0] + u;    // low(UV) + u 
               xa = v >> (ML_WORD - 1);
               xb = u >> (ML_WORD - 1);
               tres = (v & zfff) - (u & zfff);
               carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));
               //carry = is_digit_lessthan_ct(v, *UV);

               //carry = v < *UV;
               u = UV[1] + carry;
               v = temp[i + j] + v;
               xa = v >> (ML_WORD - 1);
               xb = temp[i + j] >> (ML_WORD - 1);
               tres = (v & zfff) - (temp[i + j] & zfff);
               carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));
               //carry = v < temp[i + j];
               u = u + carry;

               temp[i + j] = v;
          }
          temp[ML_WORDS256 + i] = u;
     }

     dig_x_dig(gamma_189, temp[ML_WORDS256 + 0], AB);

     partial[0] = AB[0] + temp[0];
     //rsi = (partial[0] < AB[0]); 
     xa = partial[0] >> (ML_WORD - 1);
     xb = AB[0] >> (ML_WORD - 1);
     tres = (partial[0] & zfff) - (AB[0] & zfff);
     rsi = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));

     for (i = 1; i < ML_WORDS256; i++)
     {
          dig_x_dig(gamma_189, temp[ML_WORDS256 + i], AB + (2 * i % 4));

          partial[i] = AB[3 - (2 * i % 4)] + temp[i];
          xa = partial[i] >> (ML_WORD - 1);
          xb = temp[i] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (temp[i] & zfff);
          carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));
          res = partial[i] + rdi;
          rdi = carry | (rdi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;

          partial[i] += AB[2 * i % 4];
          xa = partial[i] >> (ML_WORD - 1);
          xb = AB[2 * i % 4] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (AB[2 * i % 4] & zfff);
          carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
          res = partial[i] + rsi;

          rsi = carry | (rsi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;
     }

     partial[ML_WORDS256] = AB[3] + rdi + rsi + 1;    // no carry possible here
     partial[ML_WORDS256] *= gamma_189;
     c[0] = partial[0] + partial[ML_WORDS256];
     xa = c[0] >> (ML_WORD - 1);
     xb = partial[0] >> (ML_WORD - 1);
     tres = (c[0] & zfff) - (partial[0] & zfff);
     carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));

     for (i = 1; i < ML_WORDS256; i++)
     {
          c[i] = partial[i] + carry;
          //carry = c[i] < partial[i];
          carry = carry & ~(c[i] >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1));
     }

     rsi = ~(0 - carry);    // rsi = mask
     xa = c[0] >> (ML_WORD - 1);
     xb = (rsi & gamma_189) >> (ML_WORD - 1);
     tres = (c[0] & zfff) - ((rsi & gamma_189) & zfff);
     borrow = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     c[0] -= rsi & gamma_189;

     for (i = 1; i < ML_WORDS256; i++)
     {
          res = c[i] - borrow;
          borrow = (borrow & ((~(0 - c[i])) >> (ML_WORD - 1)) & (~(c[i]) >> (ML_WORD - 1)));
          c[i] = res;
     }

#elif TARGET == TARGET_AMD64
     dig rax, rdx, rdi, r9, r10, r11, r12, r13;
     dig r8_8, r8_16, r8_24;
     unsigned char CF;
#if OS_TARGET == OS_LINUX
     uint128_t tempReg;
#endif

     MUL(a[0], b[0], &rdx, rax);     
     r13 = rax;                      // r13 = C0
     r9 = rdx;

     r11 = 0;
     MUL(a[1], b[0], &rdx, rax);
     ADDC(0, r9, rax, CF, r9);
     r10 = rdx;
     ADDC(CF, r10, 0, CF, r10);

     MUL(a[0], b[1], &rdx, rax);
     ADDC(0, r9, rax, CF, r9);
     ADDC(CF, r10, rdx, CF, r10)
     r11 = CF;
     r8_8 = r9;                      // r8_8 = C1

     r9 = 0;
     MUL(a[2], b[0], &rdx, rax);
     ADDC(0, r10, rax, CF, r10);
     ADDC(CF, r11, rdx, CF, r11);

     MUL(a[1], b[1], &rdx, rax);
     ADDC(0, r10, rax, CF, r10);
     ADDC(CF, r11, rdx, CF, r11);
     r9 = CF;

     MUL(a[0], b[2], &rdx, rax);
     ADDC(0, r10, rax, CF, r10);
     r8_16 = r10;                    // r8_16 = C2
     ADDC(CF, r11, rdx, CF, r11);
     r9 += CF;

     r10 = 0;
     MUL(a[3], b[0], &rdx, rax);
     ADDC(0, r11, rax, CF, r11);
     ADDC(CF, r9, rdx, CF, r9);
     r10 = CF;

     MUL(a[2], b[1], &rdx, rax);
     ADDC(0, r11, rax, CF, r11);
     ADDC(CF, r9, rdx, CF, r9);
     r10 += CF;

     MUL(a[1], b[2], &rdx, rax);
     ADDC(0, r11, rax, CF, r11);
     ADDC(CF, r9, rdx, CF, r9);
     r10 += CF;

     MUL(a[0], b[3], &rdx, rax);
     ADDC(0, r11, rax, CF, r11);
     r8_24 = r11;                    // r8_24 = C3
     ADDC(CF, r9, rdx, CF, r9);
     r10 += CF;

     r11 = 0;
     MUL(a[3], b[1], &rdx, rax);
     ADDC(0, r9, rax, CF, r9);
     ADDC(CF, r10, rdx, CF, r10);
     r11 = CF;

     MUL(a[2], b[2], &rdx, rax);
     ADDC(0, r9, rax, CF, r9);
     ADDC(CF, r10, rdx, CF, r10);
     r11 += CF;

     MUL(a[1], b[3], &rdx, rax);
     ADDC(0, r9, rax, CF, r9);
     rdi = r9;                       // rdi = C4
     ADDC(CF, r10, rdx, CF, r10);
     r11 += CF;

     r9 = 0;
     MUL(a[3], b[2], &rdx, rax);
     ADDC(0, r10, rax, CF, r10);
     ADDC(CF, r11, rdx, CF, r11);
     r9 = CF;

     MUL(a[2], b[3], &rdx, rax);
     ADDC(0, r10, rax, CF, r10);    // r10 = C5
     ADDC(CF, r11, rdx, CF, r11);
     r9 += CF;

     MUL(a[3], b[3], &rdx, rax);
     ADDC(0, r11, rax, CF, r11);    // r11 = C6
     ADDC(CF, r9, rdx, CF, r9);     // r9 = C7

     // Reduction

     MUL(gamma_189, rdi, &rdx, rax);
     ADDC(0, rax, r13, CF, r13);    // r13 = partial0
     ADDC(CF, rdx, 0, CF, rdi);     

     r12 = 0;                        
     MUL(gamma_189, r10, &rdx, rax);
     ADDC(0, rax, rdi, CF, rax);
     r12 = CF;
     ADDC(0, r8_8, rax, CF, r10);   // r10 = partial1 
     ADDC(CF, rdx, r12, CF, r12);

     rdi = 0;                        
     MUL(gamma_189, r11, &rdx, rax);
     ADDC(0, rax, r12, CF, rax);
     rdi = CF;
     r11 = r8_16;
     ADDC(0, rax, r11, CF, r11);    // r11 = partial2
     ADDC(CF, rdi, rdx, CF, rdi);

     r12 = 0;                        
     MUL(gamma_189, r9, &rdx, rax);
     ADDC(0, rax, rdi, CF, rax);
     ADDC(CF, 1, r12, CF, r12);     
     r9 = r8_24;                     
     ADDC(0, rax, r9, CF, r9);      // r9 = partial3
     ADDC(CF, rdx, r12, CF, rdx);   // rdx = partial4 + 1 

     r12 = 0;                        
     MUL(gamma_189, rdx, &rdx, rax);
     ADDC(0, r13, rax, CF, r13);
     ADDC(CF, r10, 0, CF, r10);     
     ADDC(CF, r11, 0, CF, r11);
     ADDC(CF, r9, 0, CF, r9);

     rax = ~(0 - CF);                // 0 if carry is 1, 0xFF..F if carry is 0
     SUBC(0, r13, gamma_189 & rax, CF, c[0]);
     SUBC(CF, r10, 0, CF, c[1]);
     SUBC(CF, r11, 0, CF, c[2]);
     SUBC(CF, r9, 0, CF, c[3]);
               
#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
     unsigned char rsi = 0, rdi = 0, carry = 0, borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
     dig rsi = 0, rdi = 0, carry = 0, borrow = 0;
#endif
     uint64_t tempReg;
     dig i, j, u, v;
     dig t[2 * ML_WORDS256] = { 0 };
     dig partial[ML_WORDS256 + 1];
     dig AB[4], UV[2];

     for (i = 0; i < ML_WORDS256; i++)
     {
          u = 0;
          for (j = 0; j < ML_WORDS256; j++)
          {
               MUL(a[i], b[j], UV + 1, UV[0]);
               ADDC(0, UV[0], u, carry, v);
               u = UV[1] + carry;
               ADDC(0, t[i + j], v, carry, v);
               u = u + carry;
               t[i + j] = v;
          }
          t[ML_WORDS256 + i] = u;
     }

     MUL(gamma_189, t[ML_WORDS256 + 0], AB + 1, AB[0]);
     ADDC(0, AB[0], t[0], rsi, partial[0]);
     for (i = 1; i < ML_WORDS256; i++)
     {
          MUL(gamma_189, t[ML_WORDS256 + i], AB + (2 * i % 4) + 1, AB[2 * i % 4]);
          ADDC(rdi, AB[3 - (2 * i % 4)], t[i], rdi, partial[i]);
          ADDC(rsi, AB[2 * i % 4], partial[i], rsi, partial[i]);
     }

     partial[ML_WORDS256] = AB[3] + rdi + rsi + 1;
     partial[ML_WORDS256] *= gamma_189;
     ADDC(0, partial[0], partial[ML_WORDS256], carry, c[0]);
     for (i = 1; i < ML_WORDS256; i++)
     {
          ADDC(carry, partial[i], 0, carry, c[i]);
     }

     rsi = ~(0 - carry);
     SUBC(0, c[0], rsi & gamma_189, borrow, c[0]);
     for (i = 1; i < ML_WORDS256; i++)
     {
          SUBC(borrow, c[i], 0, borrow, c[i]);
     }
#endif

    return TRUE;
}


// Computation in fpsqr256, fpsqr384_c and fpsqr512_c.
// Given a in [0, 2^m - gamma>, compute c = a^2 mod p as follows:
//
// 1. a^2 = yH*2^m + yL,
// 2. yL + gamma*yH = zH*2^m + zL
// 3. c = (zL + gamma*(zH+1)) mod 2^m - (mask * gamma),
//
// where: if (zL + gamma*(zH+1)) >= 2^m then mask = 0, else mask = 1

BOOL fpsqr256_c(dig256 a, dig256 c)
{ // Field squaring c=a^2 mod p implemented in C
#if TARGET_GENERIC == TRUE
     dig rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
     sdig i, j, k, bound;
     dig r0 = 0, r1 = 0, r2 = 0;
     dig temp[2 * ML_WORDS256] = { 0 };
     dig partial[ML_WORDS256 + 1];
     dig AB[4], UV[2] = {0};
     dig zfff = (dig)(-1);
     dig xa, xb, res, tres;

     for (k = 0; k < ML_WORDS256; k++)
     {
          i = k;
          j = 0;
          bound = k / 2;
          while (j < bound)
          {
               dig_x_dig(a[i], a[j], UV);

               // mul by 2
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
               //---

               r0 = r0 + UV[0];
               //eps0 = (r0 < UV[0]); 
               eps0 = is_digit_lessthan_ct(r0, UV[0]);

               r1 = r1 + UV[1];
               //eps1 = (r1 < UV[1]); 
               eps1 = is_digit_lessthan_ct(r1, UV[1]);

               r1 = r1 + eps0;
               //eps1 = eps1 | (!r1 & eps0);
               eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);
               //#endif

               r2 = r2 + eps1;

               i--;
               j++;
          }

          dig_x_dig(a[i], a[j], UV);

          if ((k % 2) == 1)
          {
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
          }

          r0 = r0 + UV[0];
          //eps0 = (r0 < UV[0]); 
          eps0 = is_digit_lessthan_ct(r0, UV[0]);

          r1 = r1 + UV[1];
          //eps1 = (r1 < UV[1]); 
          eps1 = is_digit_lessthan_ct(r1, UV[1]);

          r1 = r1 + eps0;
          //eps1 = eps1 | (!r1 & eps0);
          eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);
          //#endif

          r2 = r2 + eps1;

          temp[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;
     }

     for (k = ML_WORDS256; k <= 2 * ML_WORDS256 - 2; k++)
     {
          i = (ML_WORDS256 - 1);
          j = k - i;
          bound = k / 2;
          while (j < bound)
          {
               dig_x_dig(a[i], a[j], UV);

               // mul by 2
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
               //---

               r0 = r0 + UV[0];
               //eps0 = (r0 < UV[0]); 
               eps0 = is_digit_lessthan_ct(r0, UV[0]);

               r1 = r1 + UV[1];
               //eps1 = (r1 < UV[1]); 
               eps1 = is_digit_lessthan_ct(r1, UV[1]);

               r1 = r1 + eps0;
               //eps1 = eps1 | (!r1 & eps0);
               eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);
               //#endif

               r2 = r2 + eps1;

               i--;
               j++;
          }

          dig_x_dig(a[i], a[j], UV);

          if ((k % 2) == 1)
          {
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
          }

          r0 = r0 + UV[0];
          //eps0 = (r0 < UV[0]); 
          eps0 = is_digit_lessthan_ct(r0, UV[0]);

          r1 = r1 + UV[1];
          //eps1 = (r1 < UV[1]); 
          eps1 = is_digit_lessthan_ct(r1, UV[1]);

          r1 = r1 + eps0;
          //eps1 = eps1 | (!r1 & eps0);
          eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);

          r2 = r2 + eps1;

          temp[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;
     }

     temp[2 * ML_WORDS256 - 1] = r0;
     dig_x_dig(gamma_189, temp[ML_WORDS256 + 0], AB);
     partial[0] = AB[0] + temp[0];
     xa = partial[0] >> (ML_WORD - 1);
     xb = AB[0] >> (ML_WORD - 1);
     tres = (partial[0] & zfff) - (AB[0] & zfff);
     rsi = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));

     for (i = 1; i < ML_WORDS256; i++)
     {
          dig_x_dig(gamma_189, temp[ML_WORDS256 + i], AB + (2 * i % 4));

          partial[i] = AB[3 - (2 * i % 4)] + temp[i];
          //carry = (partial[i] < temp[i]); 
          //---
          xa = partial[i] >> (ML_WORD - 1);
          xb = temp[i] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (temp[i] & zfff);
          carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
          //---
          res = partial[i] + rdi;
          //partial[i] += rdi;
          //(partial[i] < rdi);
          //---
          rdi = carry | (rdi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;
          //---


          partial[i] += AB[2 * i % 4];
          //carry = (partial[i] < AB[2 * i % 4]);
          //---
          xa = partial[i] >> (ML_WORD - 1);
          xb = AB[2 * i % 4] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (AB[2 * i % 4] & zfff);
          carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
          //---
          res = partial[i] + rsi;
          //partial[i] += rsi;
          //---

          //---
          //rsi = carry | (partial[i] < rsi); 
          rsi = carry | (rsi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;
          //---
     }
     partial[ML_WORDS256] = AB[3] + rdi + rsi + 1; //no carry possible here

     partial[ML_WORDS256] *= gamma_189;

     c[0] = partial[0] + partial[ML_WORDS256];
     //carry = (*c < partial[0]); 
     //---
     xa = c[0] >> (ML_WORD - 1);
     xb = partial[0] >> (ML_WORD - 1);
     tres = (*c & zfff) - (partial[0] & zfff);
     carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     //---

     for (i = 1; i < ML_WORDS256; i++)
     {
          c[i] = partial[i] + carry;
          //carry = c[i] < partial[i];
          //---
          carry = carry & ~(c[i] >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1));
          //---
     }

     rsi = ~(0 - carry);

     xa = c[0] >> (ML_WORD - 1);
     xb = (rsi & gamma_189) >> (ML_WORD - 1);
     tres = (c[0] & zfff) - ((rsi & gamma_189) & zfff);
     borrow = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     //---
     c[0] -= rsi & gamma_189;

     for (i = 1; i < ML_WORDS256; i++)
     {
          res = c[i] - borrow;
          borrow = (borrow & ((~(0 - c[i]) >> (ML_WORD - 1)) & (~(c[i]) >> (ML_WORD - 1))));
          c[i] = res;
     }

#elif TARGET == TARGET_AMD64
    dig rcx, rdx, rax, rdi, r8, r9, r10, r11, r12;
    dig rbx[4];
    unsigned char CF;
#if OS_TARGET == OS_LINUX
     uint128_t tempReg;
#endif

    r10 = 0;
    MUL(a[0], a[1], &rdx, rax);
    ADDC(0, rax, rax, CF, rax);
    r8 = rax;
    ADDC(CF, rdx, rdx, CF, rdx);
    r9 = rdx;
    r10 = CF;

    MUL(a[0], a[0], &rdx, rax);
    rbx[0] = rax;
    ADDC(0, r8, rdx, CF, r8);
    rbx[1] = r8;
    ADDC(CF, r9, 0, CF, r9);

    rdi = 0;
    MUL(a[0], a[2], &rdx, rax);
    ADDC(0, rax, rax, CF, rax);
    r8 = rax;
    ADDC(CF, rdx, rdx, CF, rdx);
    r11 = rdx;
    rdi = CF;

    MUL(a[1], a[1], &rdx, rax);
    ADDC(0, r8, rax, CF, r8);
    ADDC(CF, r11, rdx, CF, r11);
    ADDC(CF, rdi, 0, CF, rdi);

    MUL(a[0], a[3], &rdx, rax);
    ADDC(0, r8, r9, CF, r8);
    rbx[2] = r8;
    ADDC(CF, r11, r10, CF, r11);
    ADDC(CF, rdi, 0, CF, rdi);
    r8 = rax;
    r10 = rdx;

    r9 = 0;
    MUL(a[1], a[2], &rdx, rax);
    ADDC(0, r8, rax, CF, r8);
    ADDC(CF, r10, rdx, CF, r10);
    r9 = CF;
    ADDC(0, r8, r8, CF, r8);
    ADDC(CF, r10, r10, CF, r10);
    ADDC(CF, r9, r9, CF, r9);

    MUL(a[1], a[3], &rdx, rax);
    ADDC(0, r8, r11, CF, r8);
    rbx[3] = r8;
    ADDC(CF, r10, rdi, CF, r10);
    ADDC(CF, r9, 0, CF, r9);
    rdi = 0;
    ADDC(0, rax, rax, CF, rax);
    r8 = rax;
    ADDC(CF, rdx, rdx, CF, rdx);
    r11 = rdx;
    rdi = CF;

    MUL(a[2], a[2], &rdx, rax);
    ADDC(0, r8, r10, CF, r8);
    ADDC(CF, r9, r11, CF, r9);
    ADDC(CF, rdi, 0, CF, rdi);
    ADDC(0, r8, rax, CF, r8);
    ADDC(CF, r9, rdx, CF, r9);
    ADDC(CF, rdi, 0, CF, rdi);

    r11 = 0;
    MUL(a[2], a[3], &rdx, rax);
    ADDC(0, rax, rax, CF, rax);
    ADDC(CF, rdx, rdx, CF, rdx);
    r11 = CF;
    ADDC(0, r9, rax, CF, r9);
    ADDC(CF, rdi, rdx, CF, rdi);
    ADDC(CF, r11, 0, CF, r11);

    MUL(a[3], a[3], &rdx, rax);
    ADDC(0, rdi, rax, CF, rdi);
    ADDC(CF, r11, rdx, CF, r11);

    // Reduction

    MUL(gamma_189, r8, &rdx, rax);
    r8 = rbx[0];
    ADDC(0, r8, rax, CF, r8);
    ADDC(CF, rdx, 0, CF, rdx);
    r10 = rdx;

    r12 = 0;
    MUL(gamma_189, r9, &rdx, rax);
    ADDC(0, rax, r10, CF, rax);
    r12 = CF;
    r9 = rbx[1];
    ADDC(0, r9, rax, CF, r9);
    ADDC(CF, r12, rdx, CF, r12);

    rcx = 0;
    MUL(gamma_189, rdi, &rdx, rax);
    ADDC(0, rax, r12, CF, rax);
    rcx = CF;
    rdi = rbx[2];
    ADDC(0, rdi, rax, CF, rdi);
    ADDC(CF, rcx, rdx, CF, rcx);

    r10 = 0;
    MUL(gamma_189, r11, &rdx, rax);
    ADDC(0, rax, rcx, CF, rax);
    ADDC(CF, r10, 1, CF, r10);
    r11 = rbx[3];
    ADDC(0, r11, rax, CF, r11);
    ADDC(CF, r10, rdx, CF, r10);

    r12 = 0;
    MUL(gamma_189, r10, &rdx, rax);
    ADDC(0, r8, rax, CF, r8);
    ADDC(CF, r9, 0, CF, r9);
    ADDC(CF, rdi, 0, CF, rdi);
    ADDC(CF, r11, 0, CF, r11);

    rax = (~(0 - CF)) & gamma_189;
    SUBC(0, r8, rax, CF, c[0]);
    SUBC(CF, r9, 0, CF, c[1]);
    SUBC(CF, rdi, 0, CF, c[2]);
    SUBC(CF, r11, 0, CF, c[3]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
    unsigned char rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    dig rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
#endif
    uint64_t tempReg;
    sdig i, j, k, bound;
    dig r0 = 0, r1 = 0, r2 = 0;
    dig temp[2 * ML_WORDS256] = { 0 };
    dig partial[ML_WORDS256 + 1];
    dig AB[4], UV[2] = {0};

    for (k = 0; k < ML_WORDS256; k++)
    {
         i = k;
         j = 0;
         bound = k / 2;
         while (j < bound) {
              MUL(a[i], a[j], &(UV[1]), UV[0]);
              r2 = r2 + (UV[1] >> (ML_WORD - 1));
              SHIFTL(UV[1], UV[0], 1, UV[1]);
              UV[0] <<= 1;
              ADDC(0, r0, UV[0], eps0, r0);
              ADDC(eps0, r1, UV[1], eps1, r1);
              r2 = r2 + eps1;
              i--;
              j++;
         }
         if ((k % 2) == 0) {
              MUL(a[i], a[j], &(UV[1]), UV[0]);
              ADDC(0, r0, UV[0], eps0, r0);
              ADDC(eps0, r1, UV[1], eps1, r1);
              r2 = r2 + eps1;
         } else {
              MUL(a[i], a[j], &(UV[1]), UV[0]);
              r2 = r2 + (UV[1] >> (ML_WORD - 1));
              SHIFTL(UV[1], UV[0], 1, UV[1]);
              UV[0] <<= 1;
              ADDC(0, r0, UV[0], eps0, r0);
              ADDC(eps0, r1, UV[1], eps1, r1);
              r2 = r2 + eps1;
         }
         temp[k] = r0;
         r0 = r1;
         r1 = r2;
         r2 = 0;
    }
    for (k = ML_WORDS256; k <= 2 * ML_WORDS256 - 2; k++)
    {
         i = (ML_WORDS256 - 1);
         j = k - i;
         bound = k / 2;
         while (j < bound) {
              MUL(a[i], a[j], &(UV[1]), UV[0]);
              r2 = r2 + (UV[1] >> (ML_WORD - 1));
              SHIFTL(UV[1], UV[0], 1, UV[1]);
              UV[0] <<= 1;
              ADDC(0, r0, UV[0], eps0, r0);
              ADDC(eps0, r1, UV[1], eps1, r1);
              r2 = r2 + eps1;
              i--;
              j++;
         }
         if ((k % 2) == 0) {
              MUL(a[i], a[j], &(UV[1]), UV[0]);
              ADDC(0, r0, UV[0], eps0, r0);
              ADDC(eps0, r1, UV[1], eps1, r1);
              r2 = r2 + eps1;
         } else {
              MUL(a[i], a[j], &(UV[1]), UV[0]);
              r2 = r2 + (UV[1] >> (ML_WORD - 1));
              SHIFTL(UV[1], UV[0], 1, UV[1]);
              UV[0] <<= 1;
              ADDC(0, r0, UV[0], eps0, r0);
              ADDC(eps0, r1, UV[1], eps1, r1);
              r2 = r2 + eps1;
         }
         temp[k] = r0;
         r0 = r1;
         r1 = r2;
         r2 = 0;

    }
    temp[2 * ML_WORDS256 - 1] = r0;

    MUL(gamma_189, temp[ML_WORDS256 + 0], &(AB[1]), AB[0]);
    ADDC(0, AB[0], temp[0], rsi, partial[0]);
    for (i = 1; i < ML_WORDS256; i++)
    {
         MUL(gamma_189, temp[ML_WORDS256 + i], AB + (2 * i % 4) + 1, AB[2 * i % 4]);
         ADDC(rdi, AB[(3 - (2 * i % 4))], temp[i], rdi, partial[i]); 
         ADDC(rsi, partial[i], AB[((2 * i) % 4)], rsi, partial[i]);
    }
    partial[ML_WORDS256] = AB[3] + rdi + rsi + 1; 
    partial[ML_WORDS256] *= gamma_189;

    ADDC(0, partial[0], partial[ML_WORDS256], carry, c[0]);
    for (i = 1; i < ML_WORDS256; i++)
    {
         ADDC(carry, partial[i], 0, carry, c[i]);
    }

    rsi = ~(0 - carry);
    SUBC(0, c[0], rsi & gamma_189, borrow, c[0]);
    for (i = 1; i < ML_WORDS256; i++)
    {
         SUBC(borrow, c[i], 0, borrow, c[i]);
    }
#endif
    
    return TRUE;
}

#endif


#ifdef ECCURVES_384
//
// 384-bit field operations for curves "numsp384d1" and "numsp384t1" implemented using C only
//

BOOL fpzero384_c(dig384 a)
{ // Zeroing of a 384-bit field element, a = 0 
     dig i;

     for (i = 0; i < ML_WORDS384; i++)
     {
        ((dig volatile*)a)[i] = 0;
     }
     return TRUE;
}


BOOL fpadd384_c(dig384 a, dig384 b, dig384 c)
{ // Field addition c = a+b mod p implemented in C
     dig correction;
     dig temp[ML_WORDS384];
     
#if TARGET_GENERIC == TRUE
     dig carry = 0, borrow = 0;
     dig res, tres, xa, xb, i;
     dig zfff = (dig)(-1) >> 1;

     temp[0] = a[0] + gamma_317;
     tres = (a[0] & zfff) + gamma_317;
     xa = a[0] >> (ML_WORD - 1);
     carry = xa & (tres >> (ML_WORD - 1));
     for (i = 1; i < ML_WORDS384; i++)
     {
          res = a[i] + carry;
          temp[i] = res;
          carry = carry & ~(res >> (ML_WORD - 1)) & (a[i] >> (ML_WORD - 1));
     }

     for (i = 0; i < ML_WORDS384; i++)
     {
          res = b[i] + carry;
          temp[i] = temp[i] + res;
          xa = temp[i] >> (ML_WORD - 1);
          xb = res >> (ML_WORD - 1);
          tres = (temp[i] & zfff) - (res & zfff);
          carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1))) | (carry & ~(res >> (ML_WORD - 1)) & (b[i] >> (ML_WORD - 1)));
     }

     correction = ~(0 - carry);
     res = gamma_317 & correction;
     tres = (temp[0] & zfff) - res;
     xa = temp[0] >> (ML_WORD - 1);
     borrow = (~xa) & (tres >> (ML_WORD - 1));
     temp[0] = temp[0] - res;
     c[0] = temp[0];
     for (i = 1; i < ML_WORDS384; i++)
     {
          res = temp[i] - borrow;
          borrow = borrow & ~(temp[i] >> (ML_WORD - 1)) & (~(0 - temp[i]) >> (ML_WORD - 1));
          c[i] = res;
     }
     
#elif TARGET == TARGET_AMD64
#if OS_TARGET == OS_WIN
     unsigned char carry = 0, borrow = 0;
#elif OS_TARGET == OS_LINUX
     uint128_t tempReg;
     dig carry = 0, borrow = 0;
#endif
     ADDC(0, a[0], gamma_317, carry, temp[0]);
     ADDC(carry, a[1], 0, carry, temp[1]);
     ADDC(carry, a[2], 0, carry, temp[2]);
     ADDC(carry, a[3], 0, carry, temp[3]);
     ADDC(carry, a[4], 0, carry, temp[4]);
     ADDC(carry, a[5], 0, carry, temp[5]);

     ADDC(carry, b[0], temp[0], carry, temp[0]);
     ADDC(carry, b[1], temp[1], carry, temp[1]);
     ADDC(carry, b[2], temp[2], carry, temp[2]);
     ADDC(carry, b[3], temp[3], carry, temp[3]);
     ADDC(carry, b[4], temp[4], carry, temp[4]);
     ADDC(carry, b[5], temp[5], carry, temp[5]);

     correction = ~(0 - carry);
     SUBC(0, temp[0], gamma_317 & correction, borrow, c[0]);
     SUBC(borrow, temp[1], 0, borrow, c[1]);
     SUBC(borrow, temp[2], 0, borrow, c[2]);
     SUBC(borrow, temp[3], 0, borrow, c[3]);
     SUBC(borrow, temp[4], 0, borrow, c[4]);
     SUBC(borrow, temp[5], 0, borrow, c[5]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
     unsigned char carry = 0, borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
     dig carry = 0, borrow = 0;
     uint64_t tempReg;
#endif 
     ADDC(0, a[0], gamma_317, carry, temp[0]);
     ADDC(carry, a[1], 0, carry, temp[1]);
     ADDC(carry, a[2], 0, carry, temp[2]);
     ADDC(carry, a[3], 0, carry, temp[3]);
     ADDC(carry, a[4], 0, carry, temp[4]);
     ADDC(carry, a[5], 0, carry, temp[5]);
     ADDC(carry, a[6], 0, carry, temp[6]);
     ADDC(carry, a[7], 0, carry, temp[7]);
     ADDC(carry, a[8], 0, carry, temp[8]);
     ADDC(carry, a[9], 0, carry, temp[9]);
     ADDC(carry, a[10], 0, carry, temp[10]);
     ADDC(carry, a[11], 0, carry, temp[11]);

     ADDC(carry, b[0], temp[0], carry, temp[0]);
     ADDC(carry, b[1], temp[1], carry, temp[1]);
     ADDC(carry, b[2], temp[2], carry, temp[2]);
     ADDC(carry, b[3], temp[3], carry, temp[3]);
     ADDC(carry, b[4], temp[4], carry, temp[4]);
     ADDC(carry, b[5], temp[5], carry, temp[5]);
     ADDC(carry, b[6], temp[6], carry, temp[6]);
     ADDC(carry, b[7], temp[7], carry, temp[7]);
     ADDC(carry, b[8], temp[8], carry, temp[8]);
     ADDC(carry, b[9], temp[9], carry, temp[9]);
     ADDC(carry, b[10], temp[10], carry, temp[10]);
     ADDC(carry, b[11], temp[11], carry, temp[11]);

     correction = ~(0 - carry);
     SUBC(0, temp[0], gamma_317 & correction, borrow, c[0]);
     SUBC(borrow, temp[1], 0, borrow, c[1]);
     SUBC(borrow, temp[2], 0, borrow, c[2]);
     SUBC(borrow, temp[3], 0, borrow, c[3]);
     SUBC(borrow, temp[4], 0, borrow, c[4]);
     SUBC(borrow, temp[5], 0, borrow, c[5]);
     SUBC(borrow, temp[6], 0, borrow, c[6]);
     SUBC(borrow, temp[7], 0, borrow, c[7]);
     SUBC(borrow, temp[8], 0, borrow, c[8]);
     SUBC(borrow, temp[9], 0, borrow, c[9]);
     SUBC(borrow, temp[10], 0, borrow, c[10]);
     SUBC(borrow, temp[11], 0, borrow, c[11]);
#endif

     return TRUE;
}


BOOL fpsub384_c(dig384 a, dig384 b, dig384 c)
{ // Field subtraction c = a-b mod p implemented in C
     dig mask;
     
#if TARGET_GENERIC == TRUE
     dig carry = 0, borrow = 0;
     dig i, res;

     //a-b mod 2^W
     for (i = 0; i < ML_WORDS384; i++)
     {
          res = a[i] - b[i];
          carry = is_digit_lessthan_ct(a[i], b[i]);
          c[i] = res - borrow;
          borrow = carry | (borrow & is_digit_zero_ct(res));
     }

     mask = 0 - borrow;
     borrow = 0;
     res = c[0] - (gamma_317 & mask);
     borrow = is_digit_lessthan_ct(c[0], gamma_317 & mask);
     c[0] = res;
     for (i = 1; i < ML_WORDS384; i++)
     {
          res = c[i] - borrow;
          borrow = (borrow & is_digit_zero_ct(c[i]));
          c[i] = res;
     }
     
#elif TARGET == TARGET_AMD64
     dig temp[ML_WORDS384]; 
#if OS_TARGET == OS_WIN
     unsigned char borrow = 0;
#elif OS_TARGET == OS_LINUX
     uint128_t tempReg;
     dig borrow = 0;
#endif
     SUBC(0, a[0], b[0], borrow, temp[0]);
     SUBC(borrow, a[1], b[1], borrow, temp[1]);
     SUBC(borrow, a[2], b[2], borrow, temp[2]);
     SUBC(borrow, a[3], b[3], borrow, temp[3]);
     SUBC(borrow, a[4], b[4], borrow, temp[4]);
     SUBC(borrow, a[5], b[5], borrow, temp[5]);

     mask = (0 - borrow);
     mask = mask & gamma_317;
     SUBC(0, temp[0], mask, borrow, c[0]);
     SUBC(borrow, temp[1], 0, borrow, c[1]);
     SUBC(borrow, temp[2], 0, borrow, c[2]);
     SUBC(borrow, temp[3], 0, borrow, c[3]);
     SUBC(borrow, temp[4], 0, borrow, c[4]);
     SUBC(borrow, temp[5], 0, borrow, c[5]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM)
     dig temp[ML_WORDS384];  
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
     unsigned char borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
     dig borrow = 0;
     uint64_t tempReg;
#endif 
     SUBC(0, a[0], b[0], borrow, temp[0]);
     SUBC(borrow, a[1], b[1], borrow, temp[1]);
     SUBC(borrow, a[2], b[2], borrow, temp[2]);
     SUBC(borrow, a[3], b[3], borrow, temp[3]);
     SUBC(borrow, a[4], b[4], borrow, temp[4]);
     SUBC(borrow, a[5], b[5], borrow, temp[5]);
     SUBC(borrow, a[6], b[6], borrow, temp[6]);
     SUBC(borrow, a[7], b[7], borrow, temp[7]);
     SUBC(borrow, a[8], b[8], borrow, temp[8]);
     SUBC(borrow, a[9], b[9], borrow, temp[9]);
     SUBC(borrow, a[10], b[10], borrow, temp[10]);
     SUBC(borrow, a[11], b[11], borrow, temp[11]);

     mask = (0 - borrow);
     mask = mask & gamma_317;
     SUBC(0, temp[0], mask, borrow, c[0]);
     SUBC(borrow, temp[1], 0, borrow, c[1]);
     SUBC(borrow, temp[2], 0, borrow, c[2]);
     SUBC(borrow, temp[3], 0, borrow, c[3]);
     SUBC(borrow, temp[4], 0, borrow, c[4]);
     SUBC(borrow, temp[5], 0, borrow, c[5]);
     SUBC(borrow, temp[6], 0, borrow, c[6]);
     SUBC(borrow, temp[7], 0, borrow, c[7]);
     SUBC(borrow, temp[8], 0, borrow, c[8]);
     SUBC(borrow, temp[9], 0, borrow, c[9]);
     SUBC(borrow, temp[10], 0, borrow, c[10]);
     SUBC(borrow, temp[11], 0, borrow, c[11]);
#endif

     return TRUE;
}


BOOL fpdiv2_384_c(dig384 a, dig384 c)
{ // Field division by two c = a/2 mod p implemented in C
     dig t[ML_WORDS384];
     dig mask, lsb;

     lsb = 1 & a[0];
     mask = 0 - lsb;

#if TARGET_GENERIC == TRUE
     dig i, res, carry;

     t[0] = a[0] + (mask & (mask - (gamma_317 - 1)));
     carry = is_digit_lessthan_ct(t[0], a[0]);

     for (i = 1; i < ML_WORDS384; i++)
     {
          res = a[i] + carry;
          t[i] = res + mask;
          carry = is_digit_lessthan_ct(t[i], res) | (carry & is_digit_zero_ct(res));
     }

     for (i = 0; i < ML_WORDS384 - 1; i++)
     {
          c[i] = (t[i] >> 1) ^ (t[i + 1] << (ML_WORD - 1));
     }

     c[ML_WORDS384 - 1] = (t[ML_WORDS384 - 1] >> 1) ^ (carry << (ML_WORD - 1));

#elif TARGET == TARGET_AMD64
#if OS_TARGET == OS_WIN
     unsigned char carry = 0;
#elif OS_TARGET == OS_LINUX
     uint128_t tempReg;
     dig carry = 0;
#endif
     ADDC(0, a[0], mask & (mask - (gamma_317 - 1)), carry, t[0]);
     ADDC(carry, a[1], mask, carry, t[1]);
     ADDC(carry, a[2], mask, carry, t[2]);
     ADDC(carry, a[3], mask, carry, t[3]);
     ADDC(carry, a[4], mask, carry, t[4]);
     ADDC(carry, a[5], mask, carry, t[5]);

     SHIFTR(t[1], t[0], 1, c[0]);
     SHIFTR(t[2], t[1], 1, c[1]);
     SHIFTR(t[3], t[2], 1, c[2]);
     SHIFTR(t[4], t[3], 1, c[3]);
     SHIFTR(t[5], t[4], 1, c[4]);
     SHIFTR(carry, t[5], 1, c[5]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
     unsigned char carry = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
     dig carry = 0;
     uint64_t tempReg;
#endif 
     ADDC(0, a[0], mask & (mask - (gamma_317 - 1)), carry, t[0]);
     ADDC(carry, a[1], mask, carry, t[1]);
     ADDC(carry, a[2], mask, carry, t[2]);
     ADDC(carry, a[3], mask, carry, t[3]);
     ADDC(carry, a[4], mask, carry, t[4]);
     ADDC(carry, a[5], mask, carry, t[5]);
     ADDC(carry, a[6], mask, carry, t[6]);
     ADDC(carry, a[7], mask, carry, t[7]);
     ADDC(carry, a[8], mask, carry, t[8]);
     ADDC(carry, a[9], mask, carry, t[9]);
     ADDC(carry, a[10], mask, carry, t[10]);
     ADDC(carry, a[11], mask, carry, t[11]);

     SHIFTR(t[1], t[0], 1, c[0]);
     SHIFTR(t[2], t[1], 1, c[1]);
     SHIFTR(t[3], t[2], 1, c[2]);
     SHIFTR(t[4], t[3], 1, c[3]);
     SHIFTR(t[5], t[4], 1, c[4]);
     SHIFTR(t[6], t[5], 1, c[5]);
     SHIFTR(t[7], t[6], 1, c[6]);
     SHIFTR(t[8], t[7], 1, c[7]);
     SHIFTR(t[9], t[8], 1, c[8]);
     SHIFTR(t[10], t[9], 1, c[9]);
     SHIFTR(t[11], t[10], 1, c[10]);
     SHIFTR(carry, t[11], 1, c[11]);
#endif

     return TRUE;
}


BOOL fpneg384_c(dig384 modulus, dig384 a)
{ // Field subtraction a = modulus-a, or field negation, a = -a (mod p) if modulus=p, implemented in C  
  // If a <= modulus returns "1" (TRUE), else returns "0" (FALSE)  
#if TARGET_GENERIC == TRUE
     dig i, res, carry = 0, borrow = 0;

     for (i = 0; i < ML_WORDS384; i++)
     {
          res = modulus[i] - a[i];
          carry = is_digit_lessthan_ct(modulus[i], a[i]);
          a[i] = res - borrow;
          borrow = carry | (borrow & is_digit_zero_ct(res));
     }

#elif TARGET == TARGET_AMD64
#if OS_TARGET == OS_WIN
    unsigned char borrow = 0;
#elif OS_TARGET == OS_LINUX
    uint128_t tempReg;
    dig borrow = 0;
#endif
     SUBC(borrow, modulus[0], a[0], borrow, a[0]);
     SUBC(borrow, modulus[1], a[1], borrow, a[1]);
     SUBC(borrow, modulus[2], a[2], borrow, a[2]);
     SUBC(borrow, modulus[3], a[3], borrow, a[3]);
     SUBC(borrow, modulus[4], a[4], borrow, a[4]);
     SUBC(borrow, modulus[5], a[5], borrow, a[5]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
    unsigned char borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    dig borrow = 0;
    uint64_t tempReg;
#endif 
     SUBC(borrow, modulus[0], a[0], borrow, a[0]);
     SUBC(borrow, modulus[1], a[1], borrow, a[1]);
     SUBC(borrow, modulus[2], a[2], borrow, a[2]);
     SUBC(borrow, modulus[3], a[3], borrow, a[3]);
     SUBC(borrow, modulus[4], a[4], borrow, a[4]);
     SUBC(borrow, modulus[5], a[5], borrow, a[5]);
     SUBC(borrow, modulus[6], a[6], borrow, a[6]);
     SUBC(borrow, modulus[7], a[7], borrow, a[7]);
     SUBC(borrow, modulus[8], a[8], borrow, a[8]);
     SUBC(borrow, modulus[9], a[9], borrow, a[9]);
     SUBC(borrow, modulus[10], a[10], borrow, a[10]);
     SUBC(borrow, modulus[11], a[11], borrow, a[11]);
#endif

     return (~borrow & 0x01);
}


BOOL fpmul384_c(dig384 a, dig384 b, dig384 c)
{ // Field multiplication c=a*b mod p implemented in C
#if TARGET_GENERIC == TRUE
     dig carry = 0;
     dig borrow = 0;
     dig u, v;
     dig rsi = 0, rdi = 0;
     dig partial[ML_WORDS384 + 1];
     dig AB[4];
     dig temp[2 * ML_WORDS384] = { 0 };
     dig UV[2];
     dig zfff = (dig)(-1);
     dig xa, xb, res, tres;
     dig i, j;

     for (i = 0; i < ML_WORDS384; i++)
     {
          u = 0;
          for (j = 0; j < ML_WORDS384; j++)
          {
               dig_x_dig(a[i], b[j], UV);
               v = UV[0] + u; // low(UV) + u 
               //----
               xa = v >> (ML_WORD - 1);
               xb = u >> (ML_WORD - 1);
               tres = (v & zfff) - (u & zfff);
               carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
               //carry = is_digit_lessthan_ct(v, *UV);

               //carry = v < *UV;
               //----
               u = UV[1] + carry;

               v = temp[i + j] + v;
               //----
               xa = v >> (ML_WORD - 1);
               xb = temp[i + j] >> (ML_WORD - 1);
               tres = (v & zfff) - (temp[i + j] & zfff);
               carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));
               //----
               //carry = v < temp[i + j];
               u = u + carry;

               temp[i + j] = v;
          }
          temp[ML_WORDS384 + i] = u;
     }

     dig_x_dig(gamma_317, temp[ML_WORDS384 + 0], AB);

     partial[0] = AB[0] + temp[0];
     //rsi = (partial[0] < AB[0]); 
     //---
     xa = partial[0] >> (ML_WORD - 1);
     xb = AB[0] >> (ML_WORD - 1);
     tres = (partial[0] & zfff) - (AB[0] & zfff);
     rsi = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     //---

     for (i = 1; i < ML_WORDS384; i++)
     {
          dig_x_dig(gamma_317, temp[ML_WORDS384 + i], AB + (2 * i % 4));

          partial[i] = AB[3 - (2 * i % 4)] + temp[i];
          xa = partial[i] >> (ML_WORD - 1);
          xb = temp[i] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (temp[i] & zfff);
          carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));
          res = partial[i] + rdi;
          rdi = carry | (rdi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;

          partial[i] += AB[2 * i % 4];
          xa = partial[i] >> (ML_WORD - 1);
          xb = AB[2 * i % 4] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (AB[2 * i % 4] & zfff);
          carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
          res = partial[i] + rsi;

          rsi = carry | (rsi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;
     }

     partial[ML_WORDS384] = AB[3] + rdi + rsi + 1; //no carry possible here

     partial[ML_WORDS384] *= gamma_317;

     c[0] = partial[0] + partial[ML_WORDS384];

     xa = c[0] >> (ML_WORD - 1);
     xb = partial[0] >> (ML_WORD - 1);
     tres = (c[0] & zfff) - (partial[0] & zfff);
     carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));

     for (i = 1; i < ML_WORDS384; i++)
     {
          c[i] = partial[i] + carry;
          //carry = c[i] < partial[i];
          //---
          carry = carry & ~(c[i] >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1));
          //---
     }

     u = ~(0 - (dig)carry); // rsi = mask

     xa = c[0] >> (ML_WORD - 1);
     xb = (u & gamma_317) >> (ML_WORD - 1);
     tres = (c[0] & zfff) - ((u & gamma_317) & zfff);
     borrow = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     //---
     c[0] -= u & gamma_317;

     for (i = 1; i < ML_WORDS384; i++)
     {
          res = c[i] - borrow;
          borrow = (borrow & ((~(0 - c[i])) >> (ML_WORD - 1)) & (~(c[i]) >> (ML_WORD - 1)));
          c[i] = res;
     }

#elif (TARGET == TARGET_AMD64 || TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_AMD64)
    unsigned char rsi = 0, rdi = 0, carry = 0, borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_AMD64)
    dig rsi = 0, rdi = 0, carry = 0, borrow = 0;
    uint128_t tempReg;
#elif (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
    unsigned char rsi = 0, rdi = 0, carry = 0, borrow = 0;
    uint64_t tempReg;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    dig rsi = 0, rdi = 0, carry = 0, borrow = 0;
    uint64_t tempReg;
#endif
    dig i, j, u, v;
    dig t[2 * ML_WORDS384] = { 0 };
    dig partial[ML_WORDS384 + 1];
    dig AB[4], UV[2];

     for (i = 0; i < ML_WORDS384; i++)
     {
          u = 0;
          for (j = 0; j < ML_WORDS384; j++)
          {
               MUL(a[i], b[j], UV + 1, UV[0]);
               ADDC(0, UV[0], u, carry, v);
               u = UV[1] + carry;
               ADDC(0, t[i + j], v, carry, v);
               u = u + carry;
               t[i + j] = v;
          }
          t[ML_WORDS384 + i] = u;
     }

     MUL(gamma_317, t[ML_WORDS384 + 0], AB + 1, AB[0]);
     ADDC(0, AB[0], t[0], rsi, partial[0]);

     for (i = 1; i < ML_WORDS384; i++)
     {
          MUL(gamma_317, t[ML_WORDS384 + i], AB + (2 * i % 4) + 1, AB[2 * i % 4]);
          ADDC(rdi, AB[3 - (2 * i % 4)], t[i], rdi, partial[i]);
          ADDC(rsi, AB[2 * i % 4], partial[i], rsi, partial[i]);
     }

     partial[ML_WORDS384] = AB[3] + rdi + rsi + 1;
     partial[ML_WORDS384] *= gamma_317;
     ADDC(0, partial[0], partial[ML_WORDS384], carry, c[0]);
     for (i = 1; i < ML_WORDS384; i++)
     {
          ADDC(carry, partial[i], 0, carry, c[i]);
     }

     u = ~(0 - (dig)carry);
     SUBC(0, c[0], u & gamma_317, borrow, c[0]);
     for (i = 1; i < ML_WORDS384; i++)
     {
          SUBC(borrow, c[i], 0, borrow, c[i]);
     }
#endif

     return TRUE;
}


BOOL fpsqr384_c(dig384 a, dig384 c)
{ // Field squaring c=a^2 mod p implemented in C
#if TARGET_GENERIC == TRUE
     dig rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
     sdig i, j, k, bound;
     dig r0 = 0, r1 = 0, r2 = 0;
     dig temp[2 * ML_WORDS384] = { 0 };
     dig partial[ML_WORDS384 + 1];
     dig AB[4], UV[2] = { 0 };
     dig zfff = (dig)(-1);
     dig xa, xb, res, tres;

     for (k = 0; k < ML_WORDS384; k++)
     {
          i = k;
          j = 0;
          bound = k / 2;
          while (j < bound)
          {
               dig_x_dig(a[i], a[j], UV);

               // mul by 2
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
               //---

               r0 = r0 + UV[0];
               //eps0 = (r0 < UV[0]); 
               eps0 = is_digit_lessthan_ct(r0, UV[0]);

               r1 = r1 + UV[1];
               //eps1 = (r1 < UV[1]); 
               eps1 = is_digit_lessthan_ct(r1, UV[1]);

               r1 = r1 + eps0;
               //eps1 = eps1 | (!r1 & eps0);
               eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);
               //#endif

               r2 = r2 + eps1;

               i--;
               j++;
          }

          dig_x_dig(a[i], a[j], UV);

          if ((k % 2) == 1)
          {
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
          }

          r0 = r0 + UV[0];
          //eps0 = (r0 < UV[0]); 
          eps0 = is_digit_lessthan_ct(r0, UV[0]);

          r1 = r1 + UV[1];
          //eps1 = (r1 < UV[1]); 
          eps1 = is_digit_lessthan_ct(r1, UV[1]);

          r1 = r1 + eps0;
          //eps1 = eps1 | (!r1 & eps0);
          eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);
          //#endif

          r2 = r2 + eps1;

          temp[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;
     }

     for (k = ML_WORDS384; k <= 2 * ML_WORDS384 - 2; k++)
     {
          i = (ML_WORDS384 - 1);
          j = k - i;
          bound = k / 2;
          while (j < bound)
          {
               dig_x_dig(a[i], a[j], UV);

               // mul by 2
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
               //---

               r0 = r0 + UV[0];
               //eps0 = (r0 < UV[0]); 
               eps0 = is_digit_lessthan_ct(r0, UV[0]);

               r1 = r1 + UV[1];
               //eps1 = (r1 < UV[1]); 
               eps1 = is_digit_lessthan_ct(r1, UV[1]);

               r1 = r1 + eps0;
               //eps1 = eps1 | (!r1 & eps0);
               eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);
               //#endif

               r2 = r2 + eps1;

               i--;
               j++;
          }

          dig_x_dig(a[i], a[j], UV);

          if ((k % 2) == 1)
          {
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
          }

          r0 = r0 + UV[0];
          //eps0 = (r0 < UV[0]); 
          eps0 = is_digit_lessthan_ct(r0, UV[0]);

          r1 = r1 + UV[1];
          //eps1 = (r1 < UV[1]); 
          eps1 = is_digit_lessthan_ct(r1, UV[1]);

          r1 = r1 + eps0;
          //eps1 = eps1 | (!r1 & eps0);
          eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);

          r2 = r2 + eps1;

          temp[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;
     }

     temp[2 * ML_WORDS384 - 1] = r0;

     dig_x_dig(gamma_317, temp[ML_WORDS384 + 0], AB);

     partial[0] = AB[0] + temp[0];

     xa = partial[0] >> (ML_WORD - 1);
     xb = AB[0] >> (ML_WORD - 1);
     tres = (partial[0] & zfff) - (AB[0] & zfff);
     rsi = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));

     for (i = 1; i < ML_WORDS384; i++)
     {
          dig_x_dig(gamma_317, temp[ML_WORDS384 + i], AB + (2 * i % 4));

          partial[i] = AB[3 - (2 * i % 4)] + temp[i];
          //carry = (partial[i] < temp[i]); 
          //---
          xa = partial[i] >> (ML_WORD - 1);
          xb = temp[i] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (temp[i] & zfff);
          carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));
          //---
          res = partial[i] + rdi;
          //partial[i] += rdi;
          //(partial[i] < rdi);
          //---
          rdi = carry | (rdi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;
          //---
          partial[i] += AB[2 * i % 4];
          //carry = (partial[i] < AB[2 * i % 4]);
          //---
          xa = partial[i] >> (ML_WORD - 1);
          xb = AB[2 * i % 4] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (AB[2 * i % 4] & zfff);
          carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));
          //---
          res = partial[i] + rsi;
          //partial[i] += rsi;
          //---

          //---
          //rsi = carry | (partial[i] < rsi); 
          rsi = carry | (rsi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;
          //---
     }
     partial[ML_WORDS384] = AB[3] + rdi + rsi + 1; //no carry possible here
     partial[ML_WORDS384] *= gamma_317;
     c[0] = partial[0] + partial[ML_WORDS384];
     //carry = (*c < partial[0]); 
     //---
     xa = c[0] >> (ML_WORD - 1);
     xb = partial[0] >> (ML_WORD - 1);
     tres = (*c & zfff) - (partial[0] & zfff);
     carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     //---

     for (i = 1; i < ML_WORDS384; i++)
     {
          c[i] = partial[i] + carry;
          //carry = c[i] < partial[i];
          //---
          carry = carry & ~(c[i] >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1));
          //---
     }

     r0 = ~(0 - (dig)carry);

     xa = c[0] >> (ML_WORD - 1);
     xb = (r0 & gamma_317) >> (ML_WORD - 1);
     tres = (c[0] & zfff) - ((r0 & gamma_317) & zfff);
     borrow = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     //---
     c[0] -= r0 & gamma_317;

     for (i = 1; i < ML_WORDS384; i++)
     {
          res = c[i] - borrow;
          borrow = (borrow & ((~(0 - c[i]) >> (ML_WORD - 1)) & (~(c[i]) >> (ML_WORD - 1))));
          c[i] = res;
     }

#elif (TARGET == TARGET_AMD64 || TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_AMD64)
    unsigned char rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_AMD64)
    dig rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
    uint128_t tempReg;
#elif (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
    unsigned char rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
    uint64_t tempReg;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    dig rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
    uint64_t tempReg;
#endif
    sdig i, j, k, bound;
    dig r0 = 0, r1 = 0, r2 = 0;
    dig temp[2 * ML_WORDS384] = { 0 };
    dig partial[ML_WORDS384 + 1];
    dig AB[4], UV[2] = { 0 };
    
     for (k = 0; k < ML_WORDS384; k++)
     {
          i = k;
          j = 0;
          bound = k / 2;
          while (j < bound)
          {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               r2 = r2 + (UV[1] >> (ML_WORD - 1));
               SHIFTL(UV[1], UV[0], 1, UV[1]);
               UV[0] <<= 1;
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
               i--;
               j++;
          }
          if ((k % 2) == 0) {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
          } else {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               r2 = r2 + (UV[1] >> (ML_WORD - 1));
               SHIFTL(UV[1], UV[0], 1, UV[1]);
               UV[0] <<= 1;
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
          }
          temp[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;

     }
     for (k = ML_WORDS384; k <= 2 * ML_WORDS384 - 2; k++)
     {
          i = (ML_WORDS384 - 1);
          j = k - i;
          bound = k / 2;
          while (j < bound)
          {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               r2 = r2 + (UV[1] >> (ML_WORD - 1));
               SHIFTL(UV[1], UV[0], 1, UV[1]);
               UV[0] <<= 1;
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
               i--;
               j++;
          }
          if ((k % 2) == 0) {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
          } else {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               r2 = r2 + (UV[1] >> (ML_WORD - 1));
               SHIFTL(UV[1], UV[0], 1, UV[1]);
               UV[0] <<= 1;
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
          }
          temp[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;
     }
     temp[2 * ML_WORDS384 - 1] = r0;

     MUL(gamma_317, temp[ML_WORDS384 + 0], &(AB[1]), AB[0]);
     ADDC(0, AB[0], temp[0], rsi, partial[0]);
     for (i = 1; i < ML_WORDS384; i++)
     {
          MUL(gamma_317, temp[ML_WORDS384 + i], AB + (2 * i % 4) + 1, AB[2 * i % 4]);
          ADDC(rdi, AB[(3 - (2 * i % 4))], temp[i], rdi, partial[i]); 
          ADDC(rsi, partial[i], AB[((2 * i) % 4)], rsi, partial[i]);
     }
     partial[ML_WORDS384] = AB[3] + rdi + rsi + 1; 
     partial[ML_WORDS384] *= gamma_317;

     ADDC(0, partial[0], partial[ML_WORDS384], carry, c[0]);
     for (i = 1; i < ML_WORDS384; i++)
     {
          ADDC(carry, partial[i], 0, carry, c[i]);
     }

     r0 = ~(0 - (dig)carry);
     SUBC(0, c[0], r0 & gamma_317, borrow, c[0]);
     for (i = 1; i < ML_WORDS384; i++)
     {
          SUBC(borrow, c[i], 0, borrow, c[i]);
     }
#endif

     return TRUE;
}

#endif


#ifdef ECCURVES_512
//
// 512-bit field operations for curves "numsp512d1" and "numsp512t1" implemented using C only
//

BOOL fpzero512_c(dig512 a)
{ // Zeroing of a 512-bit field element, a = 0 
     dig i;

     for (i = 0; i < ML_WORDS512; i++)
     {
        ((dig volatile*)a)[i] = 0;
     }
     return TRUE;
}


BOOL fpadd512_c(dig512 a, dig512 b, dig512 c)
{ // Field addition c = a+b mod p implemented in C
     dig correction;
     dig temp[ML_WORDS512];
     
#if TARGET_GENERIC == TRUE
     dig carry = 0, borrow = 0;
     dig res, tres, xa, xb, i;
     dig zfff = (dig)(-1) >> 1;

     temp[0] = a[0] + gamma_569;
     tres = (a[0] & zfff) + gamma_569;
     xa = a[0] >> (ML_WORD - 1);
     carry = xa & (tres >> (ML_WORD - 1));
     for (i = 1; i < ML_WORDS512; i++)
     {
          res = a[i] + carry;
          temp[i] = res;
          carry = carry & ~(res >> (ML_WORD - 1)) & (a[i] >> (ML_WORD - 1));
     }

     for (i = 0; i < ML_WORDS512; i++)
     {
          res = b[i] + carry;
          temp[i] = temp[i] + res;
          xa = temp[i] >> (ML_WORD - 1);
          xb = res >> (ML_WORD - 1);
          tres = (temp[i] & zfff) - (res & zfff);
          carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1))) | (carry & ~(res >> (ML_WORD - 1)) & (b[i] >> (ML_WORD - 1)));
     }

     correction = ~(0 - carry);
     res = gamma_569 & correction;
     tres = (temp[0] & zfff) - res;
     xa = temp[0] >> (ML_WORD - 1);
     borrow = (~xa) & (tres >> (ML_WORD - 1));
     temp[0] = temp[0] - res;
     c[0] = temp[0];
     for (i = 1; i < ML_WORDS512; i++)
     {
          res = temp[i] - borrow;
          borrow = borrow & ~(temp[i] >> (ML_WORD - 1)) & (~(0 - temp[i]) >> (ML_WORD - 1));
          c[i] = res;
     }
     
#elif TARGET == TARGET_AMD64
#if OS_TARGET == OS_WIN
     unsigned char carry = 0, borrow = 0;
#elif OS_TARGET == OS_LINUX
     uint128_t tempReg;
     dig carry = 0, borrow = 0;
#endif
     ADDC(0, a[0], gamma_569, carry, temp[0]);
     ADDC(carry, a[1], 0, carry, temp[1]);
     ADDC(carry, a[2], 0, carry, temp[2]);
     ADDC(carry, a[3], 0, carry, temp[3]);
     ADDC(carry, a[4], 0, carry, temp[4]);
     ADDC(carry, a[5], 0, carry, temp[5]);
     ADDC(carry, a[6], 0, carry, temp[6]);
     ADDC(carry, a[7], 0, carry, temp[7]);

     ADDC(carry, b[0], temp[0], carry, temp[0]);
     ADDC(carry, b[1], temp[1], carry, temp[1]);
     ADDC(carry, b[2], temp[2], carry, temp[2]);
     ADDC(carry, b[3], temp[3], carry, temp[3]);
     ADDC(carry, b[4], temp[4], carry, temp[4]);
     ADDC(carry, b[5], temp[5], carry, temp[5]);
     ADDC(carry, b[6], temp[6], carry, temp[6]);
     ADDC(carry, b[7], temp[7], carry, temp[7]);

     correction = ~(0 - carry);
     SUBC(0, temp[0], gamma_569 & correction, borrow, c[0]);
     SUBC(borrow, temp[1], 0, borrow, c[1]);
     SUBC(borrow, temp[2], 0, borrow, c[2]);
     SUBC(borrow, temp[3], 0, borrow, c[3]);
     SUBC(borrow, temp[4], 0, borrow, c[4]);
     SUBC(borrow, temp[5], 0, borrow, c[5]);
     SUBC(borrow, temp[6], 0, borrow, c[6]);
     SUBC(borrow, temp[7], 0, borrow, c[7]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
     unsigned char carry = 0, borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
     dig carry = 0, borrow = 0;
     uint64_t tempReg;
#endif 
     ADDC(0, a[0], gamma_569, carry, temp[0]);
     ADDC(carry, a[1], 0, carry, temp[1]);
     ADDC(carry, a[2], 0, carry, temp[2]);
     ADDC(carry, a[3], 0, carry, temp[3]);
     ADDC(carry, a[4], 0, carry, temp[4]);
     ADDC(carry, a[5], 0, carry, temp[5]);
     ADDC(carry, a[6], 0, carry, temp[6]);
     ADDC(carry, a[7], 0, carry, temp[7]);
     ADDC(carry, a[8], 0, carry, temp[8]);
     ADDC(carry, a[9], 0, carry, temp[9]);
     ADDC(carry, a[10], 0, carry, temp[10]);
     ADDC(carry, a[11], 0, carry, temp[11]);
     ADDC(carry, a[12], 0, carry, temp[12]);
     ADDC(carry, a[13], 0, carry, temp[13]);
     ADDC(carry, a[14], 0, carry, temp[14]);
     ADDC(carry, a[15], 0, carry, temp[15]);

     ADDC(carry, b[0], temp[0], carry, temp[0]);
     ADDC(carry, b[1], temp[1], carry, temp[1]);
     ADDC(carry, b[2], temp[2], carry, temp[2]);
     ADDC(carry, b[3], temp[3], carry, temp[3]);
     ADDC(carry, b[4], temp[4], carry, temp[4]);
     ADDC(carry, b[5], temp[5], carry, temp[5]);
     ADDC(carry, b[6], temp[6], carry, temp[6]);
     ADDC(carry, b[7], temp[7], carry, temp[7]);
     ADDC(carry, b[8], temp[8], carry, temp[8]);
     ADDC(carry, b[9], temp[9], carry, temp[9]);
     ADDC(carry, b[10], temp[10], carry, temp[10]);
     ADDC(carry, b[11], temp[11], carry, temp[11]);
     ADDC(carry, b[12], temp[12], carry, temp[12]);
     ADDC(carry, b[13], temp[13], carry, temp[13]);
     ADDC(carry, b[14], temp[14], carry, temp[14]);
     ADDC(carry, b[15], temp[15], carry, temp[15]);

     correction = ~(0 - carry);
     SUBC(0, temp[0], gamma_569 & correction, borrow, c[0]);
     SUBC(borrow, temp[1], 0, borrow, c[1]);
     SUBC(borrow, temp[2], 0, borrow, c[2]);
     SUBC(borrow, temp[3], 0, borrow, c[3]);
     SUBC(borrow, temp[4], 0, borrow, c[4]);
     SUBC(borrow, temp[5], 0, borrow, c[5]);
     SUBC(borrow, temp[6], 0, borrow, c[6]);
     SUBC(borrow, temp[7], 0, borrow, c[7]);
     SUBC(borrow, temp[8], 0, borrow, c[8]);
     SUBC(borrow, temp[9], 0, borrow, c[9]);
     SUBC(borrow, temp[10], 0, borrow, c[10]);
     SUBC(borrow, temp[11], 0, borrow, c[11]);
     SUBC(borrow, temp[12], 0, borrow, c[12]);
     SUBC(borrow, temp[13], 0, borrow, c[13]);
     SUBC(borrow, temp[14], 0, borrow, c[14]);
     SUBC(borrow, temp[15], 0, borrow, c[15]);
#endif

     return TRUE;
}


BOOL fpsub512_c(dig512 a, dig512 b, dig512 c)
{ // Field subtraction c = a-b mod p implemented in C
     dig mask;
     
#if TARGET_GENERIC == TRUE
     dig carry = 0, borrow = 0;
     dig i, res;

     //a-b mod 2^W
     for (i = 0; i < ML_WORDS512; i++)
     {
          res = a[i] - b[i];
          carry = is_digit_lessthan_ct(a[i], b[i]);
          c[i] = res - borrow;
          borrow = carry | (borrow & is_digit_zero_ct(res));
     }

     mask = 0 - borrow;
     borrow = 0;

     res = c[0] - (gamma_569 & mask);
     borrow = is_digit_lessthan_ct(c[0], gamma_569 & mask);
     c[0] = res;
     for (i = 1; i < ML_WORDS512; i++)
     {
          res = c[i] - borrow;
          borrow = (borrow & is_digit_zero_ct(c[i]));
          c[i] = res;
     }
     
#elif TARGET == TARGET_AMD64
     dig temp[ML_WORDS512]; 
#if OS_TARGET == OS_WIN
     unsigned char borrow = 0;
#elif OS_TARGET == OS_LINUX
     uint128_t tempReg;
     dig borrow = 0;
#endif
     SUBC(0, a[0], b[0], borrow, temp[0]);
     SUBC(borrow, a[1], b[1], borrow, temp[1]);
     SUBC(borrow, a[2], b[2], borrow, temp[2]);
     SUBC(borrow, a[3], b[3], borrow, temp[3]);
     SUBC(borrow, a[4], b[4], borrow, temp[4]);
     SUBC(borrow, a[5], b[5], borrow, temp[5]);
     SUBC(borrow, a[6], b[6], borrow, temp[6]);
     SUBC(borrow, a[7], b[7], borrow, temp[7]);

     mask = (0 - borrow);
     mask = mask & gamma_569;

     SUBC(0, temp[0], mask, borrow, c[0]);
     SUBC(borrow, temp[1], 0, borrow, c[1]);
     SUBC(borrow, temp[2], 0, borrow, c[2]);
     SUBC(borrow, temp[3], 0, borrow, c[3]);
     SUBC(borrow, temp[4], 0, borrow, c[4]);
     SUBC(borrow, temp[5], 0, borrow, c[5]);
     SUBC(borrow, temp[6], 0, borrow, c[6]);
     SUBC(borrow, temp[7], 0, borrow, c[7]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
     dig temp[ML_WORDS512]; 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
     unsigned char borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
     dig borrow = 0;
     uint64_t tempReg;
#endif 
     SUBC(0, a[0], b[0], borrow, temp[0]);
     SUBC(borrow, a[1], b[1], borrow, temp[1]);
     SUBC(borrow, a[2], b[2], borrow, temp[2]);
     SUBC(borrow, a[3], b[3], borrow, temp[3]);
     SUBC(borrow, a[4], b[4], borrow, temp[4]);
     SUBC(borrow, a[5], b[5], borrow, temp[5]);
     SUBC(borrow, a[6], b[6], borrow, temp[6]);
     SUBC(borrow, a[7], b[7], borrow, temp[7]);
     SUBC(borrow, a[8], b[8], borrow, temp[8]);
     SUBC(borrow, a[9], b[9], borrow, temp[9]);
     SUBC(borrow, a[10], b[10], borrow, temp[10]);
     SUBC(borrow, a[11], b[11], borrow, temp[11]);
     SUBC(borrow, a[12], b[12], borrow, temp[12]);
     SUBC(borrow, a[13], b[13], borrow, temp[13]);
     SUBC(borrow, a[14], b[14], borrow, temp[14]);
     SUBC(borrow, a[15], b[15], borrow, temp[15]);

     mask = (0 - borrow);
     mask = mask & gamma_569;

     SUBC(0, temp[0], mask, borrow, c[0]);
     SUBC(borrow, temp[1], 0, borrow, c[1]);
     SUBC(borrow, temp[2], 0, borrow, c[2]);
     SUBC(borrow, temp[3], 0, borrow, c[3]);
     SUBC(borrow, temp[4], 0, borrow, c[4]);
     SUBC(borrow, temp[5], 0, borrow, c[5]);
     SUBC(borrow, temp[6], 0, borrow, c[6]);
     SUBC(borrow, temp[7], 0, borrow, c[7]);
     SUBC(borrow, temp[8], 0, borrow, c[8]);
     SUBC(borrow, temp[9], 0, borrow, c[9]);
     SUBC(borrow, temp[10], 0, borrow, c[10]);
     SUBC(borrow, temp[11], 0, borrow, c[11]);
     SUBC(borrow, temp[12], 0, borrow, c[12]);
     SUBC(borrow, temp[13], 0, borrow, c[13]);
     SUBC(borrow, temp[14], 0, borrow, c[14]);
     SUBC(borrow, temp[15], 0, borrow, c[15]);
#endif

     return TRUE;
}


BOOL fpdiv2_512_c(dig512 a, dig512 c)
{ // Field division by two c = a/2 mod p implemented in C
     dig temp[ML_WORDS512];
     dig mask, lsb;

     lsb = 1 & a[0];
     mask = 0 - lsb;
     
#if TARGET_GENERIC == TRUE
     dig i, res, carry;

     temp[0] = a[0] + (mask & (mask - (gamma_569 - 1)));
     carry = is_digit_lessthan_ct(temp[0], a[0]);

     for (i = 1; i < ML_WORDS512; i++)
     {
          res = a[i] + carry;
          temp[i] = res + mask;
          carry = is_digit_lessthan_ct(temp[i], res) | (carry & is_digit_zero_ct(res));
     }

     for (i = 0; i < ML_WORDS512 - 1; i++)
     {
          c[i] = (temp[i] >> 1) ^ (temp[i + 1] << (ML_WORD - 1));
     }

     c[ML_WORDS512 - 1] = (temp[ML_WORDS512 - 1] >> 1) ^ (carry << (ML_WORD - 1));

#elif TARGET == TARGET_AMD64
#if OS_TARGET == OS_WIN
     unsigned char carry = 0;
#elif OS_TARGET == OS_LINUX
     uint128_t tempReg;
     dig carry = 0;
#endif
     ADDC(0, a[0], mask & (mask - (gamma_569 - 1)), carry, temp[0]);
     ADDC(carry, a[1], mask, carry, temp[1]);
     ADDC(carry, a[2], mask, carry, temp[2]);
     ADDC(carry, a[3], mask, carry, temp[3]);
     ADDC(carry, a[4], mask, carry, temp[4]);
     ADDC(carry, a[5], mask, carry, temp[5]);
     ADDC(carry, a[6], mask, carry, temp[6]);
     ADDC(carry, a[7], mask, carry, temp[7]);

     SHIFTR(temp[1], temp[0], 1, c[0]);
     SHIFTR(temp[2], temp[1], 1, c[1]);
     SHIFTR(temp[3], temp[2], 1, c[2]);
     SHIFTR(temp[4], temp[3], 1, c[3]);
     SHIFTR(temp[5], temp[4], 1, c[4]);
     SHIFTR(temp[6], temp[5], 1, c[5]);
     SHIFTR(temp[7], temp[6], 1, c[6]);
     SHIFTR((dig)carry, temp[7], 1, c[7]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
     unsigned char carry = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
     dig carry = 0;
     uint64_t tempReg;
#endif 
     ADDC(0, a[0], mask & (mask - (gamma_569 - 1)), carry, temp[0]);
     ADDC(carry, a[1], mask, carry, temp[1]);
     ADDC(carry, a[2], mask, carry, temp[2]);
     ADDC(carry, a[3], mask, carry, temp[3]);
     ADDC(carry, a[4], mask, carry, temp[4]);
     ADDC(carry, a[5], mask, carry, temp[5]);
     ADDC(carry, a[6], mask, carry, temp[6]);
     ADDC(carry, a[7], mask, carry, temp[7]);
     ADDC(carry, a[8], mask, carry, temp[8]);
     ADDC(carry, a[9], mask, carry, temp[9]);
     ADDC(carry, a[10], mask, carry, temp[10]);
     ADDC(carry, a[11], mask, carry, temp[11]);
     ADDC(carry, a[12], mask, carry, temp[12]);
     ADDC(carry, a[13], mask, carry, temp[13]);
     ADDC(carry, a[14], mask, carry, temp[14]);
     ADDC(carry, a[15], mask, carry, temp[15]);

     SHIFTR(temp[1], temp[0], 1, c[0]);
     SHIFTR(temp[2], temp[1], 1, c[1]);
     SHIFTR(temp[3], temp[2], 1, c[2]);
     SHIFTR(temp[4], temp[3], 1, c[3]);
     SHIFTR(temp[5], temp[4], 1, c[4]);
     SHIFTR(temp[6], temp[5], 1, c[5]);
     SHIFTR(temp[7], temp[6], 1, c[6]);
     SHIFTR(temp[8], temp[7], 1, c[7]);
     SHIFTR(temp[9], temp[8], 1, c[8]);
     SHIFTR(temp[10], temp[9], 1, c[9]);
     SHIFTR(temp[11], temp[10], 1, c[10]);
     SHIFTR(temp[12], temp[11], 1, c[11]);
     SHIFTR(temp[13], temp[12], 1, c[12]);
     SHIFTR(temp[14], temp[13], 1, c[13]);
     SHIFTR(temp[15], temp[14], 1, c[14]);
     SHIFTR(carry, temp[15], 1, c[15]);
#endif
     return TRUE;
}


BOOL fpneg512_c(dig512 modulus, dig512 a)
{ // Field subtraction a = modulus-a, or field negation, a = -a (mod p) if modulus=p, implemented in C
  // If a <= modulus returns "1" (TRUE), else returns "0" (FALSE)
#if TARGET_GENERIC == TRUE
     dig i, res, carry = 0, borrow = 0;

     for (i = 0; i < ML_WORDS512; i++)
     {
          res = modulus[i] - a[i];
          carry = is_digit_lessthan_ct(modulus[i], a[i]);
          a[i] = res - borrow;
          borrow = carry | (borrow & is_digit_zero_ct(res));
     }

#elif TARGET == TARGET_AMD64
#if OS_TARGET == OS_WIN
    unsigned char borrow = 0;
#elif OS_TARGET == OS_LINUX
    uint128_t tempReg;
    dig borrow = 0;
#endif
     SUBC(borrow, modulus[0], a[0], borrow, a[0]);
     SUBC(borrow, modulus[1], a[1], borrow, a[1]);
     SUBC(borrow, modulus[2], a[2], borrow, a[2]);
     SUBC(borrow, modulus[3], a[3], borrow, a[3]);
     SUBC(borrow, modulus[4], a[4], borrow, a[4]);
     SUBC(borrow, modulus[5], a[5], borrow, a[5]);
     SUBC(borrow, modulus[6], a[6], borrow, a[6]);
     SUBC(borrow, modulus[7], a[7], borrow, a[7]);

#elif (TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
    unsigned char borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    dig borrow = 0;
    uint64_t tempReg;
#endif 
     SUBC(borrow, modulus[0], a[0], borrow, a[0]);
     SUBC(borrow, modulus[1], a[1], borrow, a[1]);
     SUBC(borrow, modulus[2], a[2], borrow, a[2]);
     SUBC(borrow, modulus[3], a[3], borrow, a[3]);
     SUBC(borrow, modulus[4], a[4], borrow, a[4]);
     SUBC(borrow, modulus[5], a[5], borrow, a[5]);
     SUBC(borrow, modulus[6], a[6], borrow, a[6]);
     SUBC(borrow, modulus[7], a[7], borrow, a[7]);
     SUBC(borrow, modulus[8], a[8], borrow, a[8]);
     SUBC(borrow, modulus[9], a[9], borrow, a[9]);
     SUBC(borrow, modulus[10], a[10], borrow, a[10]);
     SUBC(borrow, modulus[11], a[11], borrow, a[11]);
     SUBC(borrow, modulus[12], a[12], borrow, a[12]);
     SUBC(borrow, modulus[13], a[13], borrow, a[13]);
     SUBC(borrow, modulus[14], a[14], borrow, a[14]);
     SUBC(borrow, modulus[15], a[15], borrow, a[15]);
#endif

     return (~borrow & 0x01);
}


BOOL fpmul512_c(dig512 a, dig512 b, dig512 c)
{ // Field multiplication c=a*b mod p implemented in C
#if TARGET_GENERIC == TRUE
     dig carry = 0;
     dig borrow = 0;
     dig u, v;
     dig rsi = 0, rdi = 0;
     dig partial[ML_WORDS512 + 1];
     dig AB[4];
     dig temp[2 * ML_WORDS512] = { 0 };
     dig UV[2];
     dig zfff = (dig)(-1);
     dig xa, xb, res, tres;
     dig i, j;

     for (i = 0; i < ML_WORDS512; i++)
     {
          u = 0;
          for (j = 0; j < ML_WORDS512; j++)
          {
               dig_x_dig(a[i], b[j], UV);
               v = UV[0] + u; // low(UV) + u 
               //----
               xa = v >> (ML_WORD - 1);
               xb = u >> (ML_WORD - 1);
               tres = (v & zfff) - (u & zfff);
               carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
               //carry = is_digit_lessthan_ct(v, *UV);

               //carry = v < *UV;
               //----
               u = UV[1] + carry;

               v = temp[i + j] + v;
               //----
               xa = v >> (ML_WORD - 1);
               xb = temp[i + j] >> (ML_WORD - 1);
               tres = (v & zfff) - (temp[i + j] & zfff);
               carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
               //----
               //carry = v < temp[i + j];
               u = u + carry;

               temp[i + j] = v;
          }
          temp[ML_WORDS512 + i] = u;
     }

     dig_x_dig(gamma_569, temp[ML_WORDS512 + 0], AB);

     partial[0] = AB[0] + temp[0];
     //rsi = (partial[0] < AB[0]); 
     //---
     xa = partial[0] >> (ML_WORD - 1);
     xb = AB[0] >> (ML_WORD - 1);
     tres = (partial[0] & zfff) - (AB[0] & zfff);
     rsi = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     //---

     for (i = 1; i < ML_WORDS512; i++)
     {
          dig_x_dig(gamma_569, temp[ML_WORDS512 + i], AB + (2 * i % 4));

          partial[i] = AB[3 - (2 * i % 4)] + temp[i];
          xa = partial[i] >> (ML_WORD - 1);
          xb = temp[i] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (temp[i] & zfff);
          carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));
          res = partial[i] + rdi;
          rdi = carry | (rdi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;

          partial[i] += AB[2 * i % 4];
          xa = partial[i] >> (ML_WORD - 1);
          xb = AB[2 * i % 4] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (AB[2 * i % 4] & zfff);
          carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));
          res = partial[i] + rsi;

          rsi = carry | (rsi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;
     }

     partial[ML_WORDS512] = AB[3] + rdi + rsi + 1; //no carry possible here

     partial[ML_WORDS512] *= gamma_569;

     c[0] = partial[0] + partial[ML_WORDS512];

     xa = c[0] >> (ML_WORD - 1);
     xb = partial[0] >> (ML_WORD - 1);
     tres = (c[0] & zfff) - (partial[0] & zfff);
     carry = (~xa & xb) | ((~xa | xb) & (tres >> (ML_WORD - 1)));

     for (i = 1; i < ML_WORDS512; i++)
     {
          c[i] = partial[i] + carry;
          //carry = c[i] < partial[i];
          //---
          carry = carry & ~(c[i] >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1));
          //---
     }

     u = ~(0 - (dig)carry); // rsi = mask

     xa = c[0] >> (ML_WORD - 1);
     xb = (u & gamma_569) >> (ML_WORD - 1);
     tres = (c[0] & zfff) - ((u & gamma_569) & zfff);
     borrow = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     //---
     c[0] -= u & gamma_569;

     for (i = 1; i < ML_WORDS512; i++)
     {
          res = c[i] - borrow;
          borrow = (borrow & ((~(0 - c[i])) >> (ML_WORD - 1)) & (~(c[i]) >> (ML_WORD - 1)));
          c[i] = res;
     }

#elif (TARGET == TARGET_AMD64 || TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_AMD64)
    unsigned char rsi = 0, rdi = 0, carry = 0, borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_AMD64)
    dig rsi = 0, rdi = 0, carry = 0, borrow = 0;
    uint128_t tempReg;
#elif (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
    unsigned char rsi = 0, rdi = 0, carry = 0, borrow = 0;
    uint64_t tempReg;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    dig rsi = 0, rdi = 0, carry = 0, borrow = 0;
    uint64_t tempReg;
#endif
    dig i, j, u, v;
    dig t[2 * ML_WORDS512] = { 0 };
    dig partial[ML_WORDS512 + 1];
    dig AB[4], UV[2];

     for (i = 0; i < ML_WORDS512; i++)
     {
          u = 0;
          for (j = 0; j < ML_WORDS512; j++)
          {
               MUL(a[i], b[j], UV + 1, UV[0]);
               ADDC(0, UV[0], u, carry, v);
               u = UV[1] + carry;
               ADDC(0, t[i + j], v, carry, v);
               u = u + carry;
               t[i + j] = v;
          }
          t[ML_WORDS512 + i] = u;
     }

     MUL(gamma_569, t[ML_WORDS512 + 0], AB + 1, AB[0]);
     ADDC(0, AB[0], t[0], rsi, partial[0]);

     for (i = 1; i < ML_WORDS512; i++)
     {
          MUL(gamma_569, t[ML_WORDS512 + i], AB + (2 * i % 4) + 1, AB[2 * i % 4]);
          ADDC(rdi, AB[3 - (2 * i % 4)], t[i], rdi, partial[i]);
          ADDC(rsi, AB[2 * i % 4], partial[i], rsi, partial[i]);
     }

     partial[ML_WORDS512] = AB[3] + rdi + rsi + 1;
     partial[ML_WORDS512] *= gamma_569;
     ADDC(0, partial[0], partial[ML_WORDS512], carry, c[0]);
     for (i = 1; i < ML_WORDS512; i++)
     {
          ADDC(carry, partial[i], 0, carry, c[i]);
     }

     u = ~(0 - (dig)carry);
     SUBC(0, c[0], u & gamma_569, borrow, c[0]);
     for (i = 1; i < ML_WORDS512; i++)
     {
          SUBC(borrow, c[i], 0, borrow, c[i]);
     }
#endif

     return TRUE;
}


BOOL fpsqr512_c(dig512 a, dig512 c)
{ // Field squaring c=a^2 mod p implemented in C
#if TARGET_GENERIC == TRUE
     dig rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
     sdig i, j, k, bound;
     dig r0 = 0, r1 = 0, r2 = 0;
     dig temp[2 * ML_WORDS512] = { 0 };
     dig partial[ML_WORDS512 + 1];
     dig AB[4], UV[2] = { 0 };
     dig zfff = (dig)(-1);
     dig xa, xb, res, tres;

     for (k = 0; k < ML_WORDS512; k++)
     {
          i = k;
          j = 0;
          bound = k / 2;
          while (j < bound)
          {
               dig_x_dig(a[i], a[j], UV);

               // mul by 2
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
               //---

               r0 = r0 + UV[0];
               //eps0 = (r0 < UV[0]); 
               eps0 = is_digit_lessthan_ct(r0, UV[0]);

               r1 = r1 + UV[1];
               //eps1 = (r1 < UV[1]); 
               eps1 = is_digit_lessthan_ct(r1, UV[1]);

               r1 = r1 + eps0;
               //eps1 = eps1 | (!r1 & eps0);
               eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);
               //#endif

               r2 = r2 + eps1;

               i--;
               j++;
          }

          dig_x_dig(a[i], a[j], UV);

          if ((k % 2) == 1)
          {
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
          }

          r0 = r0 + UV[0];
          //eps0 = (r0 < UV[0]); 
          eps0 = is_digit_lessthan_ct(r0, UV[0]);

          r1 = r1 + UV[1];
          //eps1 = (r1 < UV[1]); 
          eps1 = is_digit_lessthan_ct(r1, UV[1]);

          r1 = r1 + eps0;
          //eps1 = eps1 | (!r1 & eps0);
          eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);
          //#endif

          r2 = r2 + eps1;

          temp[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;

     }

     for (k = ML_WORDS512; k <= 2 * ML_WORDS512 - 2; k++)
     {
          i = (ML_WORDS512 - 1);
          j = k - i;
          bound = k / 2;
          while (j < bound)
          {
               dig_x_dig(a[i], a[j], UV);

               // mul by 2
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
               //---

               r0 = r0 + UV[0];
               //eps0 = (r0 < UV[0]); 
               eps0 = is_digit_lessthan_ct(r0, UV[0]);

               r1 = r1 + UV[1];
               //eps1 = (r1 < UV[1]); 
               eps1 = is_digit_lessthan_ct(r1, UV[1]);

               r1 = r1 + eps0;
               //eps1 = eps1 | (!r1 & eps0);
               eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);
               //#endif

               r2 = r2 + eps1;

               i--;
               j++;
          }

          dig_x_dig(a[i], a[j], UV);

          if ((k % 2) == 1)
          {
               eps0 = UV[0] >> (ML_WORD - 1);
               eps1 = UV[1] >> (ML_WORD - 1);
               UV[0] <<= 1;
               UV[1] <<= 1;
               UV[1] ^= eps0;
               r2 = r2 + eps1;
          }

          r0 = r0 + UV[0];
          //eps0 = (r0 < UV[0]); 
          eps0 = is_digit_lessthan_ct(r0, UV[0]);

          r1 = r1 + UV[1];
          //eps1 = (r1 < UV[1]); 
          eps1 = is_digit_lessthan_ct(r1, UV[1]);

          r1 = r1 + eps0;
          //eps1 = eps1 | (!r1 & eps0);
          eps1 = eps1 | (is_digit_zero_ct(r1) & eps0);

          r2 = r2 + eps1;

          temp[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;
     }

     temp[2 * ML_WORDS512 - 1] = r0;

     dig_x_dig(gamma_569, temp[ML_WORDS512 + 0], AB);

     partial[0] = AB[0] + temp[0];

     xa = partial[0] >> (ML_WORD - 1);
     xb = AB[0] >> (ML_WORD - 1);
     tres = (partial[0] & zfff) - (AB[0] & zfff);
     rsi = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));

     for (i = 1; i < ML_WORDS512; i++)
     {
          dig_x_dig(gamma_569, temp[ML_WORDS512 + i], AB + (2 * i % 4));

          partial[i] = AB[3 - (2 * i % 4)] + temp[i];
          //carry = (partial[i] < temp[i]); 
          //---
          xa = partial[i] >> (ML_WORD - 1);
          xb = temp[i] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (temp[i] & zfff);
          carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
          //---
          res = partial[i] + rdi;
          //partial[i] += rdi;
          //(partial[i] < rdi);
          //---
          rdi = carry | (rdi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;
          //---


          partial[i] += AB[2 * i % 4];
          //carry = (partial[i] < AB[2 * i % 4]);
          //---
          xa = partial[i] >> (ML_WORD - 1);
          xb = AB[2 * i % 4] >> (ML_WORD - 1);
          tres = (partial[i] & zfff) - (AB[2 * i % 4] & zfff);
          carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
          //---
          res = partial[i] + rsi;
          //partial[i] += rsi;
          //---

          //---
          //rsi = carry | (partial[i] < rsi); 
          rsi = carry | (rsi & ~(res >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1)));
          partial[i] = res;
          //---
     }
     partial[ML_WORDS512] = AB[3] + rdi + rsi + 1; //no carry possible here

     partial[ML_WORDS512] *= gamma_569;

     c[0] = partial[0] + partial[ML_WORDS512];
     //carry = (*c < partial[0]); 
     //---
     xa = c[0] >> (ML_WORD - 1);
     xb = partial[0] >> (ML_WORD - 1);
     tres = (*c & zfff) - (partial[0] & zfff);
     carry = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     //---

     for (i = 1; i < ML_WORDS512; i++)
     {
          c[i] = partial[i] + carry;
          //carry = c[i] < partial[i];
          //---
          carry = carry & ~(c[i] >> (ML_WORD - 1)) & (partial[i] >> (ML_WORD - 1));
          //---
     }

     r0 = ~(0 - carry);

     xa = c[0] >> (ML_WORD - 1);
     xb = (r0 & gamma_569) >> (ML_WORD - 1);
     tres = (c[0] & zfff) - ((r0 & gamma_569) & zfff);
     borrow = (~xa & xb) | ((~xa | xb)& (tres >> (ML_WORD - 1)));
     //---
     c[0] -= r0 & gamma_569;

     for (i = 1; i < ML_WORDS512; i++)
     {
          res = c[i] - borrow;
          borrow = (borrow & ((~(0 - c[i]) >> (ML_WORD - 1)) & (~(c[i]) >> (ML_WORD - 1))));
          c[i] = res;
     }

#elif (TARGET == TARGET_AMD64 || TARGET == TARGET_x86 || TARGET == TARGET_ARM) 
#if (OS_TARGET == OS_WIN && TARGET == TARGET_AMD64)
    unsigned char rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_AMD64)
    dig rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
    uint128_t tempReg;
#elif (OS_TARGET == OS_WIN && TARGET == TARGET_x86)
    unsigned char rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
    uint64_t tempReg;
#elif (OS_TARGET == OS_LINUX && TARGET == TARGET_x86) || TARGET == TARGET_ARM
    dig rsi = 0, rdi = 0, eps0 = 0, eps1 = 0, carry = 0, borrow = 0;
    uint64_t tempReg;
#endif
    sdig i, j, k, bound;
    dig r0 = 0, r1 = 0, r2 = 0;
    dig temp[2 * ML_WORDS512] = { 0 };
    dig partial[ML_WORDS512 + 1];
    dig AB[4], UV[2] = { 0 };

     for (k = 0; k < ML_WORDS512; k++)
     {
          i = k;
          j = 0;
          bound = k / 2;
          while (j < bound)
          {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               r2 = r2 + (UV[1] >> (ML_WORD - 1));
               SHIFTL(UV[1], UV[0], 1, UV[1]);
               UV[0] <<= 1;
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
               i--;
               j++;
          }
          if ((k % 2) == 0) {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
          } else {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               r2 = r2 + (UV[1] >> (ML_WORD - 1));
               SHIFTL(UV[1], UV[0], 1, UV[1]);
               UV[0] <<= 1;
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
          }
          temp[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;
     }
     for (k = ML_WORDS512; k <= 2 * ML_WORDS512 - 2; k++)
     {
          i = (ML_WORDS512 - 1);
          j = k - i;
          bound = k / 2;
          while (j < bound)
          {
               MUL(a[i], a[j], &(UV[1]), UV[0]);

               r2 = r2 + (UV[1] >> (ML_WORD - 1));
               SHIFTL(UV[1], UV[0], 1, UV[1]);
               UV[0] <<= 1;

               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;

               i--;
               j++;
          }
          if ((k % 2) == 0) {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
          } else {
               MUL(a[i], a[j], &(UV[1]), UV[0]);
               r2 = r2 + (UV[1] >> (ML_WORD - 1));
               SHIFTL(UV[1], UV[0], 1, UV[1]);
               UV[0] <<= 1;
               ADDC(0, r0, UV[0], eps0, r0);
               ADDC(eps0, r1, UV[1], eps1, r1);
               r2 = r2 + eps1;
          }
          temp[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;
     }
     temp[2 * ML_WORDS512 - 1] = r0;

     MUL(gamma_569, temp[ML_WORDS512 + 0], &(AB[1]), AB[0]);
     ADDC(0, AB[0], temp[0], rsi, partial[0]);
     for (i = 1; i < ML_WORDS512; i++)
     {
          MUL(gamma_569, temp[ML_WORDS512 + i], AB + (2 * i % 4) + 1, AB[2 * i % 4]);
          ADDC(rdi, AB[(3 - (2 * i % 4))], temp[i], rdi, partial[i]); 
          ADDC(rsi, partial[i], AB[((2 * i) % 4)], rsi, partial[i]);
     }
     partial[ML_WORDS512] = AB[3] + rdi + rsi + 1; 
     partial[ML_WORDS512] *= gamma_569;

     ADDC(0, partial[0], partial[ML_WORDS512], carry, c[0]);
     for (i = 1; i < ML_WORDS512; i++)
     {
          ADDC(carry, partial[i], 0, carry, c[i]);
     }

     r0 = ~(0 - (dig)carry);
     SUBC(0, c[0], r0 & gamma_569, borrow, c[0]);
     for (i = 1; i < ML_WORDS512; i++)
     {
          SUBC(borrow, c[i], 0, borrow, c[i]);
     }
#endif

     return TRUE;
}

#endif
