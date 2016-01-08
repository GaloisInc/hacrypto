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
* Abstract: template for field functions
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
******************************************************************************/  

#include "msr_ecclib.h"
#include "msr_ecclib_priv.h"


void FP_MUL(BASE_ELM a, BASE_ELM b, BASE_ELM c)
{ // Modular multiplication, c=a*b mod p

    FP_MUL_LOW(a, b, c);
    return;
}


void FP_SQR(BASE_ELM a, BASE_ELM c)
{ // Modular squaring, c=a^2 mod p

    FP_SQR_LOW(a, c);
    return;
}


void FP_ADD(BASE_ELM a, BASE_ELM b, BASE_ELM c)
{ // Modular addition, c=a+b mod p

    FP_ADD_LOW(a, b, c);
    return;
}


void FP_SUB(BASE_ELM a, BASE_ELM b, BASE_ELM c)
{ // Modular subtraction, c=a-b mod p

    FP_SUB_LOW(a, b, c);
    return;
}


void FP_DIV2(BASE_ELM a, BASE_ELM c)
{ // Modular division by two, c=a/2 mod p

    FP_DIV2_LOW(a, c);
    return;
}


BOOL FP_NEG(BASE_ELM modulus, BASE_ELM a)
{ // Subtraction, a=modulus-a
  // If modulus=p then it performs a modular negation a=-a mod p
  // If a <= modulus then eval = 1 (TRUE)
    BOOL eval = FALSE;

    eval = FP_NEG_LOW(modulus, a);
    return eval;
}


void FP_MULC(BASE_ELM a, BASE_ELM b, BASE_ELM c)
{ // Modular multiplication by a single-word multiplier, c=a*b mod p, where b is a single-word operand

    FP_MULC_LOW(a, b, c);
    return;
}


void FP_ZERO(BASE_ELM a)
{ // Zeroize a field element, a=0

    FP_ZERO_LOW(a);
    return;
}


void FP_INV(BASE_ELM a)
{ // Modular inversion, a=a^-1 mod p

    FP_INV_LOW(a);
    return;
}