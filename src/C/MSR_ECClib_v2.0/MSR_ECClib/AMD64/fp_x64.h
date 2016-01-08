//*******************************************************************************
// MSR ECClib v2.0, an efficient and secure elliptic curve cryptographic library
//
//   Copyright (c) Microsoft Corporation. All rights reserved.
//
//   MIT License
//
//   Permission is hereby granted, free of charge, to any person obtaining 
//   a copy of this software and associated documentation files (the 
//   ""Software""), to deal in the Software without restriction, including
//   without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to
//   permit persons to whom the Software is furnished to do so, subject to
//   the following conditions:
//
//   The above copyright notice and this permission notice shall
//   be included in all copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND,
//   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
//   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
//   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
//
// Abstract: header file for field operations in x64 assembly
//
// This software is based on the article by Joppe Bos, Craig Costello, 
// Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
// cryptography: an efficiency and security analysis", preprint available
// at http://eprint.iacr.org/2014/130.
//*****************************************************************************

#ifdef __WINDOWS__
    #include "macamd64.inc"
#endif


// Prime values

#define P256_0 18446744073709551427       // Prime p = 2^256-189
#define P256_1 18446744073709551615
#define P256_c 189                        // Value c in p = 2^256-c

#define P384_0 18446744073709551299       // Prime p = 2^384-317
#define P384_1 18446744073709551615
#define P384_2 18446744073709551615
#define P384_3 18446744073709551615
#define P384_4 18446744073709551615
#define P384_5 18446744073709551615
#define P384_c 317                        // Value c in p = 2^384-c

#define P512_0 18446744073709551047       // Prime p = 2^512-569
#define P512_1 18446744073709551615
#define P512_2 18446744073709551615
#define P512_3 18446744073709551615
#define P512_4 18446744073709551615
#define P512_5 18446744073709551615
#define P512_6 18446744073709551615
#define P512_7 18446744073709551615
#define P512_c 569                        // Value c in p = 2^512-c


// Register macros

#ifdef __WINDOWS__                        // For Windows OS

//--- Volatile registers that can be used freely: rcx, rdx, r8:r11, rax, xmm0:xmm5, ymm0:ymm5, ymm6h:ymm15h
//--- Non-volatile registers that should be saved: rbx, rbp, rdi, rsi, r12:r15, xmm6:xmm15

//--- Following registers are used for parameter passing:
#define reg_p1   rcx
#define reg_p2   rdx
#define reg_p3   r8
#define reg_p4   r9
//--- Extra registers:
#define reg_x1   rdi
#define reg_x2   rsi

// Byte-size registers
#define reg_p1b  cl
#define reg_p2b  dl
#define reg_p3b  r8b
#define reg_p4b  r9b
#define reg_x1b  dil
#define reg_x2b  sil

// Auxiliary temp for fpmul and fpsqr
#define reg_aux  reg_p3

#else                                    // For Linux OS

//--- Volatile registers that can be used freely: rdi, rsi, rcx, rdx, r8:r11, rax, xmm0:xmm15, ymm0:ymm15
//--- Non-volatile registers that should be saved: rbx, rbp, r12:r15

//--- Following registers are used for parameter passing:
#define reg_p1   rdi
#define reg_p2   rsi
#define reg_p3   rdx
#define reg_p4   rcx
//--- Extra registers:
#define reg_x1   r8
#define reg_x2   r9

// Byte-size registers
#define reg_p1b  dil
#define reg_p2b  sil
#define reg_p3b  dl
#define reg_p4b  cl
#define reg_x1b  r8b
#define reg_x2b  r9b

// Auxiliary temp for fpmul and fpsqr
#define reg_aux  reg_p2

#endif
