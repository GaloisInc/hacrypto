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
// Abstract: field operations over GF(2^256-189) in x64 assembly.
//           Supports MASM through pre-building in MSVS, and GNU assembler (GAS).
//
// This software is based on the article by Joppe Bos, Craig Costello, 
// Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
// cryptography: an efficiency and security analysis", preprint available
// at http://eprint.iacr.org/2014/130.
//******************************************************************************

#include "fp_x64.h"

#ifdef __LINUX__
  .intel_syntax noprefix
#endif


#ifdef __WINDOWS__
.code
#else
.text
#endif
//****************************************************************************************
// (Constant-time) field multiplication using integer multiplication by product scanning
// Operation: c [reg_p3] = a [reg_p1] * b [reg_p2] mod p, p = 2^256-189
// NOTE: input should have reg_p3 != reg_p1 and reg_p3 != reg_p2 
// Inputs: a, b in [0, p-1]
// Output: c in [0, p-1] 
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpmul256_a, _TEXT00
  rex_push_reg rbx
  push_reg     reg_x1
  push_reg     reg_x2
  push_reg     r12
  push_reg     r13
  END_PROLOGUE
#else
.global fpmul256_a
fpmul256_a:
  push         rbx
  push         r12
  push         r13
#endif

  mov  rbx, reg_p2          // Save rbx<-rdx (in Windows)
  mov  reg_x2, reg_p3       // Save r9 <-rdx (in Linux) 
  
  mov  rax, [rbx]
  mul qword ptr [reg_p1]    // a0*b0
  mov  r13, rax             // r13 = C0
  mov  r12, rdx        
  
  mov  reg_aux, [reg_p1+8] 
  mov  rax, [rbx]
  xor  reg_p4, reg_p4  
  xor  r11, r11  
  mul  reg_aux              // a1*b0
  add  r12, rax
  mov  r10, rdx
  adc  r10, 0

  mov  rax, [rbx+8]         // a0*b1
  mul qword ptr [reg_p1] 
  add  r12, rax
  adc  r10, rdx
  //adc  r11, 0
  setc r11b
  mov  [reg_x2+8], r12      // C1
  
  mov  rax, [rbx]
  mul qword ptr [reg_p1+16] // a2*b0
  add  r10, rax
  adc  r11, rdx
  //adc  reg_p4, 0

  mov  rax, [rbx+8]
  mul  reg_aux              // a1*b1
  add  r10, rax
  adc  r11, rdx
  //adc  reg_p4, 0
  setc reg_p4b

  mov  rax, [rbx+16]
  mul qword ptr [reg_p1]    // a0*b2
  add  r10, rax
  mov  [reg_x2+16], r10     // C2
  adc  r11, rdx
  adc  reg_p4, 0

  xor  r10, r10
  mov  rax, [rbx]
  mul qword ptr [reg_p1+24] // a3*b0 
  add  r11, rax
  adc  reg_p4, rdx
  //adc  r10, 0
  setc r10b

  mov  rax, [rbx+8]
  mul qword ptr [reg_p1+16] // a2*b1
  add  r11, rax
  adc  reg_p4, rdx
  adc  r10, 0

  mov  rax,[rbx+16]
  mul  reg_aux              // a1*b2
  add  r11, rax
  adc  reg_p4, rdx
  adc  r10, 0

  mov  rax, [rbx+24]
  mul qword ptr [reg_p1]    // a0*b3
  add  r11, rax
  mov  [reg_x2+24], r11     // C3
  adc  reg_p4, rdx
  adc  r10, 0

  xor  r11, r11
  mov  rax, [rbx+8]
  mul qword ptr [reg_p1+24] // a3*b1
  add  reg_p4, rax
  adc  r10, rdx
  //adc  r11, 0
  setc r11b

  mov  rax, [rbx+16]
  mul qword ptr [reg_p1+16] // a2*b2
  add  reg_p4, rax
  adc  r10, rdx
  adc  r11, 0

  mov  rax, [rbx+24]
  mul  reg_aux              // a1*b3
  add  reg_p4, rax          // reg_x1 = C4
  adc  r10, rdx
  adc  r11, 0

  xor  reg_x1, reg_x1
  mov  rax, [rbx+16]
  mul qword ptr [reg_p1+24] // a3*b2
  add  r10, rax
  adc  r11, rdx
  //adc  reg_x1, 0
  setc reg_x1b

  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+16] // a2*b3
  add  r10, rax             // r10 = C5
  adc  r11, rdx
  adc  reg_x1, 0

  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+24] // a3*b3
  add  r11, rax             // r11 = C6
  adc  reg_x1, rdx          // reg_x1 = C7

// Reduction

  mov  rax, P256_c
  mul  reg_p4 
  add  r13, rax             // r13 = partial0
  adc  rdx, 0    
  mov  reg_p4, rdx 

  xor  r12, r12
  mov  rax, P256_c
  mul  r10 
  add  rax, reg_p4 
  //adc  r12, 0
  setc r12b 
  mov  r10, [reg_x2+8]    
  add  r10, rax             // r10 = partial1
  adc  r12, rdx 

  xor  reg_p4, reg_p4
  mov  rax, P256_c
  mul  r11 
  add  rax, r12  
  //adc  reg_p4, 0 
  setb reg_p4b  
  mov  r11, [reg_x2+16]    
  add  r11, rax             // r11 = partial2
  adc  reg_p4, rdx  

  xor  r12, r12
  mov  rax, P256_c
  mul  reg_x1 
  add  rax, reg_p4 
  adc  r12, 1       
  mov  reg_x1, [reg_x2+24]    
  add  reg_x1, rax          // reg_x1 = partial3
  adc  rdx, r12             // rdx = partial4 + 1
  
  xor  r12, r12
  mov  rax, P256_c         
  mul  rdx   
  add  r13, rax             // r13 = partial0     
  adc  r10, 0               // r10 = partial1
  adc  r11, 0               // r11 = partial2
  adc  reg_x1, 0            // reg_x1 = partial3
  
  mov  rax, P256_c          // final correction
  cmovc rax, r12
  sub  r13, rax
  mov  [reg_x2], r13  
  sbb  r10, 0
  mov  [reg_x2+8], r10 
  sbb  r11, 0
  mov  [reg_x2+16], r11  
  sbb  reg_x1, 0
  mov  [reg_x2+24], reg_x1   

#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop  r13
  pop  r12
  pop  reg_x2
  pop  reg_x1
  pop  rbx
  ret
NESTED_END fpmul256_a, _TEXT00
#else
  pop  r13
  pop  r12
  pop  rbx
  ret
#endif


//****************************************************************************************
// (Constant-time) field squaring using integer multiplication by product scanning
// Operation: c [reg_p2] = a [reg_p1]^2 mod p, p = 2^256-189
// NOTE: input should have reg_p2 != reg_p1 
// Input:  a in [0, p-1]
// Output: c in [0, p-1] 
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpsqr256_a, _TEXT00
  rex_push_reg rbx
  push_reg     reg_x1
  push_reg     reg_x2
  END_PROLOGUE
#else
.global fpsqr256_a
fpsqr256_a:
  push         rbx
#endif

  mov  rbx, reg_p2          // Save rbx<-rdx (in Windows)
  mov  reg_x2, reg_p3       // Save r9 <-rdx (in Linux) 

  xor  r10, r10
  mov  rax, [reg_p1]
  mul qword ptr [reg_p1+8]   
  add  rax, rax
  mov  reg_x2, rax
  adc  rdx, rdx
  mov  reg_p4, rdx
  //adc  r10, 0             // 2*a0*a1
  setb r10b

  mov  rax, [reg_p1]
  mul  rax                  // a0^2
  mov  [rbx], rax           // C0
  add  reg_x2, rdx
  mov  [rbx+8], reg_x2      // C1
  adc  reg_p4, 0

  xor  reg_x1, reg_x1
  mov  rax, [reg_p1]
  mul qword ptr [reg_p1+16] 
  add  rax, rax
  mov  reg_x2, rax
  adc  rdx, rdx
  mov  r11, rdx
  //adc  reg_x1, 0          // 2*a0*a2
  setb reg_x1b

  mov  rax, [reg_p1+8]
  mul qword ptr [reg_p1+8]  // a1^2
  add  reg_x2, rax
  mov  reg_aux, [reg_p1+24]
  adc  r11, rdx
  adc  reg_x1, 0

  mov  rax, [reg_p1]
  mul  reg_aux              // a0*a3
  add  reg_x2, reg_p4
  mov  [rbx+16], reg_x2     // C2
  adc  r11, r10
  adc  reg_x1, 0
  mov  reg_x2, rax
  mov  r10, rdx
  
  xor  reg_p4, reg_p4 
  mov  rax, [reg_p1+8]
  mul qword ptr [reg_p1+16] // a1*a2
  add  reg_x2, rax
  adc  r10, rdx
  //adc  reg_p4, 0
  setb reg_p4b
  add  reg_x2, reg_x2
  adc  r10, r10
  adc  reg_p4, reg_p4

  mov  rax, [reg_p1+8]
  mul  reg_aux              // a1*a3
  add  reg_x2, r11
  mov  [rbx+24], reg_x2     // C3
  adc  r10, reg_x1
  adc  reg_p4, 0
  xor  reg_x1, reg_x1
  add  rax, rax            // 2*a1*a3
  mov  reg_x2, rax
  adc  rdx, rdx
  mov  r11, rdx
  //adc  reg_x1, 0
  setb reg_x1b
  
  mov  rax, [reg_p1+16]
  mul qword ptr [reg_p1+16] // a2^2
  add  reg_x2, r10
  adc  reg_p4, r11
  adc  reg_x1, 0
  add  reg_x2, rax          // reg_x2 = C4
  //mov  [rbx+32], reg_x2
  adc  reg_p4, rdx
  adc  reg_x1, 0

  xor  r11, r11
  mov  rax, [reg_p1+16]
  mul  reg_aux              
  add  rax, rax
  adc  rdx, rdx
  //adc  r11, 0             // 2*a2*a3
  setb r11b
  add  reg_p4, rax          // reg_p4 = C5
  //mov  [rbx+40], reg_p4
  adc  reg_x1, rdx
  adc  r11, 0

  mov  rax, reg_aux
  mul  rax                  // a3^2
  add  reg_x1, rax          // reg_x1 = C6 
  //mov  [rbx+48], reg_x1
  adc  r11, rdx             // r11 = C7
  //mov  [rbx+56], r11

// Reduction

  mov  rax, P256_c
  mul  reg_x2 
  mov  reg_x2, [rbx]
  add  reg_x2, rax          // reg_x2 = partial0
  adc  rdx, 0    
  mov  r10, rdx 

  xor  reg_aux, reg_aux
  mov  rax, P256_c
  mul  reg_p4 
  add  rax, r10 
  adc  reg_aux, 0
  mov  reg_p4, [rbx+8]    
  add  reg_p4, rax          // reg_p4 = partial1
  adc  reg_aux, rdx 

  xor  reg_p1, reg_p1
  mov  rax, P256_c
  mul  reg_x1 
  add  rax, reg_aux  
  //adc  reg_p1, 0  
  setb reg_p1b 
  mov  reg_x1, [rbx+16]    
  add  reg_x1, rax          // reg_x1 = partial2
  adc  reg_p1, rdx  

  xor  r10, r10
  mov  rax, P256_c
  mul  r11 
  add  rax, reg_p1  
  adc  r10, 1       
  mov  r11, [rbx+24]    
  add  r11, rax             // r11 = partial3
  adc  r10, rdx             // r10 = partial4 + 1
  
  xor  reg_aux, reg_aux
  mov  rax, P256_c         
  mul  r10 
  add  reg_x2, rax          // reg_x2 = partial0     
  adc  reg_p4, 0            // reg_p4 = partial1
  adc  reg_x1, 0            // reg_x1 = partial2
  adc  r11, 0               // r11 = partial3
  
  mov  rax, P256_c          // final correction
  cmovc rax, reg_aux
  sub  reg_x2, rax
  mov  [rbx], reg_x2
  sbb  reg_p4, 0
  mov  [rbx+8], reg_p4 
  sbb  reg_x1, 0
  mov  [rbx+16], reg_x1  
  sbb  r11, 0
  mov  [rbx+24], r11  

#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop  reg_x2
  pop  reg_x1
  pop  rbx
  ret
NESTED_END fpsqr256_a, _TEXT00
#else
  pop  rbx
  ret
#endif


//****************************************************************************************
// (Constant-time) field addition 
// Operation: c [reg_p3] = a [reg_p1] + b [reg_p2] mod p, p = 2^256-189
// Inputs:  a, b in [0, p-1]
// Output: c in [0, p-1]
//****************************************************************************************
#ifdef __WINDOWS__
LEAF_ENTRY fpadd256_a, _TEXT00  
#else
.global fpadd256_a
fpadd256_a:
#endif
  mov  reg_p4, [reg_p1]      // a + P256_c  
  add  reg_p4, P256_c
  mov  r10, [reg_p1+8]
  adc  r10, 0
  mov  r11, [reg_p1+16]
  adc  r11, 0
  mov  rax, [reg_p1+24]
  adc  rax, 0
  
  mov  reg_p1, [reg_p2]     // (a+P256_c) + b 
  add  reg_p4, reg_p1
  mov  reg_p1, [reg_p2+8]
  adc  r10, reg_p1
  mov  reg_p1, [reg_p2+16]
  adc  r11, reg_p1
  mov  reg_p1, [reg_p2+24]
  adc  rax, reg_p1
  
  mov  reg_p2, 0            // if (carry) then c = (a+P256_c) + b
  mov  reg_p1, P256_c       // else c = (a+P256_c) + b - P256_c
  cmovc reg_p1, reg_p2
  sub  reg_p4, reg_p1
  mov  [reg_p3], reg_p4
  sbb  r10, 0
  mov  [reg_p3+8], r10
  sbb  r11, 0
  mov  [reg_p3+16], r11
  sbb  rax, 0
  mov  [reg_p3+24], rax
  ret
#ifdef __WINDOWS__
LEAF_END fpadd256_a, _TEXT00
#endif


//****************************************************************************************
// (Constant-time) field subtraction
// Operation: c [reg_p3] = a [reg_p1] + b [reg_p2] mod p, p = 2^256-189
// Input:  a, b in [0, p-1]
// Output: c in [0, p-1]
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpsub256_a, _TEXT00
  rex_push_reg   reg_x1
  END_PROLOGUE
#else
.global fpsub256_a
fpsub256_a:
#endif

  xor  rax, rax             // a - b
  mov  reg_p4, [reg_p1]
  sub  reg_p4, [reg_p2]
  mov  r10, [reg_p1+8]
  sbb  r10, [reg_p2+8]
  mov  r11, [reg_p1+16]
  sbb  r11, [reg_p2+16]
  mov  reg_x1, [reg_p1+24]
  sbb  reg_x1, [reg_p2+24]

  mov  reg_p1, P256_c       // if (carry) then c = (a-b) - P256_c  
  cmovnc reg_p1, rax        // else c = a - b
  sub  reg_p4, reg_p1
  mov  [reg_p3], reg_p4
  sbb  r10, 0
  mov  [reg_p3+8], r10
  sbb  r11, 0
  mov  [reg_p3+16], r11
  sbb  reg_x1, 0
  mov  [reg_p3+24], reg_x1 

#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop  reg_x1
  ret
NESTED_END fpsub256_a, _TEXT00
#else
  ret
#endif


//****************************************************************************************
// (Constant-time) field division by 2 
// Operation: a [reg_p2] = a [reg_p1]/2 mod p, p = 2^256-189
// Input:  a in [0, p-1]
// Output: c in [0, p-1]
//****************************************************************************************
#ifdef __WINDOWS__
LEAF_ENTRY fpdiv2_256_a, _TEXT00
#else
.global fpdiv2_256_a
fpdiv2_256_a:
#endif
  xor  reg_p4, reg_p4
  mov  reg_p3, [reg_p1]
  bt   reg_p3, 0
  mov  r11, P256_0
  cmovnc r11, reg_p4
  mov  rax, P256_1
  cmovnc rax, reg_p4
    
  add  reg_p3, r11          // if (a mod 2 = 1) then temp = a + p
  mov  reg_p4, [reg_p1+8]   // else temp = a + 0
  adc  reg_p4, rax
  mov  r10, [reg_p1+16]
  adc  r10, rax
  mov  r11, [reg_p1+24]
  adc  r11, rax
  mov  rax, 0
  adc  rax, 0
  
  shrd reg_p3, reg_p4, 1    // c = temp/2
  mov  [reg_p2], reg_p3
  shrd reg_p4, r10, 1
  mov  [reg_p2+8], reg_p4
  shrd r10, r11, 1
  mov  [reg_p2+16], r10
  shrd r11, rax, 1
  mov  [reg_p2+24], r11
  ret
#ifdef __WINDOWS__
LEAF_END fpdiv2_256_a, _TEXT00
#endif


//****************************************************************************************
// (Constant-time) field negation and subtraction from a modulus
// Operation: a [reg_p2] = modulus [reg_p1] - a [reg_p2]
//            if modulus = p = 2^256-189, then this performs a field negation -a (mod p)
// Input:  a in [0, modulus-1]
// Output: a in [0, modulus-1], rax = 1 (TRUE) if a <= modulus
//****************************************************************************************
#ifdef __WINDOWS__
LEAF_ENTRY fpneg256_a, _TEXT00
#else
.global fpneg256_a
fpneg256_a:
#endif
  xor  rax, rax
  mov  reg_p4, [reg_p1]     // a = modulus - a
  sub  reg_p4, [reg_p2]
  mov  [reg_p2], reg_p4
  mov  reg_p4, [reg_p1+8]      
  sbb  reg_p4, [reg_p2+8]
  mov  [reg_p2+8], reg_p4
  mov  reg_p4, [reg_p1+16]      
  sbb  reg_p4, [reg_p2+16]
  mov  [reg_p2+16], reg_p4
  mov  reg_p4, [reg_p1+24]      
  sbb  reg_p4, [reg_p2+24]
  mov  [reg_p2+24], reg_p4
  
  setnb  al
  ret
#ifdef __WINDOWS__
LEAF_END fpneg256_a, _TEXT00
#endif


//*******************************************************************************************************************************
// (Constant-time) Evaluation for the complete addition
// Operation: if [reg_p1] = 0 (P=-Q) then index=0, if [reg_p2] = 0 (P infinity) then index=1, if [reg_p3] = 0 (P=Q) then index=2, 
//            else index=3
// Output:    if index(rax)=3 then mask [reg_p4] = 0xff...ff, else mask [reg_p4] = 0  
//*******************************************************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_eval_numsp256d1_a, _TEXT00
  rex_push_reg   reg_x1
  END_PROLOGUE
#else
.global complete_eval_numsp256d1_a
complete_eval_numsp256d1_a:
#endif

  xor    rax, rax
  mov    r11, 3             // index 3 (P+Q) 
  mov    reg_x1, [reg_p1]
  mov    r10, [reg_p1+8]
  or     reg_x1, r10
  mov    r10, [reg_p1+16]
  or     reg_x1, r10
  mov    r10, [reg_p1+24]
  or     reg_x1, r10
  cmovnz rax, r11           // index 0 (P=-Q) if [reg_p1]=0
  
  mov    r11, 2         
  mov    r10, [reg_p3]
  or     reg_x1, r10
  mov    r10, [reg_p3+8]
  or     reg_x1, r10
  mov    r10, [reg_p3+16]
  or     reg_x1, r10
  mov    r10, [reg_p3+24]
  or     reg_x1, r10
  cmovz  rax, r11           // index 2 (P=Q) if [reg_p1] & [reg_p3]=0
  
  mov    r11, 1        
  mov    reg_x1, [reg_p2]
  mov    r10, [reg_p2+8]
  or     reg_x1, r10
  mov    r10, [reg_p2+16]
  or     reg_x1, r10
  mov    r10, [reg_p2+24]
  or     reg_x1, r10
  cmovz  rax, r11           // index 1 (P infinity) if [reg_p2]=0

  xor    reg_p1, reg_p1
  mov    r10, 18446744073709551615
  mov    r11, rax
  sub    r11, 3
  cmovz  reg_p1, r10        // mask = 0xff...f if index=3, else mask = 0
  mov    [reg_p4], reg_p1

#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop    reg_x1
  ret
NESTED_END complete_eval_numsp256d1_a, _TEXT00
#else
  ret
#endif


//*****************************************************************************************************************
// (Constant-time) Field element selection for the complete addition
// Operation: if (reg_p4)=0 then c [reg_p3] = a [reg_p1], else if (reg_p4) = 0xff...ff then c [reg_p3] = b [reg_p2]
//*****************************************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_select_numsp256d1_a, _TEXT00
  alloc_stack   8
  END_PROLOGUE
#else
.global complete_select_numsp256d1_a
complete_select_numsp256d1_a:
  sub           rsp, 8
#endif

  mov           [rsp], reg_p4
  vbroadcastss  ymm0, DWORD PTR [rsp]
  vmovdqu       ymm1, YMMWORD PTR [reg_p1]     // ymm1=a
  vmovdqu       ymm2, YMMWORD PTR [reg_p2]     // ymm2=b
  vblendvpd     ymm3, ymm1, ymm2, ymm0         // if ymm0=0 then ymm3=a else ymm3=b 
  vmovdqu       YMMWORD PTR [reg_p3], ymm3
  add           rsp, 8

#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  ret
NESTED_END complete_select_numsp256d1_a, _TEXT00
#else
  ret
#endif


//****************************************************************************************
// (Constant-time) Point extraction from 4-LUT for the complete mixed addition
// Operation: use index (reg_p2) to extract point from [reg_p1] and pass it to [reg_p3]
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_lut4_numsp256d1_a, _TEXT00
  alloc_stack   8
  END_PROLOGUE
#else
.global complete_lut4_numsp256d1_a
complete_lut4_numsp256d1_a: 
  sub          rsp, 8
#endif

  xor          rax, rax  
  mov          r11, 18446744073709551615 
  
  vmovdqu      ymm0, YMMWORD PTR [reg_p1]        // Load table[0]
  vmovdqu      ymm1, YMMWORD PTR [reg_p1+32]
  vmovdqu      ymm2, YMMWORD PTR [reg_p1+64]

  dec          reg_p2                            // Pass over table[1]
  cmovnz       rax, r11
  mov          [rsp], rax
  vbroadcastss ymm4, DWORD PTR [rsp]
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+96]
  vblendvpd    ymm0, ymm5, ymm0, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+128]
  vblendvpd    ymm1, ymm5, ymm1, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+160]
  vblendvpd    ymm2, ymm5, ymm2, ymm4
  
  xor          rax, rax                          // Pass over table[2]
  dec          reg_p2
  cmovnz       rax, r11
  mov          [rsp], rax
  vbroadcastss ymm4, DWORD PTR [rsp]
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+192]
  vblendvpd    ymm0, ymm5, ymm0, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+224]
  vblendvpd    ymm1, ymm5, ymm1, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+256]
  vblendvpd    ymm2, ymm5, ymm2, ymm4
  
  xor          rax, rax                          // Pass over table[3]
  dec          reg_p2
  cmovz        r11, rax
  mov          [rsp], r11
  vbroadcastss ymm4, DWORD PTR [rsp]
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+288]
  vblendvpd    ymm0, ymm5, ymm0, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+320]
  vblendvpd    ymm1, ymm5, ymm1, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+352]
  vblendvpd    ymm2, ymm5, ymm2, ymm4
    
  vmovdqu      YMMWORD PTR [reg_p3], ymm0        // [reg_p3] = table[index]
  vmovdqu      YMMWORD PTR [reg_p3+32], ymm1
  vmovdqu      YMMWORD PTR [reg_p3+64], ymm2
  add          rsp, 8

#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  ret
NESTED_END complete_lut4_numsp256d1_a, _TEXT00
#else
  ret
#endif


//****************************************************************************************
// (Constant-time) Point extraction from 5-LUT for the complete addition
// Operation: use index (reg_p2) to extract point from [reg_p1] and pass it to [reg_p3]
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_lut5_numsp256d1_a, _TEXT00
  alloc_stack   8
  END_PROLOGUE
#else
.global complete_lut5_numsp256d1_a
complete_lut5_numsp256d1_a:
  sub          rsp, 8
#endif

  xor          rax, rax  
  mov          r11, 18446744073709551615  
  
  vmovdqu      ymm0, YMMWORD PTR [reg_p1]        // Load table[0]
  vmovdqu      ymm1, YMMWORD PTR [reg_p1+32]
  vmovdqu      ymm2, YMMWORD PTR [reg_p1+64]

  dec          reg_p2                            // Pass over table[1]
  cmovnz       rax, r11
  mov          [rsp], rax
  vbroadcastss ymm4, DWORD PTR [rsp]
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+96]
  vblendvpd    ymm0, ymm5, ymm0, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+128]
  vblendvpd    ymm1, ymm5, ymm1, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+160]
  vblendvpd    ymm2, ymm5, ymm2, ymm4
  
  xor          rax, rax                          // Pass over table[2]
  dec          reg_p2
  cmovnz       rax, r11
  mov          [rsp], rax
  vbroadcastss ymm4, DWORD PTR [rsp]
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+192]
  vblendvpd    ymm0, ymm5, ymm0, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+224]
  vblendvpd    ymm1, ymm5, ymm1, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+256]
  vblendvpd    ymm2, ymm5, ymm2, ymm4
  
  xor          rax, rax                          // Pass over table[3]
  dec          reg_p2
  cmovnz       rax, r11
  mov          [rsp], rax
  vbroadcastss ymm4, DWORD PTR [rsp]
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+288]
  vblendvpd    ymm0, ymm5, ymm0, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+320]
  vblendvpd    ymm1, ymm5, ymm1, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+352]
  vblendvpd    ymm2, ymm5, ymm2, ymm4
  
  xor          rax, rax                          // Pass over table[4]
  dec          reg_p2
  cmovz        r11, rax
  mov          [rsp], r11
  vbroadcastss ymm4, DWORD PTR [rsp]
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+384]
  vblendvpd    ymm0, ymm5, ymm0, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+416]
  vblendvpd    ymm1, ymm5, ymm1, ymm4
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+448]
  vblendvpd    ymm2, ymm5, ymm2, ymm4
    
  vmovdqu      YMMWORD PTR [reg_p3], ymm0        // [reg_p3] = table[index]
  vmovdqu      YMMWORD PTR [reg_p3+32], ymm1
  vmovdqu      YMMWORD PTR [reg_p3+64], ymm2
  add          rsp, 8
  
#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  ret
NESTED_END complete_lut5_numsp256d1_a, _TEXT00
#else
  ret
#endif


//****************************************************************************************
// Zeroing field element
//****************************************************************************************
#ifdef __WINDOWS__
LEAF_ENTRY fpzero256_a, _TEXT00
#else
.global fpzero256_a
fpzero256_a:
#endif
  xor          rax, rax
  mov          [reg_p1], rax
  mov          [reg_p1+8], rax 
  mov          [reg_p1+16], rax
  mov          [reg_p1+24], rax 
  ret
#ifdef __WINDOWS__
LEAF_END fpzero256_a, _TEXT00
#endif


#ifdef __WINDOWS__
END
#endif
