//***********************************************************************************
// FourQ: 4-dimensional decomposition on a Q-curve with CM in twisted Edwards form
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
// Abstract: arithmetic over GF(p^2) using x64 assembly for Linux with AVX2 support
//
// This code is based on the paper "FourQ: four-dimensional decompositions on a 
// Q-curve over the Mersenne prime" by Craig Costello and Patrick Longa, in Advances 
// in Cryptology - ASIACRYPT, 2015.
// Preprint available at http://eprint.iacr.org/2015/565.
//***********************************************************************************

.intel_syntax noprefix 

// Registers that are used for parameter passing:
#define reg_p1  rdi
#define reg_p2  rsi
#define reg_p3  rdx

#define mask63  0x7FFFFFFFFFFFFFFF


.text
//***********************************************************************
//  Quadratic extension field multiplication using lazy reduction
//  Based on schoolbook method
//  Operation: c [reg_p3] = a [reg_p1] * b [reg_p2] mod p, p = 2^127-1
//  NOTE: only a=c is allowed for fp2mul1271_a(a, b, c)
//*********************************************************************** 
.global fp2mul1271_a
fp2mul1271_a:
  mov    rcx, reg_p3 

  // T0 = a0 * b0, (r11, r10, r9, r8) <- [reg_p1_0-8] * [reg_p2_0-8]
  mov    rdx, [reg_p2]	
  mulx   r9, r8, [reg_p1]
  mulx   rax, r10, [reg_p1+8] 
  push   r15
  push   r14
  add    r9, r10
  mov    rdx, [reg_p2+8]
  mulx   r11, r10, [reg_p1+8]
  push   r13
  push   r12
  adc    r10, rax
  mulx   rax, rdx, [reg_p1]
  adc    r11, 0
  add    r9, rdx

  // T1 = a1 * b1, (r15, r14, r13, r12) <- [reg_p1_16-24] * [reg_p2_16-24]
  mov    rdx, [reg_p2+16]
  mulx   r13, r12, [reg_p1+16]
  adc    r10, rax
  mulx   rax, r14, [reg_p1+24] 
  adc    r11, 0  
  mov    rdx, [reg_p2+24]
  add    r13, r14
  mulx   r15, r14, [reg_p1+24]
  adc    r14, rax
  adc    r15, 0
  mulx   rax, rdx, [reg_p1+16] 
  add    r13, rdx
  adc    r14, rax
  adc    r15, 0  

  // c0 = T0 - T1 = a0*b0 - a1*b1 
  xor    rax, rax
  sub    r8, r12
  sbb    r9, r13
  sbb    r10, r14
  sbb    r11, r15
  
  shld   r11, r10, 1      
  shld   r10, r9, 1
  mov    rdx, [reg_p2+16]
  btr    r9, 63

  // T0 = a0 * b1, (r15, r14, r13, r12) <- [reg_p1_0-8] * [reg_p2_16-24]
  mulx   r13, r12, [reg_p1]
  btr    r11, 63           // Add prime if borrow=1
  sbb    r10, 0
  sbb    r11, 0
  mulx   rax, r14, [reg_p1+8] 
  add    r13, r14
  mov    rdx, [reg_p2+24]
  mulx   r15, r14, [reg_p1+8]
  adc    r14, rax
  adc    r15, 0
  mulx   rax, rdx, [reg_p1] 
  add    r13, rdx
  adc    r14, rax
  adc    r15, 0  

  // Reducing and storing c0
  add    r10, r8
  adc    r11, r9
  btr    r11, 63
  adc    r10, 0
  adc    r11, 0

  // T1 = a1 * b0, (r12, r11, r10, r9) <- [reg_p1_16-24] * [reg_p2_0-8]	  
  mov    rdx, [reg_p2]
  mulx   r9, r8, [reg_p1+16]
  mov    [rcx], r10
  mulx   rax, r10, [reg_p1+24] 
  mov    [rcx+8], r11
  add    r9, r10
  mov    rdx, [reg_p2+8]
  mulx   r11, r10, [reg_p1+24]
  adc    r10, rax
  adc    r11, 0
  mulx   rax, rdx, [reg_p1+16]
  add    r9, rdx
  adc    r10, rax
  adc    r11, 0  

  // c1 = T0 + T1 = a0*b1 + a1*b0 
  add    r8, r12
  pop    r12
  adc    r9, r13
  pop    r13
  adc    r10, r14
  pop    r14
  adc    r11, r15
  pop    r15

  // Reducing and storing c1
  shld   r11, r10, 1 
  shld   r10, r9, 1
  btr    r11, 63
  adc    r10, 0
  adc    r11, 0
  btr    r9, 63
  
  add    r8, r10
  adc    r9, r11
  btr    r9, 63
  adc    r8, 0
  adc    r9, 0
  mov    [rcx+16], r8
  mov    [rcx+24], r9
  ret


//***********************************************************************
//  Quadratic extension field squaring
//  Operation: c [reg_p2] = a^2 [reg_p1] mod p, p = 2^127-1
//  NOTE: a=c is not allowed for fp2sqr1271_a(a, c)
//*********************************************************************** 
.global fp2sqr1271_a
fp2sqr1271_a:
  push   r14

  // t0 = (r9, r8) = a0 + a1, (rcx, r14) <- a1
  mov    r8,  [reg_p1]
  mov    r14, [reg_p1+16]
  add    r8, r14
  mov    r9,  [reg_p1+8]
  mov    rcx, [reg_p1+24]
  adc    r9, rcx
  
  // t1 = (r11, r10) = a0 - a1
  mov    r10, [reg_p1]
  sub    r10, r14
  mov    r11, [reg_p1+8]
  sbb    r11, rcx

  btr    r11, 63
  sbb    r10, 0
  push   r13
  push   r12
  sbb    r11, 0
  
  btr    r9, 63
  mov    rdx, r10
  adc    r8, 0

  //  c0 = t0 * t1 = (a0 + a1)*(a0 - a1), (rcx, r14, r13, r12) <- (r9, r8) * (r11, r10)
  mulx   r13, r12, r8
  adc    r9, 0
  mulx   rax, r14, r9 
  mov    rdx, r11
  add    r13, r14
  mulx   rcx, r14, r9
  mov    r9, [reg_p1+8]
  adc    r14, rax
  adc    rcx, 0
  mulx   rax, rdx, r8 
  mov    r8, [reg_p1]
  add    r13, rdx
  adc    r14, rax
  adc    rcx, 0  

  // t2 = (r9, r8) = 2*a0
  add    r8, r8
  adc    r9, r9
  
  btr    r9, 63
  adc    r8, 0
  adc    r9, 0
  
  // Reducing and storing c0
  shld   rcx, r14, 1   
  shld   r14, r13, 1
  btr    r13, 63
  add    r12, r14
  adc    r13, rcx
  btr    r13, 63
  adc    r12, 0
  adc    r13, 0
  mov    [reg_p2], r12
  mov    [reg_p2+8], r13

  //  c1 = 2a0 * a1, (rcx, r14, r11, r10) <- (r9, r8) * [reg_p1_16-24] 
  mov    rdx, [reg_p1+16]
  mulx   r11, r10, r8
  pop    r12
  mulx   rax, r14, r9 
  pop    r13
  add    r11, r14
  mov    rdx, [reg_p1+24]
  mulx   rcx, r14, r9
  adc    r14, rax
  adc    rcx, 0
  mulx   rax, rdx, r8 
  add    r11, rdx
  adc    r14, rax
  adc    rcx, 0  
  
  // Reducing and storing c1
  shld   rcx, r14, 1  
  shld   r14, r11, 1
  btr    r11, 63
  add    r10, r14
  adc    r11, rcx
  btr    r11, 63
  pop    r14
  adc    r10, 0
  adc    r11, 0
  mov    [reg_p2+16], r10
  mov    [reg_p2+24], r11
  ret


//***********************************************************************
//  Quadratic extension field addition/subtraction
//  Operation: c [reg_p3] = 2*a [reg_p1] - b [reg_p2] mod p, p = 2^127-1
//*********************************************************************** 
.global fp2addsub1271_a
fp2addsub1271_a:
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  add    r8, r8
  adc    r9, r9  
  btr    r9, 63
  adc    r8, 0
  adc    r9, 0
  
  mov    r10, [reg_p2]
  sub    r8, r10
  mov    r10, [reg_p2+8]
  sbb    r9, r10  
  btr    r9, 63
  sbb    r8, 0
  mov    [reg_p3], r8
  sbb    r9, 0
  mov    [reg_p3+8], r9

  mov    r8, [reg_p1+16]
  mov    r9, [reg_p1+24]
  add    r8, r8
  adc    r9, r9  
  btr    r9, 63
  adc    r8, 0
  adc    r9, 0
  
  mov    r10, [reg_p2+16]
  sub    r8, r10
  mov    r10, [reg_p2+24]
  sbb    r9, r10  
  btr    r9, 63
  sbb    r8, 0
  mov    [reg_p3+16], r8
  sbb    r9, 0
  mov    [reg_p3+24], r9
  ret
