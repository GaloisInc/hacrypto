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
// Abstract: field operations over GF(2^384-317) in x64 assembly.
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
// Operation: c [reg_p3] = a [reg_p1] * b [reg_p2] mod p, p = 2^384-317
// NOTE: input should have reg_p3 != reg_p1 and reg_p3 != reg_p2 
// Inputs: a, b in [0, p-1]
// Output: c in [0, p-1] 
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpmul384_a, _TEXT00
    rex_push_reg rbx
    push_reg     reg_x1
    push_reg     reg_x2
    push_reg     r12
    push_reg     r13
  END_PROLOGUE
#else
.global fpmul384_a
fpmul384_a:
    push         rbx
    push         r12
    push         r13
  #endif

  mov  rbx, reg_p2          // Save rbx<-rdx (in Windows)
  mov  reg_x2, reg_p3       // Save r9 <-rdx (in Linux) 
  
  mov  rax, [rbx]
  mul qword ptr [reg_p1]    // a0*b0
  mov  [reg_x2], rax        // C0
  mov  reg_p4, rdx  
  mov  reg_aux, [reg_p1+8]         
  
  xor  r11, r11
  mov  rax, [rbx]
  mul  reg_aux              // a1*b0
  add  reg_p4, rax
  mov  r10, rdx
  adc  r10, 0

  mov  rax, [rbx+8]         // a0*b1
  mul qword ptr [reg_p1]
  add  reg_p4, rax
  adc  r10, rdx
  adc  r11, 0
  mov  [reg_x2+8], reg_p4   // C1

  xor  reg_p4, reg_p4    
  mov  rax, [rbx]
  mul qword ptr [reg_p1+16] // a2*b0
  add  r10, rax
  adc  r11, rdx
  //adc  reg_p4, 0

  mov  rax, [rbx+8]
  mul  reg_aux              // a1*b1
  add  r10, rax
  adc  r11, rdx
  adc  reg_p4, 0

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
  adc  r10, 0

  mov  rax,[rbx+8]
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
  adc  r10,0

  xor  r11, r11
  mov  rax, [rbx+8]
  mul qword ptr [reg_p1+24] // a3*b1
  add  reg_p4, rax
  adc  r10, rdx
  adc  r11, 0

  mov  rax, [rbx+32]
  mul qword ptr [reg_p1]    // a0*b4
  add  reg_p4, rax
  adc  r10, rdx
  adc  r11, 0

  mov  rax, [rbx]
  mul qword ptr [reg_p1+32] // a4*b0
  add  reg_p4, rax
  adc  r10, rdx
  adc  r11, 0

  mov  rax, [rbx+16]
  mul qword ptr [reg_p1+16] // a2*b2
  add  reg_p4, rax
  adc  r10, rdx
  adc  r11, 0

  mov  rax, [rbx+24]
  mul  reg_aux              // a1*b3
  add  reg_p4, rax
  mov  [reg_x2+32], reg_p4  // C4
  adc  r10, rdx
  adc  r11, 0

  xor  reg_p4, reg_p4
  mov  rax, [rbx+16]
  mul qword ptr [reg_p1+24] // a3*b2
  add  r10, rax
  adc  r11, rdx
  adc  reg_p4, 0

  mov  rax, [rbx+32]
  mul  reg_aux              // a1*b4
  add  r10, rax
  adc  r11, rdx
  adc  reg_p4, 0

  mov  rax, [rbx+8]
  mul qword ptr [reg_p1+32] // a4*b1
  add  r10, rax
  adc  r11, rdx
  adc  reg_p4, 0

  mov  rax, [rbx+40]
  mul qword ptr [reg_p1]    // a0*b5
  add  r10, rax
  adc  r11, rdx
  adc  reg_p4, 0

  mov  rax, [rbx]
  mul qword ptr [reg_p1+40] // a5*b0
  add  r10, rax
  adc  r11, rdx
  adc  reg_p4, 0

  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+16] // a2*b3
  add  r10, rax          
  mov  [reg_x2+40], r10     // C5
  adc  r11, rdx
  adc  reg_p4, 0
  
  xor  r10, r10
  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+24] // a3*b3
  add  r11, rax          
  adc  reg_p4, rdx        
  adc  r10, 0    
  
  mov  rax, [rbx+32]
  mul qword ptr [reg_p1+16] // a2*b4
  add  r11, rax          
  adc  reg_p4, rdx        
  adc  r10, 0     
  
  mov  rax, [rbx+16]
  mul qword ptr [reg_p1+32] // a4*b2
  add  r11, rax          
  adc  reg_p4, rdx        
  adc  r10, 0        
  
  mov  rax, [rbx+40]
  mul  reg_aux              // a1*b5
  add  r11, rax          
  adc  reg_p4, rdx        
  adc  r10, 0           
  
  mov  rax, [rbx+8]
  mul qword ptr [reg_p1+40] // a5*b1
  add  r11, rax             // r11 = C6        
  adc  reg_p4, rdx        
  adc  r10, 0   
  
  xor  r12, r12
  mov  rax, [rbx+40]
  mul qword ptr [reg_p1+16] // a2*b5
  add  reg_p4, rax          
  adc  r10, rdx        
  adc  r12, 0    

  mov  rax, [rbx+16]
  mul qword ptr [reg_p1+40] // a5*b2
  add  reg_p4, rax          
  adc  r10, rdx        
  adc  r12, 0       

  mov  rax, [rbx+32]
  mul qword ptr [reg_p1+24] // a3*b4
  add  reg_p4, rax          
  adc  r10, rdx        
  adc  r12, 0         

  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+32] // a4*b3
  add  reg_p4, rax          // reg_p4 = C7         
  adc  r10, rdx        
  adc  r12, 0     
  
  xor  r13, r13
  mov  rax, [rbx+40]
  mul qword ptr [reg_p1+24] // a3*b5
  add  r10, rax          
  adc  r12, rdx        
  adc  r13, 0     
  
  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+40] // a5*b3
  add  r10, rax          
  adc  r12, rdx        
  adc  r13, 0          

  mov  rax, [rbx+32]
  mul qword ptr [reg_p1+32] // a4*b4
  add  r10, rax             // r10 = C8         
  adc  r12, rdx        
  adc  r13, 0         
  
  xor  reg_aux, reg_aux
  mov  rax, [rbx+40]
  mul qword ptr [reg_p1+32] // a4*b5
  add  r12, rax          
  adc  r13, rdx        
  adc  reg_aux, 0            

  mov  rax, [rbx+32]
  mul qword ptr [reg_p1+40] // a5*b4
  add  r12, rax             // r12 = C9         
  adc  r13, rdx        
  adc  reg_aux, 0               

  mov  rax, [rbx+40]
  mul qword ptr [reg_p1+40] // a5*b5
  add  r13, rax             // r13 = C10          
  adc  reg_aux, rdx         // reg_aux = C11                         

// Reduction

  mov  rax, P384_c
  mul  r11 
  mov  r11, [reg_x2]
  add  r11, rax             // r11 = partial0
  adc  rdx, 0    
  mov  reg_x1, rdx 

  xor  rbx, rbx
  mov  rax, P384_c
  mul  reg_p4 
  add  rax, reg_x1 
  adc  rbx, 0 
  mov  reg_p4, [reg_x2+8]    
  add  reg_p4, rax          // reg_p4 = partial1
  adc  rbx, rdx 

  xor  reg_x1, reg_x1
  mov  rax, P384_c
  mul  r10 
  add  rax, rbx  
  adc  reg_x1, 0   
  mov  r10, [reg_x2+16]    
  add  r10, rax             // r10 = partial2
  adc  reg_x1, rdx  

  xor  rbx, rbx
  mov  rax, P384_c
  mul  r12 
  add  rax, reg_x1 
  adc  rbx, 0 
  mov  r12, [reg_x2+24]    
  add  r12, rax             // r12 = partial3
  adc  rbx, rdx 

  xor  reg_x1, reg_x1
  mov  rax, P384_c
  mul  r13 
  add  rax, rbx  
  adc  reg_x1, 0   
  mov  r13, [reg_x2+32]    
  add  r13, rax             // r13 = partial4
  adc  reg_x1, rdx  

  xor  rbx, rbx
  mov  rax, P384_c
  mul  reg_aux 
  add  rax, reg_x1 
  adc  rbx, 1 
  mov  reg_aux, [reg_x2+40]    
  add  reg_aux, rax         // reg_aux = partial5
  adc  rdx, rbx             // rdx = partial4 + 1 
  
  xor  rbx, rbx
  mov  rax, P384_c         
  mul  rdx   
  add  r11, rax             // r11 = partial0     
  adc  reg_p4, 0            // reg_p4 = partial1
  adc  r10, 0               // r10 = partial2
  adc  r12, 0               // r12 = partial4
  adc  r13, 0               // r13 = partial5
  adc  reg_aux, 0           // reg_aux = partial6
  
  mov  rax, P384_c          // final correction
  cmovc rax, rbx
  sub  r11, rax
  mov  [reg_x2], r11  
  sbb  reg_p4, 0
  mov  [reg_x2+8], reg_p4 
  sbb  r10, 0
  mov  [reg_x2+16], r10  
  sbb  r12, 0
  mov  [reg_x2+24], r12 
  sbb  r13, 0
  mov  [reg_x2+32], r13 
  sbb  reg_aux, 0
  mov  [reg_x2+40], reg_aux 

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
NESTED_END fpmul384_a, _TEXT00
#else
  pop r13
  pop r12
  pop rbx
  ret
#endif


//****************************************************************************************
// (Constant-time) field squaring using integer multiplication by product scanning
// Operation: c [reg_p2] = a [reg_p1]^2 mod p, p = 2^384-317
// NOTE: input should have reg_p2 != reg_p1 
// Input:  a in [0, p-1]
// Output: c in [0, p-1] 
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpsqr384_a, _TEXT00
  rex_push_reg rbx
  push_reg     reg_x1
  push_reg     reg_x2
  push_reg     r12
  push_reg     r13
  push_reg     r14
  END_PROLOGUE
#else 
.global fpsqr384_a
fpsqr384_a:
  push         rbx
  push         r12
  push         r13
  push         r14
#endif

  mov  rbx, reg_p2          // Save rbx<-rdx (in Windows)
  mov  reg_x2, reg_p3       // Save r9 <-rdx (in Linux) 

  xor  r10, r10
  mov  reg_aux, [reg_p1+16] 
  mov  rax, [reg_p1]
  mul qword ptr [reg_p1+8]   
  add  rax, rax
  mov  reg_x2, rax
  adc  rdx, rdx
  mov  reg_p4, rdx
  adc  r10, 0               // 2*a0*a1

  mov  rax, [reg_p1]
  mul  rax                  // a0^2
  mov  [rbx], rax           // C0
  add  reg_x2, rdx
  mov  [rbx+8], reg_x2      // C1
  adc  reg_p4, 0

  xor  r11, r11
  mov  rax, [reg_p1]
  mul  reg_aux 
  add  rax, rax
  mov  reg_x2, rax
  adc  rdx, rdx
  mov  r14, rdx
  adc  r11, 0               // 2*a0*a2

  mov  rax, [reg_p1+8]
  mul  rax                  // a1^2
  add  reg_x2, rax
  adc  r14, rdx
  adc  r11, 0

  mov  rax, [reg_p1]
  mul qword ptr [reg_p1+24] // a0*a3
  add  reg_x2, reg_p4
  mov  [rbx+16], reg_x2     // C2
  adc  r14, r10
  adc  r11, 0
  mov  reg_x2, rax
  mov  r10, rdx
  
  xor  reg_p4, reg_p4 
  mov  rax, [reg_p1+8]
  mul  reg_aux              // a1*a2
  add  reg_x2, rax
  adc  r10, rdx
  adc  reg_p4, 0
  add  reg_x2, reg_x2
  adc  r10, r10
  adc  reg_p4, reg_p4       // 2(a0*a3 + a1*a2)

  mov  rax, [reg_p1+8]
  mul qword ptr [reg_p1+24] // a1*a3
  add  reg_x2, r14
  mov  [rbx+24], reg_x2     // C3
  adc  r10, r11
  adc  reg_p4, 0
  xor  r11, r11
  mov  reg_x2, rax
  mov  r14, rdx

  mov  rax, [reg_p1+32]
  mul qword ptr [reg_p1]    // a0*a4
  add  reg_x2, rax
  adc  r14, rdx
  adc  r11, 0
  add  reg_x2, reg_x2              
  adc  r14, r14
  adc  r11, r11             // 2(a1*a3 + a0*a4)

  mov  rax, reg_aux
  mul  reg_aux              // a2^2
  add  r10, reg_x2
  adc  r14, reg_p4
  adc  r11, 0
  add  r10, rax             // C4
  mov  [rbx+32], r10
  adc  r14, rdx
  adc  r11, 0

  mov  rax, [reg_p1+24]
  mul  reg_aux              // a2*a3
  xor  reg_p4, reg_p4
  mov  reg_x2, rax
  mov  r10, rdx

  mov  rax, [reg_p1+32]
  mul qword ptr [reg_p1+8]  // a1*a4
  add  reg_x2, rax
  adc  r10, rdx
  adc  reg_p4, 0

  mov  rax, [reg_p1+40]
  mul qword ptr [reg_p1]    // a0*a5
  add  reg_x2, rax
  adc  r10, rdx
  adc  reg_p4, 0
  add  reg_x2, reg_x2              
  adc  r10, r10
  adc  reg_p4, reg_p4       // 2(a2*a3 + a1*a4 + a0*a5)

  mov  rax, [reg_p1+40]
  mul qword ptr [reg_p1+8]  // a1*a5
  add  r14, reg_x2          // C5
  mov  [rbx+40], r14
  adc  r11, r10
  adc  reg_p4, 0
  xor  r14, r14
  mov  reg_x2, rax
  mov  r10, rdx

  mov  rax, [reg_p1+32]
  mul  reg_aux              // a2*a4
  add  reg_x2, rax
  adc  r10, rdx
  adc  r14, 0
  add  reg_x2, reg_x2              
  adc  r10, r10
  adc  r14, r14             // 2(a2*a4 + a1*a5)

  mov  rax, [reg_p1+24]
  mul  rax                  // a3^2
  add  r11, reg_x2             
  adc  reg_p4, r10
  adc  r14, 0
  add  r11, rax             // r11 = C6
  adc  reg_p4, rdx
  adc  r14, 0

  mov  rax, [reg_p1+40]
  mul  reg_aux              // a2*a5
  xor  r12, r12
  mov  reg_x2, rax
  mov  r10, rdx

  mov  rax, [reg_p1+32]
  mul qword ptr [reg_p1+24] // a3*a4
  add  reg_x2, rax             
  adc  r10, rdx
  adc  r12, 0
  add  reg_x2, reg_x2        
  adc  r10, r10
  adc  r12, r12             // 2(a2*a5 + a3*a4)
    
  xor  r13, r13
  mov  rax, [reg_p1+40]
  mul qword ptr [reg_p1+24] 
  add  reg_p4, reg_x2       // reg_p4 = C7
  adc  r10, r14
  adc  r12, 0
  add  rax, rax  
  mov  reg_x2, rax            
  adc  rdx, rdx
  mov  r14, rdx
  adc  r13, 0               // 2a3*a5

  mov  rax, [reg_p1+32]
  mul  rax                  // a4^2
  add  reg_x2, rax             
  adc  r14, rdx
  adc  r13, 0
  add  r10, reg_x2          // r10 = C8
  adc  r12, r14
  adc  r13, 0
   
  xor  r14, r14
  mov  rax, [reg_p1+40]
  mul qword ptr [reg_p1+32] // a4*a5
  add  rax, rax             
  adc  rdx, rdx
  adc  r14, 0
  add  r12, rax             // r12 = C9
  adc  r13, rdx
  adc  r14, 0

  mov  rax, [reg_p1+40]
  mul  rax                  // a5^2
  add  r13, rax             // r13 = C10 
  adc  r14, rdx             // r14 = C11

// Reduction  

  mov  rax, P384_c
  mul  r11 
  mov  r11, [rbx]
  add  r11, rax            // r11 = partial0
  adc  rdx, 0    
  mov  reg_x1, rdx 

  xor  reg_aux, reg_aux
  mov  rax, P384_c
  mul  reg_p4 
  add  rax, reg_x1 
  adc  reg_aux, 0 
  mov  reg_p4, [rbx+8]    
  add  reg_p4, rax         // reg_p4 = partial1
  adc  reg_aux, rdx 

  xor  reg_x1, reg_x1
  mov  rax, P384_c
  mul  r10 
  add  rax, reg_aux  
  adc  reg_x1, 0   
  mov  r10, [rbx+16]    
  add  r10, rax             // r10 = partial2
  adc  reg_x1, rdx  

  xor  reg_aux, reg_aux
  mov  rax, P384_c
  mul  r12 
  add  rax, reg_x1 
  adc  reg_aux, 0 
  mov  r12, [rbx+24]    
  add  r12, rax             // r12 = partial3
  adc  reg_aux, rdx 

  xor  reg_x1, reg_x1
  mov  rax, P384_c
  mul  r13 
  add  rax, reg_aux  
  adc  reg_x1, 0   
  mov  r13, [rbx+32]    
  add  r13, rax             // r13 = partial4
  adc  reg_x1, rdx  

  xor  reg_aux, reg_aux
  mov  rax, P384_c
  mul  r14 
  add  rax, reg_x1 
  adc  reg_aux, 1 
  mov  r14, [rbx+40]    
  add  r14, rax             // r14 = partial5
  adc  rdx, reg_aux         // rdx = partial6 + 1 
  
  xor  reg_aux, reg_aux
  mov  rax, P384_c         
  mul  rdx   
  add  r11, rax             // r11 = partial0     
  adc  reg_p4, 0            // reg_p4 = partial1
  adc  r10, 0               // r10 = partial2
  adc  r12, 0               // r12 = partial4
  adc  r13, 0               // r13 = partial5
  adc  r14, 0               // r14 = partial6
  
  mov  rax, P384_c          // final correction
  cmovc rax, reg_aux
  sub  r11, rax
  mov  [rbx], r11  
  sbb  reg_p4, 0
  mov  [rbx+8], reg_p4 
  sbb  r10, 0
  mov  [rbx+16], r10  
  sbb  r12, 0
  mov  [rbx+24], r12 
  sbb  r13, 0
  mov  [rbx+32], r13 
  sbb  r14, 0
  mov  [rbx+40], r14 
  
#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop  r14
  pop  r13
  pop  r12
  pop  reg_x2
  pop  reg_x1
  pop  rbx
  ret
NESTED_END fpsqr384_a, _TEXT00
#else
  pop  r14
  pop  r13
  pop  r12
  pop  rbx
  ret
#endif


//*********************************************************************
// (Constant-time) field addition 
// Operation: c [reg_p3] = a [reg_p1] + b [reg_p2] mod p, p = 2^384-317
// Input:  a, b in [0, p-1]
// Output: c in [0, p-1]
//*********************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpadd384_a, _TEXT00
  rex_push_reg r12
  push_reg     reg_x1
  push_reg     reg_x2
  END_PROLOGUE
#else
.global fpadd384_a
fpadd384_a:
  push r12
#endif

  mov  reg_p4, [reg_p1]     // a + P384_c
  add  reg_p4, P384_c
  mov  r10, [reg_p1+8]
  adc  r10, 0
  mov  r11, [reg_p1+16]
  adc  r11, 0
  mov  r12, [reg_p1+24]
  adc  r12, 0
  mov  reg_x1, [reg_p1+32]
  adc  reg_x1, 0
  mov  reg_x2, [reg_p1+40]
  adc  reg_x2, 0
  
  mov  reg_p1, [reg_p2]     // (a+P384_c) + b 
  add  reg_p4, reg_p1
  mov  reg_p1, [reg_p2+8]
  adc  r10, reg_p1
  mov  reg_p1, [reg_p2+16]
  adc  r11, reg_p1
  mov  reg_p1, [reg_p2+24]
  adc  r12, reg_p1
  mov  reg_p1, [reg_p2+32]
  adc  reg_x1, reg_p1
  mov  reg_p1, [reg_p2+40]
  adc  reg_x2, reg_p1
  
  mov  reg_p2, 0            // if (carry) then c = (a+P384_c) + b
  mov  reg_p1, P384_c       // else c = (a+P384_c) + b - P384_c
  cmovc reg_p1, reg_p2
  sub  reg_p4, reg_p1
  mov  [reg_p3], reg_p4
  sbb  r10, 0
  mov  [reg_p3+8], r10
  sbb  r11, 0
  mov  [reg_p3+16], r11
  sbb  r12, 0
  mov  [reg_p3+24], r12
  sbb  reg_x1, 0
  mov  [reg_p3+32], reg_x1
  sbb  reg_x2, 0
  mov  [reg_p3+40], reg_x2
  
#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop  reg_x2
  pop  reg_x1
  pop  r12
  ret
NESTED_END fpadd384_a, _TEXT00
#else
  pop r12
  ret
#endif


//*********************************************************************
// (Constant-time) field subtraction
// Operation: c [reg_p3] = a [reg_p1] + b [reg_p2] mod p, p = 2^384-317
// Input:  a, b in [0, p-1]
// Output: c in [0, p-1]
//*********************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpsub384_a, _TEXT00
  rex_push_reg reg_x1
  push_reg     reg_x2
  END_PROLOGUE
#else
.global fpsub384_a
fpsub384_a:
#endif
           
  mov  reg_p4, [reg_p1]     // a - b
  sub  reg_p4, [reg_p2]
  mov  r10, [reg_p1+8]
  sbb  r10, [reg_p2+8]
  mov  r11, [reg_p1+16]
  sbb  r11, [reg_p2+16]
  mov  rax, [reg_p1+24]
  sbb  rax, [reg_p2+24]
  mov  reg_x1, [reg_p1+32]
  sbb  reg_x1, [reg_p2+32]
  mov  reg_x2, [reg_p1+40]
  sbb  reg_x2, [reg_p2+40]

  mov  reg_p2, 0
  mov  reg_p1, P384_c       // if (carry) then c = (a-b) - P384_c 
  cmovnc reg_p1, reg_p2     // else c = a - b
  sub  reg_p4, reg_p1
  mov  [reg_p3], reg_p4
  sbb  r10, 0
  mov  [reg_p3+8], r10
  sbb  r11, 0
  mov  [reg_p3+16], r11
  sbb  rax, 0
  mov  [reg_p3+24], rax
  sbb  reg_x1, 0
  mov  [reg_p3+32], reg_x1
  sbb  reg_x2, 0
  mov  [reg_p3+40], reg_x2
 
#ifdef __WINDOWS__  
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop  reg_x2
  pop  reg_x1
  ret
NESTED_END fpsub384_a, _TEXT00
#else
  ret
#endif


//*********************************************************************
// (Constant-time) field division by 2 
// Operation: a [reg_p2] = a [reg_p1]/2 mod p, p = 2^384-317
// Input:  a in [0, p-1]
// Output: c in [0, p-1]
//*********************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpdiv2_384_a, _TEXT00 
    rex_push_reg    reg_x1
    push_reg        reg_x2
    push_reg        rbx
  END_PROLOGUE
#else
.global fpdiv2_384_a
fpdiv2_384_a:
  push              rbx
#endif
    xor     rbx, rbx
    mov     rax, [reg_p1]
    bt      rax, 0
    mov     reg_p3, P384_0 
    cmovnc  reg_p3, rbx
    mov     reg_p4, P384_1         // P384_1 = ... = P384_5
    cmovnc  reg_p4, rbx
    mov     r10, reg_p4  
    mov     r11, reg_p4 
    mov     reg_x1, reg_p4 
    mov     reg_x2, reg_p4 
    
    add     reg_p3, rax            // if (a mod 2 = 1) then temp = a + p
    mov     rax, [reg_p1+8]        // else temp = a + 0
    adc     reg_p4, rax
    mov     rax, [reg_p1+16]
    adc     r10, rax 
    mov     rax, [reg_p1+24]
    adc     r11, rax
    mov     rax, [reg_p1+32]
    adc     reg_x1, rax
    mov     rax, [reg_p1+40]
    adc     reg_x2, rax
    adc     rbx, 0
  
    shrd    reg_p3, reg_p4, 1      // c = temp/2
    mov     [reg_p2], reg_p3
    shrd    reg_p4, r10, 1
    mov     [reg_p2+8], reg_p4
    shrd    r10, r11, 1
    mov     [reg_p2+16], r10
    shrd    r11, reg_x1, 1
    mov     [reg_p2+24], r11    
    shrd    reg_x1, reg_x2, 1
    mov     [reg_p2+32], reg_x1    
    shrd    reg_x2, rbx, 1
    mov     [reg_p2+40], reg_x2    
#ifdef __WINDOWS__    
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
    pop     rbx
    pop     reg_x2
    pop     reg_x1
    ret
NESTED_END fpdiv2_384_a, _TEXT00
#else
    pop     rbx
    ret
#endif


//****************************************************************************************
// (Constant-time) field negation and subtraction from a modulus
// Operation: a [reg_p2] = modulus [reg_p1] - a [reg_p2]
//            if modulus = p = 2^384-317, then this performs a field negation -a (mod p)
// Input:  a in [0, modulus-1]
// Output: a in [0, modulus-1], rax = 1 (TRUE) if a <= modulus
//****************************************************************************************
#ifdef __WINDOWS__
LEAF_ENTRY fpneg384_a, _TEXT00
#else
.global fpneg384_a
fpneg384_a:
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
  mov  reg_p4, [reg_p1+32]      
  sbb  reg_p4, [reg_p2+32]
  mov  [reg_p2+32], reg_p4
  mov  reg_p4, [reg_p1+40]      
  sbb  reg_p4, [reg_p2+40]
  mov  [reg_p2+40], reg_p4
  
  setnb  al
  ret
#ifdef __WINDOWS__
LEAF_END fpneg384_a, _TEXT00
#endif


//*******************************************************************************************************************************
// (Constant-time) Evaluation for the complete addition
// Operation: if [reg_p1] = 0 (P=-Q) then index=0, if [reg_p2] = 0 (P infinity) then index=1, if [reg_p3] = 0 (P=Q) then index=2, 
//            else index=3
// Output:    if index(rax)=3 then mask [reg_p4] = 0xff...ff, else mask [reg_p4] = 0  
//*******************************************************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_eval_numsp384d1_a, _TEXT00
  rex_push_reg   reg_x1
  END_PROLOGUE
#else
.global complete_eval_numsp384d1_a
complete_eval_numsp384d1_a:
#endif

  xor    rax, rax
  mov    r11, 3              // index 3 (P+Q) 
  mov    reg_x1, [reg_p1]
  mov    r10, [reg_p1+8]
  or     reg_x1, r10
  mov    r10, [reg_p1+16]
  or     reg_x1, r10
  mov    r10, [reg_p1+24]
  or     reg_x1, r10
  mov    r10, [reg_p1+32]
  or     reg_x1, r10
  mov    r10, [reg_p1+40]
  or     reg_x1, r10
  cmovnz rax, r11            // index 0 (P=-Q) if [reg_p1]=0
  
  mov    r11, 2         
  mov    r10, [reg_p3]
  or     reg_x1, r10
  mov    r10, [reg_p3+8]
  or     reg_x1, r10
  mov    r10, [reg_p3+16]
  or     reg_x1, r10
  mov    r10, [reg_p3+24]
  or     reg_x1, r10
  mov    r10, [reg_p3+32]
  or     reg_x1, r10
  mov    r10, [reg_p3+40]
  or     reg_x1, r10
  cmovz  rax, r11            // index 2 (P=Q) if [reg_p1] & [reg_p3]=0
  
  mov    r11, 1        
  mov    reg_x1, [reg_p2]
  mov    r10, [reg_p2+8]
  or     reg_x1, r10
  mov    r10, [reg_p2+16]
  or     reg_x1, r10
  mov    r10, [reg_p2+24]
  or     reg_x1, r10
  mov    r10, [reg_p2+32]
  or     reg_x1, r10
  mov    r10, [reg_p2+40]
  or     reg_x1, r10
  cmovz  rax, r11            // index 1 (P infinity) if [reg_p2]=0

  xor    reg_p1, reg_p1
  mov    r10, 18446744073709551615
  mov    r11, rax
  sub    r11, 3
  cmovz  reg_p1, r10         // mask = 0xff...f if index=3, else mask = 0
  mov    [reg_p4], reg_p1
#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop    reg_x1
  ret
NESTED_END complete_eval_numsp384d1_a, _TEXT00
#else
  ret
#endif


//*****************************************************************************************************************
// (Constant-time) Field element selection for the complete addition
// Operation: if (reg_p4)=0 then c [reg_p3] = a [reg_p1], else if (reg_p4) = 0xff...ff then c [reg_p3] = b [reg_p2]
//*****************************************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_select_numsp384d1_a, _TEXT00
  alloc_stack   8
  END_PROLOGUE
#else
.global complete_select_numsp384d1_a
complete_select_numsp384d1_a:
  sub          rsp, 8
#endif

  mov           [rsp], reg_p4
  vbroadcastss  ymm0, DWORD PTR [rsp]
  vmovdqu       ymm1, YMMWORD PTR [reg_p1]       // ymm1=a
  vmovdqu       ymm2, YMMWORD PTR [reg_p2]       // ymm2=b
  vblendvpd     ymm3, ymm1, ymm2, ymm0           // if ymm0=0 then ymm3=a else ymm3=b
  vmovdqu       YMMWORD PTR [reg_p3], ymm3

  vmovdqu       xmm1, XMMWORD PTR [reg_p1+32]    // xmm1=a
  vmovdqu       xmm2, XMMWORD PTR [reg_p2+32]    // xmm2=b
  vblendvpd     xmm3, xmm1, xmm2, xmm0           // if xmm0=0 then xmm3=a else xmm3=b
  vmovdqu       XMMWORD PTR [reg_p3+32], xmm3
  add           rsp, 8
#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  ret
NESTED_END complete_select_numsp384d1_a, _TEXT00
#else
  ret
#endif


//****************************************************************************************
// (Constant-time) Point extraction from 4-LUT for the complete mixed addition
// Operation: use index (reg_p2) to extract point from [reg_p1] and pass it to [reg_p3]
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_lut4_numsp384d1_a, _TEXT00
  alloc_stack  24
  save_xmm128  xmm6, 0 
  END_PROLOGUE
#else 
.global complete_lut4_numsp384d1_a
complete_lut4_numsp384d1_a:
  sub          rsp, 8
#endif

  xor          rax, rax  
  mov          r11, 18446744073709551615 
  
  vmovdqu      ymm0, YMMWORD PTR [reg_p1]        // Load table[0]
  vmovdqu      ymm1, YMMWORD PTR [reg_p1+32]
  vmovdqu      ymm2, YMMWORD PTR [reg_p1+64]
  vmovdqu      ymm3, YMMWORD PTR [reg_p1+96]
  vmovdqu      xmm4, XMMWORD PTR [reg_p1+128]

  dec          reg_p2                            // Pass over table[1]
  cmovnz       rax, r11
#ifdef __WINDOWS__
  mov          [rsp+16], rax
  vbroadcastss ymm5, DWORD PTR [rsp+16]
#else
  mov          [rsp], rax
  vbroadcastss ymm5, DWORD PTR [rsp]
#endif
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+144]
  vblendvpd    ymm0, ymm6, ymm0, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+176]
  vblendvpd    ymm1, ymm6, ymm1, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+208]
  vblendvpd    ymm2, ymm6, ymm2, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+240]
  vblendvpd    ymm3, ymm6, ymm3, ymm5
  vmovdqu      xmm6, XMMWORD PTR [reg_p1+272]
  vblendvpd    xmm4, xmm6, xmm4, xmm5
  
  xor          rax, rax                        // Pass over table[2]
  dec          reg_p2
  cmovnz       rax, r11
#ifdef __WINDOWS__
  mov          [rsp+16], rax
  vbroadcastss ymm5, DWORD PTR [rsp+16]
#else
  mov          [rsp], rax
  vbroadcastss ymm5, DWORD PTR [rsp]
#endif
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+288]
  vblendvpd    ymm0, ymm6, ymm0, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+320]
  vblendvpd    ymm1, ymm6, ymm1, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+352]
  vblendvpd    ymm2, ymm6, ymm2, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+384]
  vblendvpd    ymm3, ymm6, ymm3, ymm5
  vmovdqu      xmm6, XMMWORD PTR [reg_p1+416]
  vblendvpd    xmm4, xmm6, xmm4, xmm5
  
  xor          rax, rax                         // Pass over table[3]
  dec          reg_p2
  cmovz        r11, rax
#ifdef __WINDOWS__
  mov          [rsp+16], r11
  vbroadcastss ymm5, DWORD PTR [rsp+16]
#else
  mov          [rsp], r11
  vbroadcastss ymm5, DWORD PTR [rsp]
#endif
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+432]
  vblendvpd    ymm0, ymm6, ymm0, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+464]
  vblendvpd    ymm1, ymm6, ymm1, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+496]
  vblendvpd    ymm2, ymm6, ymm2, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+528]
  vblendvpd    ymm3, ymm6, ymm3, ymm5
  vmovdqu      xmm6, XMMWORD PTR [reg_p1+560]
  vblendvpd    xmm4, xmm6, xmm4, xmm5
    
  vmovdqu      YMMWORD PTR [reg_p3], ymm0        // [reg_p3] = table[index]
  vmovdqu      YMMWORD PTR [reg_p3+32], ymm1
  vmovdqu      YMMWORD PTR [reg_p3+64], ymm2
  vmovdqu      YMMWORD PTR [reg_p3+96], ymm3
  vmovdqu      XMMWORD PTR [reg_p3+128], xmm4

#ifdef __WINDOWS__    
  vmovdqu      xmm6, XMMWORD PTR [rsp]           // Restore xmm6
  add          rsp, 24

ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  ret
NESTED_END complete_lut4_numsp384d1_a, _TEXT00
#else
  add          rsp, 8
  ret
#endif


//****************************************************************************************
// (Constant-time) Point extraction from 5-LUT for the complete addition
// Operation: use index (reg_p2) to extract point from [reg_p1] and pass it to [reg_p3]
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_lut5_numsp384d1_a, _TEXT00
  alloc_stack   24
  save_xmm128  xmm6, 0 
  END_PROLOGUE
#else
.global complete_lut5_numsp384d1_a
complete_lut5_numsp384d1_a:
  sub          rsp, 8
#endif

  xor          rax, rax  
  mov          r11, 18446744073709551615 
  
  vmovdqu      ymm0, YMMWORD PTR [reg_p1]        // Load table[0]
  vmovdqu      ymm1, YMMWORD PTR [reg_p1+32]
  vmovdqu      ymm2, YMMWORD PTR [reg_p1+64]
  vmovdqu      ymm3, YMMWORD PTR [reg_p1+96]
  vmovdqu      xmm4, XMMWORD PTR [reg_p1+128]

  dec          reg_p2                            // Pass over table[1]
  cmovnz       rax, r11
#ifdef __WINDOWS__
  mov          [rsp+16], rax
  vbroadcastss ymm5, DWORD PTR [rsp+16]
#else
  mov          [rsp], rax
  vbroadcastss ymm5, DWORD PTR [rsp]
#endif
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+144]
  vblendvpd    ymm0, ymm6, ymm0, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+176]
  vblendvpd    ymm1, ymm6, ymm1, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+208]
  vblendvpd    ymm2, ymm6, ymm2, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+240]
  vblendvpd    ymm3, ymm6, ymm3, ymm5
  vmovdqu      xmm6, XMMWORD PTR [reg_p1+272]
  vblendvpd    xmm4, xmm6, xmm4, xmm5
  
  xor          rax, rax                        // Pass over table[2]
  dec          reg_p2
  cmovnz       rax, r11
#ifdef __WINDOWS__
  mov          [rsp+16], rax
  vbroadcastss ymm5, DWORD PTR [rsp+16]
#else
  mov          [rsp], rax
  vbroadcastss ymm5, DWORD PTR [rsp]
#endif
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+288]
  vblendvpd    ymm0, ymm6, ymm0, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+320]
  vblendvpd    ymm1, ymm6, ymm1, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+352]
  vblendvpd    ymm2, ymm6, ymm2, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+384]
  vblendvpd    ymm3, ymm6, ymm3, ymm5
  vmovdqu      xmm6, XMMWORD PTR [reg_p1+416]
  vblendvpd    xmm4, xmm6, xmm4, xmm5
  
  xor          rax, rax                         // Pass over table[3]
  dec          reg_p2
  cmovnz       rax, r11
#ifdef __WINDOWS__
  mov          [rsp+16], rax
  vbroadcastss ymm5, DWORD PTR [rsp+16]
#else
  mov          [rsp], rax
  vbroadcastss ymm5, DWORD PTR [rsp]
#endif
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+432]
  vblendvpd    ymm0, ymm6, ymm0, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+464]
  vblendvpd    ymm1, ymm6, ymm1, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+496]
  vblendvpd    ymm2, ymm6, ymm2, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+528]
  vblendvpd    ymm3, ymm6, ymm3, ymm5
  vmovdqu      xmm6, XMMWORD PTR [reg_p1+560]
  vblendvpd    xmm4, xmm6, xmm4, xmm5
  
  xor          rax, rax                         // Pass over table[4]
  dec          reg_p2
  cmovz        r11, rax
#ifdef __WINDOWS__
  mov          [rsp+16], r11
  vbroadcastss ymm5, DWORD PTR [rsp+16]
#else
  mov          [rsp], r11
  vbroadcastss ymm5, DWORD PTR [rsp]
#endif
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+576]
  vblendvpd    ymm0, ymm6, ymm0, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+608]
  vblendvpd    ymm1, ymm6, ymm1, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+640]
  vblendvpd    ymm2, ymm6, ymm2, ymm5
  vmovdqu      ymm6, YMMWORD PTR [reg_p1+672]
  vblendvpd    ymm3, ymm6, ymm3, ymm5
  vmovdqu      xmm6, XMMWORD PTR [reg_p1+704]
  vblendvpd    xmm4, xmm6, xmm4, xmm5
      
  vmovdqu      YMMWORD PTR [reg_p3], ymm0        // [reg_p3] = table[index]
  vmovdqu      YMMWORD PTR [reg_p3+32], ymm1
  vmovdqu      YMMWORD PTR [reg_p3+64], ymm2
  vmovdqu      YMMWORD PTR [reg_p3+96], ymm3
  vmovdqu      XMMWORD PTR [reg_p3+128], xmm4

#ifdef __WINDOWS__    
  vmovdqu      xmm6, XMMWORD PTR [rsp]           // Restore xmm6
  add          rsp, 24

ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  ret
NESTED_END complete_lut5_numsp384d1_a, _TEXT00
#else
  add          rsp, 8
  ret
#endif


//****************************************************************************************
// Zeroing field element
//****************************************************************************************
#ifdef __WINDOWS__
LEAF_ENTRY fpzero384_a, _TEXT00
#else
.global fpzero384_a
fpzero384_a:
#endif
  xor          rax, rax
  mov          [reg_p1], rax
  mov          [reg_p1+8], rax 
  mov          [reg_p1+16], rax
  mov          [reg_p1+24], rax 
  mov          [reg_p1+32], rax 
  mov          [reg_p1+40], rax 
  ret
#ifdef __WINDOWS__
LEAF_END fpzero384_a, _TEXT00
#endif

#ifdef __WINDOWS__
END
#endif
