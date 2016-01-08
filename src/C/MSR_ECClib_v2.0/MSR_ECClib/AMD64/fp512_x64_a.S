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
// Abstract: field operations over GF(2^512-569) in x64 assembly.
//           Supports MASM through pre-building in MSVS, and GNU assembler (GAS).
//
// This software is based on the article by Joppe Bos, Craig Costello, 
// Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
// cryptography: an efficiency and security analysis", preprint available
// at http://eprint.iacr.org/2014/130.
//*******************************************************************************

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
// Operation: c [reg_p3] = a [reg_p1] * b [reg_p2] mod p, p = 2^512-569
// NOTE: input should have reg_p3 != reg_p1 and reg_p3 != reg_p2 
// Inputs: a, b in [0, p-1]
// Output: c in [0, p-1] 
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpmul512_a, _TEXT00
  rex_push_reg rbx
  push_reg     reg_x1
  push_reg     reg_x2
  push_reg     r12
  push_reg     r13
  push_reg     r14
  END_PROLOGUE
#else
.global fpmul512_a
fpmul512_a:
  push         rbx
  push         r12
  push         r13
  push         r14
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
  
  xor  reg_x1, reg_x1
  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+24] // a3*b3
  add  r11, rax          
  adc  reg_p4, rdx        
  adc  reg_x1, 0    
  
  mov  rax, [rbx+32]
  mul qword ptr [reg_p1+16] // a2*b4
  add  r11, rax          
  adc  reg_p4, rdx        
  adc  reg_x1, 0     
  
  mov  rax, [rbx+16]
  mul qword ptr [reg_p1+32] // a4*b2
  add  r11, rax          
  adc  reg_p4, rdx        
  adc  reg_x1, 0         
  
  mov  rax, [rbx+48]
  mul qword ptr [reg_p1]    // a0*b6
  add  r11, rax          
  adc  reg_p4, rdx        
  adc  reg_x1, 0      
  
  mov  rax, [rbx]
  mul qword ptr [reg_p1+48] // a6*b0
  add  r11, rax          
  adc  reg_p4, rdx        
  adc  reg_x1, 0         
  
  mov  rax, [rbx+40]
  mul  reg_aux              // a1*b5
  add  r11, rax          
  adc  reg_p4, rdx        
  adc  reg_x1, 0           
  
  mov  rax, [rbx+8]
  mul qword ptr [reg_p1+40] // a5*b1
  add  r11, rax          
  mov  [reg_x2+48], r11     // C6       
  adc  reg_p4, rdx        
  adc  reg_x1, 0   
  
  xor  r12, r12
  mov  rax, [rbx+40]
  mul qword ptr [reg_p1+16] // a2*b5
  add  reg_p4, rax          
  adc  reg_x1, rdx        
  adc  r12, 0    

  mov  rax, [rbx+16]
  mul qword ptr [reg_p1+40] // a5*b2
  add  reg_p4, rax          
  adc  reg_x1, rdx        
  adc  r12, 0        

  mov  rax, [rbx+8]
  mul qword ptr [reg_p1+48] // a6*b1
  add  reg_p4, rax          
  adc  reg_x1, rdx        
  adc  r12, 0           

  mov  rax, [rbx+48]
  mul  reg_aux              // a1*b6
  add  reg_p4, rax          
  adc  reg_x1, rdx        
  adc  r12, 0          

  mov  rax, [rbx]
  mul qword ptr [reg_p1+56] // a7*b0
  add  reg_p4, rax          
  adc  reg_x1, rdx        
  adc  r12, 0          

  mov  rax, [rbx+56]
  mul qword ptr [reg_p1]    // a0*b7
  add  reg_p4, rax          
  adc  reg_x1, rdx        
  adc  r12, 0              

  mov  rax, [rbx+32]
  mul qword ptr [reg_p1+24] // a3*b4
  add  reg_p4, rax          
  adc  reg_x1, rdx        
  adc  r12, 0         

  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+32] // a4*b3
  add  reg_p4, rax           
  mov  [reg_x2+56], reg_p4  // C7          
  adc  reg_x1, rdx        
  adc  r12, 0     
  
  xor  r13, r13
  mov  rax, [rbx+40]
  mul qword ptr [reg_p1+24] // a3*b5
  add  reg_x1, rax          
  adc  r12, rdx        
  adc  r13, 0     
  
  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+40] // a5*b3
  add  reg_x1, rax          
  adc  r12, rdx        
  adc  r13, 0       
  
  mov  rax, [rbx+56]
  mul  reg_aux              // a1*b7
  add  reg_x1, rax          
  adc  r12, rdx        
  adc  r13, 0       
  
  mov  rax, [rbx+8]
  mul qword ptr [reg_p1+56] // a7*b1
  add  reg_x1, rax          
  adc  r12, rdx        
  adc  r13, 0      
  
  mov  rax, [rbx+16]
  mul qword ptr [reg_p1+48] // a6*b2
  add  reg_x1, rax          
  adc  r12, rdx        
  adc  r13, 0      
  
  mov  rax, [rbx+48]
  mul qword ptr [reg_p1+16] // a2*b6
  add  reg_x1, rax          
  adc  r12, rdx        
  adc  r13, 0            

  mov  rax, [rbx+32]
  mul qword ptr [reg_p1+32] // a4*b4
  add  reg_x1, rax          // C8 = reg_x1             
  adc  r12, rdx        
  adc  r13, 0         
  
  xor  r14, r14
  mov  rax, [rbx+40]
  mul qword ptr [reg_p1+32] // a4*b5
  add  r12, rax          
  adc  r13, rdx        
  adc  r14, 0       
  
  mov  rax, [rbx+56]
  mul qword ptr [reg_p1+16] // a2*b7
  add  r12, rax          
  adc  r13, rdx        
  adc  r14, 0       
  
  mov  rax, [rbx+16]
  mul qword ptr [reg_p1+56] // a7*b2
  add  r12, rax          
  adc  r13, rdx        
  adc  r14, 0      
  
  mov  rax, [rbx+48]
  mul qword ptr [reg_p1+24] // a3*b6
  add  r12, rax          
  adc  r13, rdx        
  adc  r14, 0     
  
  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+48] // a6*b3
  add  r12, rax          
  adc  r13, rdx        
  adc  r14, 0                           

  mov  rax, [rbx+32]
  mul qword ptr [reg_p1+40] // a5*b4
  add  r12, rax             // C9 = r12        
  adc  r13, rdx        
  adc  r14, 0          
  
  xor  reg_aux, reg_aux
  mov  rax, [rbx+56]
  mul qword ptr [reg_p1+24] // a3*b7
  add  r13, rax          
  adc  r14, rdx        
  adc  reg_aux, 0    
  
  mov  rax, [rbx+24]
  mul qword ptr [reg_p1+56] // a7*b3
  add  r13, rax          
  adc  r14, rdx        
  adc  reg_aux, 0    

  mov  rax, [rbx+48]
  mul qword ptr [reg_p1+32] // a4*b6
  add  r13, rax          
  adc  r14, rdx        
  adc  reg_aux, 0      

  mov  rax, [rbx+32]
  mul qword ptr [reg_p1+48] // a6*b4
  add  r13, rax          
  adc  r14, rdx        
  adc  reg_aux, 0     

  mov  rax, [rbx+40]
  mul qword ptr [reg_p1+40] // a5*b5
  add  r13, rax             // C10 = r13        
  adc  r14, rdx        
  adc  reg_aux, 0             
  
  xor  reg_p4, reg_p4
  mov  rax, [rbx+56]
  mul qword ptr [reg_p1+32] // a4*b7
  add  r14, rax          
  adc  reg_aux, rdx        
  adc  reg_p4, 0    
  
  mov  rax, [rbx+32]
  mul qword ptr [reg_p1+56] // a7*b4
  add  r14, rax          
  adc  reg_aux, rdx        
  adc  reg_p4, 0      
  
  mov  rax, [rbx+48]
  mul qword ptr [reg_p1+40] // a5*b6
  add  r14, rax          
  adc  reg_aux, rdx        
  adc  reg_p4, 0     
  
  mov  rax, [rbx+40]
  mul qword ptr [reg_p1+48] // a6*b5
  add  r14, rax             // C11 = r14
  adc  reg_aux, rdx        
  adc  reg_p4, 0               
  
  xor  r10, r10
  mov  rax, [rbx+56]
  mul qword ptr [reg_p1+40] // a5*b7
  add  reg_aux, rax          
  adc  reg_p4, rdx        
  adc  r10, 0  
    
  mov  rax, [rbx+40]
  mul qword ptr [reg_p1+56] // a7*b5
  add  reg_aux, rax          
  adc  reg_p4, rdx        
  adc  r10, 0    
    
  mov  rax, [rbx+48]
  mul qword ptr [reg_p1+48] // a6*b6
  add  reg_aux, rax         // C12 = reg_aux       
  adc  reg_p4, rdx        
  adc  r10, 0                
  
  xor  r11, r11
  mov  rax, [rbx+56]
  mul qword ptr [reg_p1+48] // a6*b7
  add  reg_p4, rax          
  adc  r10, rdx        
  adc  r11, 0    
  
  mov  rax, [rbx+48]
  mul qword ptr [reg_p1+56] // a7*b6
  add  reg_p4, rax          // C13 = reg_p4       
  adc  r10, rdx        
  adc  r11, 0                                                 

  mov  rax, [rbx+56]
  mul qword ptr [reg_p1+56] // a7*b7
  add  r10, rax             // C14 = r10         
  adc  r11, rdx             // C15 = r11                      

// Reduction

  mov  rax, P512_c
  mul  reg_x1 
  mov  rbx, [reg_x2]
  add  rbx, rax             // rbx = partial0
  adc  rdx, 0    
  mov  reg_p1, rdx 

  xor  reg_x1, reg_x1
  mov  rax, P512_c
  mul  r12
  add  rax, reg_p1  
  adc  reg_x1, 0   
  mov  r12, [reg_x2+8]    
  add  r12, rax             // r12 = partial1
  adc  reg_x1, rdx  

  xor  reg_p1, reg_p1
  mov  rax, P512_c
  mul  r13
  add  rax, reg_x1 
  adc  reg_p1, 0 
  mov  r13, [reg_x2+16]    
  add  r13, rax             // r13 = partial2
  adc  reg_p1, rdx 

  xor  reg_x1, reg_x1
  mov  rax, P512_c
  mul  r14
  add  rax, reg_p1  
  adc  reg_x1, 0   
  mov  r14, [reg_x2+24]    
  add  r14, rax             // r14 = partial3
  adc  reg_x1, rdx  

  xor  reg_p1, reg_p1
  mov  rax, P512_c
  mul  reg_aux 
  add  rax, reg_x1 
  adc  reg_p1, 0 
  mov  reg_aux, [reg_x2+32]    
  add  reg_aux, rax         // reg_aux = partial4
  adc  reg_p1, rdx 

  xor  reg_x1, reg_x1
  mov  rax, P512_c
  mul  reg_p4 
  add  rax, reg_p1  
  adc  reg_x1, 0   
  mov  reg_p4, [reg_x2+40]    
  add  reg_p4, rax          // reg_p4 = partial5
  adc  reg_x1, rdx   

  xor  reg_p1, reg_p1
  mov  rax, P512_c
  mul  r10 
  add  rax, reg_x1 
  adc  reg_p1, 0 
  mov  r10, [reg_x2+48]    
  add  r10, rax             // r10 = partial6
  adc  reg_p1, rdx 

  xor  reg_x1, reg_x1
  mov  rax, P512_c
  mul  r11
  add  rax, reg_p1 
  adc  reg_x1, 1   
  mov  r11, [reg_x2+56]    
  add  r11, rax             // r11 = partial7
  adc  rdx, reg_x1          // rdx = partial8 + 1
  
  xor  reg_x1, reg_x1
  mov  rax, P512_c         
  mul  rdx   
  add  rbx, rax             // rbx = partial0 
  adc  r12, 0               // r12 = partial1
  adc  r13, 0               // r13 = partial2
  adc  r14, 0               // r14 = partial3
  adc  reg_aux, 0           // reg_aux = partial4
  adc  reg_p4, 0            // reg_p4 = partial5
  adc  r10, 0               // r10 = partial6
  adc  r11, 0               // r11 = partial7
    
  mov  rax, P512_c          // final correction
  cmovc rax, reg_x1
  sub  rbx, rax
  mov  [reg_x2], rbx  
  sbb  r12, 0
  mov  [reg_x2+8], r12 
  sbb  r13, 0
  mov  [reg_x2+16], r13  
  sbb  r14, 0
  mov  [reg_x2+24], r14 
  sbb  reg_aux, 0
  mov  [reg_x2+32], reg_aux 
  sbb  reg_p4, 0
  mov  [reg_x2+40], reg_p4 
  sbb  r10, 0
  mov  [reg_x2+48], r10 
  sbb  r11, 0
  mov  [reg_x2+56], r11 

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
NESTED_END fpmul512_a, _TEXT00
#else
  pop r14
  pop r13
  pop r12
  pop rbx
  ret
#endif


//****************************************************************************************
// (Constant-time) field squaring using integer multiplication by product scanning
// Operation: c [reg_p2] = a [reg_p1]^2 mod p, p = 2^512-569
// NOTE: input should have reg_p2 != reg_p1 
// Input:  a in [0, p-1]
// Output: c in [0, p-1] 
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpsqr512_a, _TEXT00
  rex_push_reg rbx
  push_reg     reg_x1
  push_reg     reg_x2
  push_reg     r12
  push_reg     r13
  push_reg     r14
  push_reg     r15
  END_PROLOGUE
#else
.global fpsqr512_a
fpsqr512_a:
  push rbx
  push r12
  push r13
  push r14
  push r15
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
  mul  rax                  // a2^2
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

  mov  rax, [reg_p1+48]
  mul qword ptr [reg_p1]    // a0*a6
  add  reg_x2, rax
  adc  r10, rdx
  adc  r14, 0

  mov  rax, [reg_p1+32]
  mul  reg_aux              // a2*a4
  add  reg_x2, rax
  adc  r10, rdx
  adc  r14, 0
  add  reg_x2, reg_x2              
  adc  r10, r10
  adc  r14, r14             // 2(a2*a4 + a1*a5 + a0*a6)

  mov  rax, [reg_p1+24]
  mul  rax                  // a3^2
  add  r11, reg_x2             
  adc  reg_p4, r10
  adc  r14, 0
  add  r11, rax             // C6
  mov  [rbx+48], r11
  adc  reg_p4, rdx
  adc  r14, 0

  mov  rax, [reg_p1+40]
  mul  reg_aux              // a2*a5
  xor  r12, r12
  mov  reg_x2, rax
  mov  r10, rdx

  mov  rax, [reg_p1+56]
  mul qword ptr [reg_p1]    // a0*a7
  add  reg_x2, rax
  adc  r10, rdx
  adc  r12, 0

  mov  rax, [reg_p1+48]
  mul qword ptr [reg_p1+8]  // a1*a6
  add  reg_x2, rax
  adc  r10, rdx
  adc  r12, 0

  mov  rax, [reg_p1+32]
  mul qword ptr [reg_p1+24] // a3*a4
  add  reg_x2, rax             
  adc  r10, rdx
  adc  r12, 0
  add  reg_x2, reg_x2        
  adc  r10, r10
  adc  r12, r12             // 2(a2*a5 + a3*a4 + a0*a7 + a1*a6)
    
  xor  r13, r13
  mov  rax, [reg_p1+40]
  mul qword ptr [reg_p1+24] // a3*a5
  add  reg_p4, reg_x2       // C7
  mov  [rbx+56], reg_p4
  adc  r10, r14
  adc  r12, 0
  xor  r13, r13
  mov  reg_x2, rax
  mov  r14, rdx

  mov  rax, [reg_p1+56]
  mul qword ptr [reg_p1+8]  // a1*a7
  add  reg_x2, rax
  adc  r14, rdx
  adc  r13, 0

  mov  rax, [reg_p1+48]
  mul  reg_aux              // a2*a6
  add  reg_x2, rax
  adc  r14, rdx
  adc  r13, 0
  add  reg_x2, reg_x2              
  adc  r14, r14
  adc  r13, r13             // 2(a2*a6 + a1*a7 + a3*a5)

  mov  rax, [reg_p1+32]
  mul  rax                  // a4^2
  add  reg_x2, rax             
  adc  r14, rdx
  adc  r13, 0
  add  r10, reg_x2          // r10 = C8
  adc  r12, r14
  adc  r13, 0  

  mov  rax, [reg_p1+40]
  mul qword ptr [reg_p1+32] // a4*a5
  xor  r14, r14
  mov  r15, rax
  mov  reg_p4, rdx

  mov  rax, [reg_p1+56]
  mul  reg_aux              // a2*a7
  add  r15, rax
  adc  reg_p4, rdx
  adc  r14, 0

  mov  rax, [reg_p1+48]
  mul qword ptr [reg_p1+24] // a3*a6
  add  r15, rax
  adc  reg_p4, rdx
  adc  r14, 0
  add  r15, r15              
  adc  reg_p4, reg_p4
  adc  r14, r14             // 2(a4*a5 + a2*a7 + a3*a6)

  mov  rax, [reg_p1+56]
  mul qword ptr [reg_p1+24] // a3*a7
  add  r12, r15             // r12 = C9
  adc  r13, reg_p4
  adc  r14, 0
  xor  r15, r15
  mov  reg_p4, rax
  mov  reg_x1, rdx  

  mov  rax, [reg_p1+48]
  mul qword ptr [reg_p1+32] // a4*a6
  add  reg_p4, rax
  adc  reg_x1, rdx
  adc  r15, 0
  add  reg_p4, reg_p4              
  adc  reg_x1, reg_x1
  adc  r15, r15             // 2(a3*a7 + a4*a6)

  mov  rax, [reg_p1+40]
  mul qword ptr [reg_p1+40] // a5^2
  add  r13, reg_p4
  adc  r14, reg_x1
  adc  r15, 0 
  mov  reg_x1, rax
  mov  r11, rdx
   
  mov  rax, [reg_p1+56]
  mul qword ptr [reg_p1+32] // a4*a7
  add  r13, reg_x1          // r13 = C10
  adc  r14, r11
  adc  r15, 0 
  xor  reg_p4, reg_p4
  mov  reg_x1, rax
  mov  r11, rdx
   
  mov  rax, [reg_p1+48]
  mul qword ptr [reg_p1+40] // a5*a6
  add  reg_x1, rax
  adc  r11, rdx
  adc  reg_p4, 0
  add  reg_x1, reg_x1
  adc  r11, r11
  adc  reg_p4, reg_p4       // 2(a4*a7 + a5*a6)
    
  mov  rax, [reg_p1+56]
  mul qword ptr [reg_p1+40] 
  add  r14, reg_x1          // r14 = C11
  adc  r15, r11
  adc  reg_p4, 0
  xor  reg_x1, reg_x1
  add  rax, rax  
  mov  reg_aux, rax            
  adc  rdx, rdx
  mov  r11, rdx
  adc  reg_x1, 0            // 2a5*a7

  mov  rax, [reg_p1+48]
  mul  rax                  // a6^2
  add  reg_aux, rax             
  adc  r11, rdx
  adc  reg_x1, 0
  add  r15, reg_aux         // r15 = C12
  adc  reg_p4, r11
  adc  reg_x1, 0
   
  xor  r11, r11
  mov  rax, [reg_p1+56]
  mul qword ptr [reg_p1+48] // a6*a7
  add  rax, rax             
  adc  rdx, rdx
  adc  r11, 0
  add  reg_p4, rax          // reg_p4 = C13
  adc  reg_x1, rdx
  adc  r11, 0

  mov  rax, [reg_p1+56]
  mul  rax                  // a7^2
  add  reg_x1, rax          // reg_x1 = C14 
  adc  r11, rdx             // r11 = C15                      

// Reduction

  mov  rax, P512_c
  mul  r10 
  mov  reg_aux, [rbx]
  add  reg_aux, rax         // reg_aux = partial0
  adc  rdx, 0    
  mov  reg_p1, rdx 

  xor  r10, r10
  mov  rax, P512_c
  mul  r12
  add  rax, reg_p1  
  adc  r10, 0   
  mov  r12, [rbx+8]    
  add  r12, rax             // r12 = partial1
  adc  r10, rdx  

  xor  reg_p1, reg_p1
  mov  rax, P512_c
  mul  r13
  add  rax, r10 
  adc  reg_p1, 0 
  mov  r13, [rbx+16]    
  add  r13, rax             // r13 = partial2
  adc  reg_p1, rdx 

  xor  r10, r10
  mov  rax, P512_c
  mul  r14
  add  rax, reg_p1  
  adc  r10, 0   
  mov  r14, [rbx+24]    
  add  r14, rax             // r14 = partial3
  adc  r10, rdx  

  xor  reg_p1, reg_p1
  mov  rax, P512_c
  mul  r15 
  add  rax, r10 
  adc  reg_p1, 0 
  mov  r15, [rbx+32]    
  add  r15, rax             // r15 = partial4
  adc  reg_p1, rdx 

  xor  r10, r10
  mov  rax, P512_c
  mul  reg_p4 
  add  rax, reg_p1  
  adc  r10, 0   
  mov  reg_p4, [rbx+40]    
  add  reg_p4, rax          // reg_p4 = partial5
  adc  r10, rdx   

  xor  reg_p1, reg_p1
  mov  rax, P512_c
  mul  reg_x1 
  add  rax, r10 
  adc  reg_p1, 0 
  mov  reg_x1, [rbx+48]    
  add  reg_x1, rax          // reg_x1 = partial6
  adc  reg_p1, rdx 

  xor  r10, r10
  mov  rax, P512_c
  mul  r11
  add  rax, reg_p1 
  adc  r10, 1   
  mov  r11, [rbx+56]    
  add  r11, rax             // r11 = partial7
  adc  rdx, r10             // rdx = partial8 + 1
  
  xor  r10, r10
  mov  rax, P512_c         
  mul  rdx   
  add  reg_aux, rax         // reg_aux = partial0 
  adc  r12, 0               // r12 = partial1
  adc  r13, 0               // r13 = partial2
  adc  r14, 0               // r14 = partial3
  adc  r15, 0               // r15 = partial4
  adc  reg_p4, 0            // reg_p4 = partial5
  adc  reg_x1, 0            // reg_x1 = partial6
  adc  r11, 0               // r11 = partial7
    
  mov  rax, P512_c          // final correction
  cmovc rax, r10
  sub  reg_aux, rax
  mov  [rbx], reg_aux  
  sbb  r12, 0
  mov  [rbx+8], r12 
  sbb  r13, 0
  mov  [rbx+16], r13  
  sbb  r14, 0
  mov  [rbx+24], r14 
  sbb  r15, 0
  mov  [rbx+32], r15 
  sbb  reg_p4, 0
  mov  [rbx+40], reg_p4 
  sbb  reg_x1, 0
  mov  [rbx+48], reg_x1 
  sbb  r11, 0
  mov  [rbx+56], r11 

#ifdef __WINDOWS__  
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop  r15
  pop  r14
  pop  r13
  pop  r12
  pop  reg_x2
  pop  reg_x1
  pop  rbx
  ret
NESTED_END fpsqr512_a, _TEXT00
#else
  pop  r15
  pop  r14
  pop  r13
  pop  r12
  pop  rbx
  ret
#endif


//*********************************************************************
// (Constant-time) field addition 
// Operation: c [reg_p3] = a [reg_p1] + b [reg_p2] mod p, p = 2^512-569
// Input:  a, b in [0, p-1]
// Output: c in [0, p-1]
//*********************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpadd512_a, _TEXT00
  rex_push_reg r12
  push_reg     r13
  push_reg     reg_x1
  push_reg     reg_x2
  push_reg     rbx
  END_PROLOGUE
#else
.global fpadd512_a
fpadd512_a:
  push r12
  push r13
  push rbx
#endif
  
  mov  reg_p4, [reg_p1]        // a + P512_c
  add  reg_p4, P512_c
  mov  r10, [reg_p1+8]
  adc  r10, 0
  mov  r11, [reg_p1+16]
  adc  r11, 0
  mov  r12, [reg_p1+24]
  adc  r12, 0
  mov  r13, [reg_p1+32]
  adc  r13, 0
  mov  reg_x1, [reg_p1+40]
  adc  reg_x1, 0
  mov  reg_x2, [reg_p1+48]
  adc  reg_x2, 0
  mov  rbx, [reg_p1+56]
  adc  rbx, 0
  
  mov  reg_p1, [reg_p2]       // (a+P512_c) + b 
  add  reg_p4, reg_p1
  mov  reg_p1, [reg_p2+8]
  adc  r10, reg_p1
  mov  reg_p1, [reg_p2+16]
  adc  r11, reg_p1
  mov  reg_p1, [reg_p2+24]
  adc  r12, reg_p1
  mov  reg_p1, [reg_p2+32]
  adc  r13, reg_p1
  mov  reg_p1, [reg_p2+40]
  adc  reg_x1, reg_p1
  mov  reg_p1, [reg_p2+48]
  adc  reg_x2, reg_p1
  mov  reg_p1, [reg_p2+56]
  adc  rbx, reg_p1
  
  mov  reg_p2, 0              // if (carry) then c = (a+P512_c) + b
  mov  reg_p1, P512_c         // else c = (a+P512_c) + b - P512_c
  cmovc reg_p1, reg_p2
  sub  reg_p4, reg_p1
  mov  [reg_p3], reg_p4
  sbb  r10, 0
  mov  [reg_p3+8], r10
  sbb  r11, 0
  mov  [reg_p3+16], r11
  sbb  r12, 0
  mov  [reg_p3+24], r12
  sbb  r13, 0
  mov  [reg_p3+32], r13
  sbb  reg_x1, 0
  mov  [reg_p3+40], reg_x1
  sbb  reg_x2, 0
  mov  [reg_p3+48], reg_x2
  sbb  rbx, 0
  mov  [reg_p3+56], rbx

#ifdef __WINDOWS__  
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop  rbx
  pop  reg_x2
  pop  reg_x1
  pop  r13
  pop  r12
  ret
NESTED_END fpadd512_a, _TEXT00
#else
  pop rbx
  pop r13
  pop r12
  ret
#endif


//*********************************************************************
// (Constant-time) field subtraction
// Operation: c [reg_p3] = a [reg_p1] + b [reg_p2] mod p, p = 2^512-569
// Input:  a, b in [0, p-1]
// Output: c in [0, p-1]
//*********************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpsub512_a, _TEXT00
  rex_push_reg r12
  push_reg     r13
  push_reg     reg_x1
  push_reg     reg_x2
  END_PROLOGUE
#else
.global fpsub512_a
fpsub512_a:
  push r12
  push r13
#endif
            
  mov  reg_p4, [reg_p1]     // a - b
  sub  reg_p4, [reg_p2]
  mov  r10, [reg_p1+8]
  sbb  r10, [reg_p2+8]
  mov  r11, [reg_p1+16]
  sbb  r11, [reg_p2+16]
  mov  r12, [reg_p1+24]
  sbb  r12, [reg_p2+24]
  mov  r13, [reg_p1+32]
  sbb  r13, [reg_p2+32]
  mov  reg_x1, [reg_p1+40]
  sbb  reg_x1, [reg_p2+40]
  mov  reg_x2, [reg_p1+48]
  sbb  reg_x2, [reg_p2+48]
  mov  rax, [reg_p1+56]
  sbb  rax, [reg_p2+56]

  mov  reg_p2, 0
  mov  reg_p1, P512_c       // if (carry) then c = (a-b) - P512_c 
  cmovnc reg_p1, reg_p2     // else c = a - b
  sub  reg_p4, reg_p1
  mov  [reg_p3], reg_p4
  sbb  r10, 0
  mov  [reg_p3+8], r10
  sbb  r11, 0
  mov  [reg_p3+16], r11
  sbb  r12, 0
  mov  [reg_p3+24], r12
  sbb  r13, 0
  mov  [reg_p3+32], r13
  sbb  reg_x1, 0
  mov  [reg_p3+40], reg_x1
  sbb  reg_x2, 0
  mov  [reg_p3+48], reg_x2
  sbb  rax, 0
  mov  [reg_p3+56], rax

#ifdef __WINDOWS__  
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop  reg_x2
  pop  reg_x1
  pop  r13
  pop  r12
  ret
NESTED_END fpsub512_a, _TEXT00
#else
  pop  r13
  pop  r12
  ret
#endif


//*********************************************************************
// (Constant-time) field division by 2 
// Operation: a [reg_p2] = a [reg_p1]/2 mod p, p = 2^512-569
// Input:  a in [0, p-1]
// Output: c in [0, p-1]
//*********************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY fpdiv2_512_a, _TEXT00 
    rex_push_reg    r12
    push_reg        r13
    push_reg        reg_x1
    push_reg        reg_x2
    push_reg        rbx
  END_PROLOGUE
#else
.global fpdiv2_512_a
fpdiv2_512_a:
    push            r12
    push            r13
    push            rbx
#endif
    xor     rbx, rbx
    mov     rax, [reg_p1]
    bt      rax, 0
    mov     reg_p3, P512_0 
    cmovnc  reg_p3, rbx
    mov     reg_p4, P512_1         // P512_1 = ... = P512_7
    cmovnc  reg_p4, rbx
    mov     r10, reg_p4  
    mov     r11, reg_p4 
    mov     r12, reg_p4 
    mov     r13, reg_p4 
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
    adc     r12, rax
    mov     rax, [reg_p1+40]
    adc     r13, rax
    mov     rax, [reg_p1+48]
    adc     reg_x1, rax
    mov     rax, [reg_p1+56]
    adc     reg_x2, rax
    adc     rbx, 0
  
    shrd    reg_p3, reg_p4, 1      // c = temp/2
    mov     [reg_p2], reg_p3
    shrd    reg_p4, r10, 1
    mov     [reg_p2+8], reg_p4
    shrd    r10, r11, 1
    mov     [reg_p2+16], r10
    shrd    r11, r12, 1
    mov     [reg_p2+24], r11    
    shrd    r12, r13, 1
    mov     [reg_p2+32], r12        
    shrd    r13, reg_x1, 1
    mov     [reg_p2+40], r13    
    shrd    reg_x1, reg_x2, 1
    mov     [reg_p2+48], reg_x1
    shrd    reg_x2, rbx, 1
    mov     [reg_p2+56], reg_x2    
#ifdef __WINDOWS__    
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
    pop     rbx
    pop     reg_x2
    pop     reg_x1
    pop     r13
    pop     r12
    ret
NESTED_END fpdiv2_512_a, _TEXT00
#else
    pop     rbx
    pop     r13
    pop     r12
    ret
#endif


//****************************************************************************************
// (Constant-time) field negation and subtraction from a modulus
// Operation: a [reg_p2] = modulus [reg_p1] - a [reg_p2]
//            if modulus = p = 2^512-569, then this performs a field negation -a (mod p)
// Input:  a in [0, modulus-1]
// Output: a in [0, modulus-1], rax = 1 (TRUE) if a <= modulus
//****************************************************************************************
#ifdef __WINDOWS__
LEAF_ENTRY fpneg512_a, _TEXT00
#else
.global fpneg512_a
fpneg512_a:
#endif
  xor  rax, rax
  mov  reg_p4, [reg_p1]      // a = modulus - a
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
  mov  reg_p4, [reg_p1+48]      
  sbb  reg_p4, [reg_p2+48]
  mov  [reg_p2+48], reg_p4
  mov  reg_p4, [reg_p1+56]      
  sbb  reg_p4, [reg_p2+56]
  mov  [reg_p2+56], reg_p4
  
  setnb  al
  ret
#ifdef __WINDOWS__
LEAF_END fpneg512_a, _TEXT00
#endif


//*******************************************************************************************************************************
// (Constant-time) Evaluation for the complete addition
// Operation: if [reg_p1] = 0 (P=-Q) then index=0, if [reg_p2] = 0 (P infinity) then index=1, if [reg_p3] = 0 (P=Q) then index=2, 
//            else index=3
// Output:    if index(rax)=3 then mask [reg_p4] = 0xff...ff, else mask [reg_p4] = 0  
//*******************************************************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_eval_numsp512d1_a, _TEXT00
  rex_push_reg   reg_x1
  END_PROLOGUE
#else
.global complete_eval_numsp512d1_a
complete_eval_numsp512d1_a:
#endif

  xor    rax, rax
  mov    r11, 3                    // index 3 (P+Q) 
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
  mov    r10, [reg_p1+48]
  or     reg_x1, r10
  mov    r10, [reg_p1+56]
  or     reg_x1, r10
  cmovnz rax, r11                  // index 0 (P=-Q) if [reg_p1]=0
  
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
  mov    r10, [reg_p3+48]
  or     reg_x1, r10
  mov    r10, [reg_p3+56]
  or     reg_x1, r10
  cmovz  rax, r11                  // index 2 (P=Q) if [reg_p1] & [reg_p3]=0
  
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
  mov    r10, [reg_p2+48]
  or     reg_x1, r10
  mov    r10, [reg_p2+56]
  or     reg_x1, r10
  cmovz  rax, r11                  // index 1 (P inf) if [reg_p2]=0

  xor    reg_p1, reg_p1
  mov    r10, 18446744073709551615
  mov    r11, rax
  sub    r11, 3
  cmovz  reg_p1, r10               // mask = ff...f if index=3, else mask = 0
  mov    [reg_p4], reg_p1

#ifdef __WINDOWS__  
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  pop    reg_x1
  ret
NESTED_END complete_eval_numsp512d1_a, _TEXT00
#else
  ret
#endif
 

//*****************************************************************************************************************
// (Constant-time) Field element selection for the complete addition
// Operation: if (reg_p4)=0 then c [reg_p3] = a [reg_p1], else if (reg_p4) = 0xff...ff then c [reg_p3] = b [reg_p2]
//*****************************************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_select_numsp512d1_a, _TEXT00
  alloc_stack   8
  END_PROLOGUE
#else
.global complete_select_numsp512d1_a
complete_select_numsp512d1_a:
  sub          rsp, 8
#endif

  mov           [rsp], reg_p4
  vbroadcastss  ymm0, DWORD PTR [rsp]
  vmovdqu       ymm1, YMMWORD PTR [reg_p1]         // ymm1=a
  vmovdqu       ymm2, YMMWORD PTR [reg_p2]         // ymm2=b
  vblendvpd     ymm3, ymm1, ymm2, ymm0             // if ymm0=0 then ymm3=a else ymm3=b
  vmovdqu       YMMWORD PTR [reg_p3], ymm3
  
  vmovdqu       ymm1, YMMWORD PTR [reg_p1+32]      // ymm1=a
  vmovdqu       ymm2, YMMWORD PTR [reg_p2+32]      // ymm2=b
  vblendvpd     ymm3, ymm1, ymm2, ymm0             // if ymm0=0 then ymm3=a else ymm3=b
  vmovdqu       YMMWORD PTR [reg_p3+32], ymm3      
  add           rsp, 8

#ifdef __WINDOWS__
ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  ret
NESTED_END complete_select_numsp512d1_a, _TEXT00
#else
  ret
#endif


//****************************************************************************************
// (Constant-time) Point extraction from 4-LUT for the complete mixed addition
// Operation: use index (reg_p2) to extract point from [reg_p1] and pass it to [reg_p3]
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_lut4_numsp512d1_a, _TEXT00
  alloc_stack  40
  save_xmm128  xmm6, 0 
  save_xmm128  xmm7, 16 
  END_PROLOGUE
#else
.global complete_lut4_numsp512d1_a
complete_lut4_numsp512d1_a:
  sub          rsp, 8
#endif

  xor          rax, rax  
  mov          r11, 18446744073709551615 
  
  vmovdqu      ymm0, YMMWORD PTR [reg_p1]        // Load table[0]
  vmovdqu      ymm1, YMMWORD PTR [reg_p1+32]
  vmovdqu      ymm2, YMMWORD PTR [reg_p1+64]
  vmovdqu      ymm3, YMMWORD PTR [reg_p1+96]        
  vmovdqu      ymm4, YMMWORD PTR [reg_p1+128]
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+160]

  dec          reg_p2                            // Pass over table[1]
  cmovnz       rax, r11
#ifdef __WINDOWS__
  mov          [rsp+32], rax
  vbroadcastss ymm6, DWORD PTR [rsp+32]
#else
  mov          [rsp], rax
  vbroadcastss ymm6, DWORD PTR [rsp]
#endif
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+192]
  vblendvpd    ymm0, ymm7, ymm0, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+224]
  vblendvpd    ymm1, ymm7, ymm1, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+256]
  vblendvpd    ymm2, ymm7, ymm2, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+288]
  vblendvpd    ymm3, ymm7, ymm3, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+320]
  vblendvpd    ymm4, ymm7, ymm4, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+352]
  vblendvpd    ymm5, ymm7, ymm5, ymm6
  
  xor          rax, rax                         // Pass over table[2]
  dec          reg_p2
  cmovnz       rax, r11
#ifdef __WINDOWS__
  mov          [rsp+32], rax
  vbroadcastss ymm6, DWORD PTR [rsp+32]
#else
  mov          [rsp], rax
  vbroadcastss ymm6, DWORD PTR [rsp]
#endif
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+384]
  vblendvpd    ymm0, ymm7, ymm0, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+416]
  vblendvpd    ymm1, ymm7, ymm1, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+448]
  vblendvpd    ymm2, ymm7, ymm2, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+480]
  vblendvpd    ymm3, ymm7, ymm3, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+512]
  vblendvpd    ymm4, ymm7, ymm4, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+544]
  vblendvpd    ymm5, ymm7, ymm5, ymm6
  
  xor          rax, rax                         // Pass over table[3]
  dec          reg_p2
  cmovz        r11, rax
#ifdef __WINDOWS__
  mov          [rsp+32], r11
  vbroadcastss ymm6, DWORD PTR [rsp+32]
#else
  mov          [rsp], r11
  vbroadcastss ymm6, DWORD PTR [rsp]
#endif
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+576]
  vblendvpd    ymm0, ymm7, ymm0, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+608]
  vblendvpd    ymm1, ymm7, ymm1, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+640]
  vblendvpd    ymm2, ymm7, ymm2, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+672]
  vblendvpd    ymm3, ymm7, ymm3, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+704]
  vblendvpd    ymm4, ymm7, ymm4, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+736]
  vblendvpd    ymm5, ymm7, ymm5, ymm6
    
  vmovdqu      YMMWORD PTR [reg_p3], ymm0       // [reg_p3] = table[index]
  vmovdqu      YMMWORD PTR [reg_p3+32], ymm1
  vmovdqu      YMMWORD PTR [reg_p3+64], ymm2
  vmovdqu      YMMWORD PTR [reg_p3+96], ymm3
  vmovdqu      YMMWORD PTR [reg_p3+128], ymm4
  vmovdqu      YMMWORD PTR [reg_p3+160], ymm5

#ifdef __WINDOWS__    
  vmovdqu      xmm6, XMMWORD PTR [rsp]          // Restore ymm6,7
  vmovdqu      xmm7, XMMWORD PTR [rsp+16] 
  add          rsp, 40

ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  ret
NESTED_END complete_lut4_numsp512d1_a, _TEXT00
#else
  add          rsp, 8
  ret
#endif


//****************************************************************************************
// (Constant-time) Point extraction from 5-LUT for the complete addition
// Operation: use index (reg_p2) to extract point from [reg_p1] and pass it to [reg_p3]
//****************************************************************************************
#ifdef __WINDOWS__
NESTED_ENTRY complete_lut5_numsp512d1_a, _TEXT00
  alloc_stack  40
  save_xmm128  xmm6, 0 
  save_xmm128  xmm7, 16 
  END_PROLOGUE
#else
.global complete_lut5_numsp512d1_a
complete_lut5_numsp512d1_a:
  sub          rsp, 8
#endif

  xor          rax, rax  
  mov          r11, 18446744073709551615 
  
  vmovdqu      ymm0, YMMWORD PTR [reg_p1]        // Load table[0]
  vmovdqu      ymm1, YMMWORD PTR [reg_p1+32]
  vmovdqu      ymm2, YMMWORD PTR [reg_p1+64]
  vmovdqu      ymm3, YMMWORD PTR [reg_p1+96]        
  vmovdqu      ymm4, YMMWORD PTR [reg_p1+128]
  vmovdqu      ymm5, YMMWORD PTR [reg_p1+160]

  dec          reg_p2                            // Pass over table[1]
  cmovnz       rax, r11
#ifdef __WINDOWS__
  mov          [rsp+32], rax
  vbroadcastss ymm6, DWORD PTR [rsp+32]
#else
  mov          [rsp], rax
  vbroadcastss ymm6, DWORD PTR [rsp]
#endif
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+192]
  vblendvpd    ymm0, ymm7, ymm0, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+224]
  vblendvpd    ymm1, ymm7, ymm1, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+256]
  vblendvpd    ymm2, ymm7, ymm2, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+288]
  vblendvpd    ymm3, ymm7, ymm3, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+320]
  vblendvpd    ymm4, ymm7, ymm4, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+352]
  vblendvpd    ymm5, ymm7, ymm5, ymm6
  
  xor          rax, rax                          // Pass over table[2]
  dec          reg_p2
  cmovnz       rax, r11
#ifdef __WINDOWS__
  mov          [rsp+32], rax
  vbroadcastss ymm6, DWORD PTR [rsp+32]
#else
  mov          [rsp], rax
  vbroadcastss ymm6, DWORD PTR [rsp]
#endif
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+384]
  vblendvpd    ymm0, ymm7, ymm0, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+416]
  vblendvpd    ymm1, ymm7, ymm1, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+448]
  vblendvpd    ymm2, ymm7, ymm2, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+480]
  vblendvpd    ymm3, ymm7, ymm3, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+512]
  vblendvpd    ymm4, ymm7, ymm4, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+544]
  vblendvpd    ymm5, ymm7, ymm5, ymm6
  
  xor          rax, rax                          // Pass over table[3]
  dec          reg_p2
  cmovnz       rax, r11
#ifdef __WINDOWS__
  mov          [rsp+32], rax
  vbroadcastss ymm6, DWORD PTR [rsp+32]
#else
  mov          [rsp], rax
  vbroadcastss ymm6, DWORD PTR [rsp]
#endif
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+576]
  vblendvpd    ymm0, ymm7, ymm0, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+608]
  vblendvpd    ymm1, ymm7, ymm1, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+640]
  vblendvpd    ymm2, ymm7, ymm2, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+672]
  vblendvpd    ymm3, ymm7, ymm3, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+704]
  vblendvpd    ymm4, ymm7, ymm4, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+736]
  vblendvpd    ymm5, ymm7, ymm5, ymm6
  
  xor          rax, rax                          // Pass over table[3]
  dec          reg_p2
  cmovz        r11, rax
#ifdef __WINDOWS__
  mov          [rsp+32], r11
  vbroadcastss ymm6, DWORD PTR [rsp+32]
#else
  mov          [rsp], r11
  vbroadcastss ymm6, DWORD PTR [rsp]
#endif
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+768]
  vblendvpd    ymm0, ymm7, ymm0, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+800]
  vblendvpd    ymm1, ymm7, ymm1, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+832]
  vblendvpd    ymm2, ymm7, ymm2, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+864]
  vblendvpd    ymm3, ymm7, ymm3, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+896]
  vblendvpd    ymm4, ymm7, ymm4, ymm6
  vmovdqu      ymm7, YMMWORD PTR [reg_p1+928]
  vblendvpd    ymm5, ymm7, ymm5, ymm6
    
  vmovdqu      YMMWORD PTR [reg_p3], ymm0       // [reg_p3] = table[index]
  vmovdqu      YMMWORD PTR [reg_p3+32], ymm1
  vmovdqu      YMMWORD PTR [reg_p3+64], ymm2
  vmovdqu      YMMWORD PTR [reg_p3+96], ymm3
  vmovdqu      YMMWORD PTR [reg_p3+128], ymm4
  vmovdqu      YMMWORD PTR [reg_p3+160], ymm5

#ifdef __WINDOWS__    
  vmovdqu      xmm6, XMMWORD PTR [rsp]          // Restore ymm6,7
  vmovdqu      xmm7, XMMWORD PTR [rsp+16] 
  add          rsp, 40

ifdef BEGIN_EPILOGUE
    BEGIN_EPILOGUE
endif  
  ret
NESTED_END complete_lut5_numsp512d1_a, _TEXT00
#else
  add          rsp, 8
  ret
#endif


//****************************************************************************************
// Zeroing field element
//****************************************************************************************
#ifdef __WINDOWS__
LEAF_ENTRY fpzero512_a, _TEXT00
#else
.global fpzero512_a
fpzero512_a:
#endif

  xor          rax, rax
  mov          [reg_p1], rax
  mov          [reg_p1+8], rax 
  mov          [reg_p1+16], rax
  mov          [reg_p1+24], rax 
  mov          [reg_p1+32], rax 
  mov          [reg_p1+40], rax 
  mov          [reg_p1+48], rax 
  mov          [reg_p1+56], rax 
  ret
#ifdef __WINDOWS__
LEAF_END fpzero512_a, _TEXT00
#endif

#ifdef __WINDOWS__
END
#endif
