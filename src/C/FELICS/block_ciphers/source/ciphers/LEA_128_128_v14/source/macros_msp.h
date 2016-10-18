/*
 *
 * National Security Research Institute
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 National Security Research Institute
 *
 * Written in 2015 by Ilwoong Jeong <iw98jeong@nsr.re.kr>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License,or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _MACROS_MSP_H_
#define _MACROS_MSP_H_
#if defined(MSP)

#include "strfy.h"

#define NAKED __attribute__((naked))

#define LSB #1

/*---------------------------------------------------------------------------
 * Save & restore registers
 *---------------------------------------------------------------------------*/
#define PUSH_ALL \
   push  r4                                                             \n\t \
   push  r5                                                             \n\t \
   push  r6                                                             \n\t \
   push  r7                                                             \n\t \
   push  r8                                                             \n\t \
   push  r9                                                             \n\t \
   push r10                                                             \n\t \
   push r11                                                             \n\t \
   push r12                                                             \n\t \
   push r13                                                             \n\t \
   push r14                                                             \n\t \
   push r15                                                             \n\t

#define POP_ALL  \
   pop r14                                                              \n\t \
   pop r13                                                              \n\t \
   pop r12                                                              \n\t \
   pop r11                                                              \n\t \
   pop r10                                                              \n\t \
   pop  r9                                                              \n\t \
   pop  r8                                                              \n\t \
   pop  r7                                                              \n\t \
   pop  r6                                                              \n\t \
   pop  r5                                                              \n\t \
   pop  r4                                                              \n\t

/*---------------------------------------------------------------------------
 * Load & save plaintext/ciphertext
 *---------------------------------------------------------------------------*/
#define LD_BLOCK(X) \
   MOV @X+,  r4                                                         \n\t \
   MOV @X+,  r5                                                         \n\t \
   MOV @X+,  r6                                                         \n\t \
   MOV @X+,  r7                                                         \n\t \
   MOV @X+,  r8                                                         \n\t \
   MOV @X+,  r9                                                         \n\t \
   MOV @X+, r10                                                         \n\t \
   MOV @X+, r11                                                         \n\t
   
#define ST_BLOCK(X)   \
   mov  r4,  0(X)                                                       \n\t \
   mov  r5,  2(X)                                                       \n\t \
   mov  r6,  4(X)                                                       \n\t \
   mov  r7,  6(X)                                                       \n\t \
   mov  r8,  8(X)                                                       \n\t \
   mov  r9, 10(X)                                                       \n\t \
   mov r10, 12(X)                                                       \n\t \
   mov r11, 14(X)                                                       \n\t

/*---------------------------------------------------------------------------
 * Left rotations for 32-bit word
 *---------------------------------------------------------------------------*/
#define ROL1(H, L) \
   rla L                                                                \n\t \
   rlc H                                                                \n\t \
   adc L                                                                \n\t

#define ROL3(H, L) \
   ROL1(H, L)                                                                \
   ROL1(H, L)                                                                \
   ROL1(H, L)                                                               

#define ROL5(H, L) \
   ROL3(H, L)                                                                \
   ROL1(H, L)                                                                \
   ROL1(H, L)                                                               

#define ROL6(H, L) \
   ROL3(H, L)                                                                \
   ROL3(H, L)                                                               

#define ROL8(H, L, T) \
   swpb  H                                                              \n\t \
   swpb  L                                                              \n\t \
   mov.b H, T                                                           \n\t \
   xor.b L, T                                                           \n\t \
   xor   T, H                                                           \n\t \
   xor   T, L                                                           \n\t

#define ROL9(H, L, T) \
   ROL8(H, L, T)                                                             \
   ROL1(H, L)                                                               

#define ROL11(H, L, T) \
   ROL8(H, L, T)                                                             \
   ROL3(H, L)                                                               

/*---------------------------------------------------------------------------
 * Right rotations for 32-bit word
 *---------------------------------------------------------------------------*/
#define ROR1(H, L) \
   bit LSB, L                                                           \n\t \
   rrc H                                                                \n\t \
   rrc L                                                                \n\t

#define ROR3(H, L) \
   ROR1(H, L)                                                                \
   ROR1(H, L)                                                                \
   ROR1(H, L)                                                               

#define ROR5(H, L) \
   ROR3(H, L)                                                                \
   ROR1(H, L)                                                                \
   ROR1(H, L)

#define ROR8(H, L, T) \
   mov.b H, T                                                           \n\t \
   xor.b L, T                                                           \n\t \
   xor   T, H                                                           \n\t \
   xor   T, L                                                           \n\t \
   swpb  H                                                              \n\t \
   swpb  L                                                              \n\t

#define ROR9(H, L, T) \
   ROR8(H, L, T)                                                             \
   ROR1(H, L)                                                               

/*---------------------------------------------------------------------------
 * Rotations for 128-bit word
 *---------------------------------------------------------------------------*/
#define ROL128_32 \
   mov r11, r13                                                         \n\t \
   mov r10, r12                                                         \n\t \
   mov  r9, r11                                                         \n\t \
   mov  r8, r10                                                         \n\t \
   mov  r7,  r9                                                         \n\t \
   mov  r6,  r8                                                         \n\t \
   mov  r5,  r7                                                         \n\t \
   mov  r4,  r6                                                         \n\t \
   mov r13,  r5                                                         \n\t \
   mov r12,  r4                                                         \n\t
   
#define ROR128_32 \
   mov  r4, r12                                                         \n\t \
   mov  r5, r13                                                         \n\t \
   mov  r6,  r4                                                         \n\t \
   mov  r7,  r5                                                         \n\t \
   mov  r8,  r6                                                         \n\t \
   mov  r9,  r7                                                         \n\t \
   mov r10,  r8                                                         \n\t \
   mov r11,  r9                                                         \n\t \
   mov r12, r10                                                         \n\t \
   mov r13, r11                                                         \n\t
   
/*---------------------------------------------------------------------------
 * Macros for key scheduling
 *---------------------------------------------------------------------------*/
#define LD_KEY(X) \
   mov @(X)+,  r5                                                       \n\t \
   mov @(X)+,  r4                                                       \n\t \
   mov @(X)+,  r7                                                       \n\t \
   mov @(X)+,  r6                                                       \n\t \
   mov @(X)+,  r9                                                       \n\t \
   mov @(X)+,  r8                                                       \n\t \
   mov @(X)+, r11                                                       \n\t \
   mov @(X)+, r10                                                       \n\t
 
#define ST_KEY(X) \
   mov  r7,  0(X)                                                       \n\t \
   mov  r6,  2(X)                                                       \n\t \
   mov r11,  4(X)                                                       \n\t \
   mov r10,  6(X)                                                       \n\t \
   mov  r9,  8(X)                                                       \n\t \
   mov  r8, 10(X)                                                       \n\t \
   mov  r5, 12(X)                                                       \n\t \
   mov  r4, 14(X)                                                       \n\t
   
#define EKS_SUBR(XH, XL, KH, KL) \
   add  KL, XL                                                          \n\t \
   addc KH, XH                                                          \n\t \
   ROL1(KH, KL)
   
#define EKS_ROUND \
   mov @r15+, r13                                                       \n\t \
   mov @r15+, r12                                                       \n\t \
   EKS_SUBR(r4, r5, r12, r13)                                                \
   ROL1(r4, r5)                                                              \
   EKS_SUBR(r6, r7, r12, r13)                                                \
   ROL3(r6, r7)                                                              \
   EKS_SUBR(r8, r9, r12, r13)                                                \
   ROL6(r8, r9)                                                              \
   EKS_SUBR(r10, r11, r12, r13)                                              \
   mov r12, -2(r15)                                                     \n\t \
   mov r13, -4(r15)                                                     \n\t \
   ROL11(r10, r11, r12)

/*---------------------------------------------------------------------------
 * Macros for encryption
 *---------------------------------------------------------------------------*/
#define ENC_SUBR1(XH, XL, YH, YL, K, TH, TL) \
   xor  0(K), XL                                                        \n\t \
   xor  2(K), XH                                                        \n\t \
   mov  4(K), TL                                                        \n\t \
   mov  6(K), TH                                                        \n\t \
   xor    YL, TL                                                        \n\t \
   xor    YH, TH                                                        \n\t \
   add    TL, XL                                                        \n\t \
   addc   TH, XH                                                        \n\t \
   ROR3(XH, XL)

#define ENC_SUBR2(XH, XL, YH, YL, K, TH, TL) \
   xor   0(K), XL                                                       \n\t \
   xor   2(K), XH                                                       \n\t \
   mov   8(K), TL                                                       \n\t \
   mov  10(K), TH                                                       \n\t \
   xor     YL, TL                                                       \n\t \
   xor     YH, TH                                                       \n\t \
   add     TL, XL                                                       \n\t \
   addc    TH, XH                                                       \n\t \
   ROR5(XH, XL)
   
#define ENC_SUBR3(XH, XL, YH, YL, K, TH, TL) \
   xor   0(K), XL                                                       \n\t \
   xor   2(K), XH                                                       \n\t \
   mov  12(K), TL                                                       \n\t \
   mov  14(K), TH                                                       \n\t \
   xor     YL, TL                                                       \n\t \
   xor     YH, TH                                                       \n\t \
   add     TL, XL                                                       \n\t \
   addc    TH, XH                                                       \n\t \
   ROL9(XH, XL, TH)
   
#define ENC_ROUND \
   ENC_SUBR1(r11, r10, r9, r8, r14, r12, r13)                                \
   ENC_SUBR2( r9,  r8, r7, r6, r14, r12, r13)                                \
   ENC_SUBR3( r7,  r6, r5, r4, r14, r12, r13)

/*---------------------------------------------------------------------------
 * Macros for decryption
 *---------------------------------------------------------------------------*/
#define DEC_SUBR1(XH, XL, YH, YL, K, TH, TL) \
   ROR9(XH, XL, TH)                                                          \
   mov 12(K), TL                                                        \n\t \
   mov 14(K), TH                                                        \n\t \
   xor    YL, TL                                                        \n\t \
   xor    YH, TH                                                        \n\t \
   sub    TL, XL                                                        \n\t \
   subc   TH, XH                                                        \n\t \
   xor  0(K), XL                                                        \n\t \
   xor  2(K), XH                                                        \n\t
   
#define DEC_SUBR2(XH, XL, YH, YL, K, TH, TL) \
   ROL5(XH, XL)                                                              \
   mov  8(K), TL                                                        \n\t \
   mov 10(K), TH                                                        \n\t \
   xor    YL, TL                                                        \n\t \
   xor    YH, TH                                                        \n\t \
   sub    TL, XL                                                        \n\t \
   subc   TH, XH                                                        \n\t \
   xor  0(K), XL                                                        \n\t \
   xor  2(K), XH                                                        \n\t
   
#define DEC_SUBR3(XH, XL, YH, YL, K, TH, TL) \
   ROL3(XH, XL)                                                              \
   mov  4(K), TL                                                        \n\t \
   mov  6(K), TH                                                        \n\t \
   xor    YL, TL                                                        \n\t \
   xor    YH, TH                                                        \n\t \
   sub    TL, XL                                                        \n\t \
   subc   TH, XH                                                        \n\t \
   xor  0(K), XL                                                        \n\t \
   xor  2(K), XH                                                        \n\t

#define DEC_ROUND \
   DEC_SUBR1( r5, r4, r11, r10, r14, r12, r13)                               \
   DEC_SUBR2( r7, r6,  r5,  r4, r14, r12, r13)                               \
   DEC_SUBR3( r9, r8,  r7,  r6, r14, r12, r13)

#endif
#endif
