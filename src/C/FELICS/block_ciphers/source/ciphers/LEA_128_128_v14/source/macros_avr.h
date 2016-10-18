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

#ifndef _MACROS_AVR_H_
#define _MACROS_AVR_H_
#if defined(AVR)

#include "strfy.h"

#define NAKED __attribute__((naked))
#define  TMP r0
#define ZERO r1

/*---------------------------------------------------------------------------
 * Save & restore registers
 *---------------------------------------------------------------------------*/
#define PUSH_ALL \
   push  r2                                                             \n\t \
   push  r3                                                             \n\t \
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
   push r15                                                             \n\t \
   push r16                                                             \n\t \
   push r17                                                             \n\t \
   push r28                                                             \n\t \
   push r29                                                             \n\t

#define POP_ALL  \
   pop  r29                                                             \n\t \
   pop  r28                                                             \n\t \
   pop  r17                                                             \n\t \
   pop  r16                                                             \n\t \
   pop  r15                                                             \n\t \
   pop  r14                                                             \n\t \
   pop  r13                                                             \n\t \
   pop  r12                                                             \n\t \
   pop  r11                                                             \n\t \
   pop  r10                                                             \n\t \
   pop   r9                                                             \n\t \
   pop   r8                                                             \n\t \
   pop   r7                                                             \n\t \
   pop   r6                                                             \n\t \
   pop   r5                                                             \n\t \
   pop   r4                                                             \n\t \
   pop   r3                                                             \n\t \
   pop   r2                                                             \n\t

/*---------------------------------------------------------------------------
 * Load & save plaintext/ciphertext
 *---------------------------------------------------------------------------*/
#define LDY_BLOCK \
   ld  r2, y+                                                           \n\t \
   ld  r3, y+                                                           \n\t \
   ld  r4, y+                                                           \n\t \
   ld  r5, y+                                                           \n\t \
   ld  r6, y+                                                           \n\t \
   ld  r7, y+                                                           \n\t \
   ld  r8, y+                                                           \n\t \
   ld  r9, y+                                                           \n\t \
   ld r10, y+                                                           \n\t \
   ld r11, y+                                                           \n\t \
   ld r12, y+                                                           \n\t \
   ld r13, y+                                                           \n\t \
   ld r14, y+                                                           \n\t \
   ld r15, y+                                                           \n\t \
   ld r16, y+                                                           \n\t \
   ld r17, y+                                                           \n\t
   
#define STX_BLOCK \
   st x+,  r2                                                           \n\t \
   st x+,  r3                                                           \n\t \
   st x+,  r4                                                           \n\t \
   st x+,  r5                                                           \n\t \
   st x+,  r6                                                           \n\t \
   st x+,  r7                                                           \n\t \
   st x+,  r8                                                           \n\t \
   st x+,  r9                                                           \n\t \
   st x+, r10                                                           \n\t \
   st x+, r11                                                           \n\t \
   st x+, r12                                                           \n\t \
   st x+, r13                                                           \n\t \
   st x+, r14                                                           \n\t \
   st x+, r15                                                           \n\t \
   st x+, r16                                                           \n\t \
   st x+, r17                                                           \n\t
 
/*---------------------------------------------------------------------------
 * Operations for 32-bit word
 *---------------------------------------------------------------------------*/
#define ADD32(X1, X2 ,X3, X4, Y1, Y2, Y3, Y4) \
   add X1, Y1                                                           \n\t \
   adc X2, Y2                                                           \n\t \
   adc X3, Y3                                                           \n\t \
   adc X4, Y4                                                           \n\t

#define SUB32(X1, X2, X3, X4, Y1, Y2, Y3, Y4) \
   sub X1, Y1                                                           \n\t \
   sbc X2, Y2                                                           \n\t \
   sbc X3, Y3                                                           \n\t \
   sbc X4, Y4                                                           \n\t
   
#define EOR32(X1, X2 ,X3, X4, Y1, Y2, Y3, Y4) \
   eor X1, Y1                                                           \n\t \
   eor X2, Y2                                                           \n\t \
   eor X3, Y3                                                           \n\t \
   eor X4, Y4                                                           \n\t

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define LDZ32(X1, X2, X3, X4) \
   lpm X1, z+                                                           \n\t \
   lpm X2, z+                                                           \n\t \
   lpm X3, z+                                                           \n\t \
   lpm X4, z+                                                           \n\t
   
#define LDMZ32(X1, X2, X3, X4) \
   lpm X1, z+                                                           \n\t \
   lpm X2, z+                                                           \n\t \
   lpm X3, z+                                                           \n\t \
   lpm X4, z+                                                           \n\t \
   sbiw r30, 8                                                          \n\t

#else
#define LDZ32(X1, X2, X3, X4) \
   ld X1, z+                                                            \n\t \
   ld X2, z+                                                            \n\t \
   ld X3, z+                                                            \n\t \
   ld X4, z+                                                            \n\t
   
#define LDMZ32(X1, X2, X3, X4) \
   ld X4, -z                                                            \n\t \
   ld X3, -z                                                            \n\t \
   ld X2, -z                                                            \n\t \
   ld X1, -z                                                            \n\t

#endif

/*---------------------------------------------------------------------------
 * Left rotations for 32-bit word
 *---------------------------------------------------------------------------*/
#define ROL1(X1, X2, X3, X4) \
   lsl X1                                                               \n\t \
   rol X2                                                               \n\t \
   rol X3                                                               \n\t \
   rol X4                                                               \n\t \
   adc X1, ZERO                                                         \n\t
   
#define ROL3(X1, X2, X3, X4) \
   ROL1(X1, X2, X3, X4)                                                      \
   ROL1(X1, X2, X3, X4)                                                      \
   ROL1(X1, X2, X3, X4)
   
#define ROL8(X1, X2, X3, X4) \
   mov TMP, X4                                                          \n\t \
   mov  X4, X3                                                          \n\t \
   mov  X3, X2                                                          \n\t \
   mov  X2, X1                                                          \n\t \
   mov  X1, TMP                                                         \n\t

/*---------------------------------------------------------------------------
 * Right rotations for 32-bit word
 *---------------------------------------------------------------------------*/
#define ROR1(X1, X2, X3, X4) \
   bst X1, 0                                                            \n\t \
   lsr X4                                                               \n\t \
   ror X3                                                               \n\t \
   ror X2                                                               \n\t \
   ror X1                                                               \n\t \
   bld X4, 7                                                            \n\t
   
#define ROR2(X1, X2, X3, X4) \
   ROR1(X1, X2, X3, X4)                                                      \
   ROR1(X1, X2, X3, X4)                                                     
 
#define ROR3(X1, X2, X3, X4) \
   clr TMP                                                              \n\t \
   lsr X4                                                               \n\t \
   ror X3                                                               \n\t \
   ror X2                                                               \n\t \
   ror X1                                                               \n\t \
   ror TMP                                                              \n\t \
   lsr X4                                                               \n\t \
   ror X3                                                               \n\t \
   ror X2                                                               \n\t \
   ror X1                                                               \n\t \
   ror TMP                                                              \n\t \
   lsr X4                                                               \n\t \
   ror X3                                                               \n\t \
   ror X2                                                               \n\t \
   ror X1                                                               \n\t \
   ror TMP                                                              \n\t \
   eor X4, TMP                                                          \n\t
   
#define ROR8(X1, X2, X3, X4) \
   mov TMP, X1                                                          \n\t \
   mov  X1, X2                                                          \n\t \
   mov  X2, X3                                                          \n\t \
   mov  X3, X4                                                          \n\t \
   mov  X4, TMP                                                         \n\t

/*---------------------------------------------------------------------------
 * Macros for key scheduling
 *
 *        R0 : temp
 *        R1 : 0
 *  R2 ~ R13 : round keys
 * R18 ~ R21 : round keys
 * R22 ~ R25 : delta
 *       R28 : loop counter
 *       R29 : delta index
 *---------------------------------------------------------------------------*/
#define EKS_PUSH \
   push  r2                                                             \n\t \
   push  r3                                                             \n\t \
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
   push r28                                                             \n\t \
   push r29                                                             \n\t

#define EKS_POP  \
   pop  r29                                                             \n\t \
   pop  r28                                                             \n\t \
   pop  r13                                                             \n\t \
   pop  r12                                                             \n\t \
   pop  r11                                                             \n\t \
   pop  r10                                                             \n\t \
   pop   r9                                                             \n\t \
   pop   r8                                                             \n\t \
   pop   r7                                                             \n\t \
   pop   r6                                                             \n\t \
   pop   r5                                                             \n\t \
   pop   r4                                                             \n\t \
   pop   r3                                                             \n\t \
   pop   r2                                                             \n\t

#define LDY_KEY \
   ld  r2, y+                                                           \n\t \
   ld  r3, y+                                                           \n\t \
   ld  r4, y+                                                           \n\t \
   ld  r5, y+                                                           \n\t \
   ld  r6, y+                                                           \n\t \
   ld  r7, y+                                                           \n\t \
   ld  r8, y+                                                           \n\t \
   ld  r9, y+                                                           \n\t \
   ld r10, y+                                                           \n\t \
   ld r11, y+                                                           \n\t \
   ld r12, y+                                                           \n\t \
   ld r13, y+                                                           \n\t \
   ld r18, y+                                                           \n\t \
   ld r19, y+                                                           \n\t \
   ld r20, y+                                                           \n\t \
   ld r21, y+                                                           \n\t
   
#define STX_RKS \
   st x+,  r6                                                           \n\t \
   st x+,  r7                                                           \n\t \
   st x+,  r8                                                           \n\t \
   st x+,  r9                                                           \n\t \
   st x+, r18                                                           \n\t \
   st x+, r19                                                           \n\t \
   st x+, r20                                                           \n\t \
   st x+, r21                                                           \n\t \
   st x+, r10                                                           \n\t \
   st x+, r11                                                           \n\t \
   st x+, r12                                                           \n\t \
   st x+, r13                                                           \n\t \
   st x+,  r2                                                           \n\t \
   st x+,  r3                                                           \n\t \
   st x+,  r4                                                           \n\t \
   st x+,  r5                                                           \n\t
 
#define EKS_SUBR1(T1, T2, T3, T4, D1, D2, D3, D4) \
   ADD32(T1, T2, T3, T4, D1, D2, D3, D4)                                     \
   ROL1(D1, D2, D3, D4)                                                      \
   ROL1(T1, T2, T3, T4)

#define EKS_SUBR3(T1, T2, T3, T4, D1, D2, D3, D4) \
   ADD32(T1, T2, T3, T4, D1, D2, D3, D4)                                     \
   ROL1(D1, D2, D3, D4)                                                      \
   ROL3(T1, T2, T3, T4)

#define EKS_SUBR6(T1, T2, T3, T4, D1, D2, D3, D4) \
   ADD32(T1, T2, T3, T4, D1, D2, D3, D4)                                     \
   ROL1(D1, D2, D3, D4)                                                      \
   ROR2(T1, T2, T3, T4)

#define EKS_SUBR11(T1, T2, T3, T4, D1, D2, D3, D4) \
   ADD32(T1, T2, T3, T4, D1, D2, D3, D4)                                     \
   ROL1(D1, D2, D3, D4)                                                      \
   ROL3(T1, T2, T3, T4)
   
#define EKS_ROUND \
   LDZ_DELTA(r22, r23, r24, r25)                                             \
   EKS_SUBR1(  r2,  r3,  r4,  r5, r22, r23, r24, r25)                        \
   EKS_SUBR3(  r6,  r7,  r8,  r9, r22, r23, r24, r25)                        \
   EKS_SUBR6( r10, r11, r12, r13, r22, r23, r24, r25)                        \
   EKS_SUBR11(r18, r19, r20, r21, r22, r23, r24, r25)                        \
   STZ_DELTA(r22, r23, r24, r25)                                             \
   EKS_REORDER \
   STX_RKS
   
#define EKS_REORDER \
   ROL8(r10, r11, r12, r13)                                                  \
   ROL8(r18, r19, r20, r21)

#define LDZ_DELTA(D1, D2, D3, D4) \
   ld  D1, z                                                            \n\t \
   ldd D2, z+1                                                          \n\t \
   ldd D3, z+2                                                          \n\t \
   ldd D4, z+3                                                          \n\t
   
#define STZ_DELTA(D1, D2, D3, D4) \
   st z+, D1                                                            \n\t \
   st z+, D2                                                            \n\t \
   st z+, D3                                                            \n\t \
   st z+, D4                                                            \n\t
   
/*---------------------------------------------------------------------------
 * Macros for encryption
 *
 *        R0 : temp
 *        R1 : 0
 *  R2 ~ R17 : block
 * R18 ~ R25 : round keys
 *       R29 : loop counter
 *---------------------------------------------------------------------------*/
#define ENC_SUBR(X1, X2, X3, X4, X5, X6, X7, X8) \
   EOR32( X1,  X2,  X3,  X4, r18, r19, r20, r21)                             \
   LDZ32(r22, r23, r24, r25)                                                 \
   EOR32(r22, r23, r24, r25, X5,  X6,  X7,  X8)                             \
   ADD32(X1, X2, X3, X4, r22, r23, r24, r25)

#define ENC_ROUND \
   LDZ32(r18, r19, r20, r21)                                                 \
   ENC_SUBR(r14, r15, r16, r17, r10, r11, r12, r13)                          \
   ROR3(r14, r15, r16, r17)                                                  \
   ENC_SUBR(r10, r11, r12, r13,  r6,  r7,  r8,  r9)                          \
   ROL3(r10, r11, r12, r13)                                                   \
   ENC_SUBR( r6,  r7,  r8,  r9,  r2,  r3,  r4,  r5)                          \
   ROL1(r6, r7, r8, r9)
 
#define ENC_REORDER(T) \
   ROR8( r2,  r9, r10, r14)                                                  \
   ROR8( r3,  r6, r11, r15)                                                  \
   ROR8( r4,  r7, r12, r16)                                                  \
   ROR8( r5,  r8, r13, r17)
 
/*---------------------------------------------------------------------------
 * Macros for decryption
 *
 *        R0 : temp
 *        R1 : 0
 *  R2 ~ R17 : block
 * R18 ~ R25 : round keys
 *       R29 : loop counter
 *---------------------------------------------------------------------------*/
#define DEC_SUBR(X1, X2, X3, X4, X5, X6, X7, X8) \
   LDMZ32(r22, r23, r24, r25)                                                \
   EOR32 (r22, r23, r24, r25, X5, X6, X7, X8)                                \
   SUB32 ( X1,  X2,  X3,  X4, r22, r23, r24, r25)                            \
   EOR32 ( X1,  X2,  X3,  X4, r18, r19, r20, r21)

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define DEC_ROUND \
   LDZ32(r18, r19, r20, r21)                                                 \
   \
   adiw r30, 8                                                          \n\t \
   \
   ROR1(r2, r3, r4, r5)                                                      \
   DEC_SUBR(r3, r4, r5, r2, r14, r15, r16, r17)                              \
   \
   ROR3(r6, r7, r8, r9)                                                      \
   DEC_SUBR(r9, r6, r7, r8, r3, r4, r5, r2)                                  \
   \
   ROL3(r10, r11, r12, r13)                                                  \
   DEC_SUBR(r10, r11, r12, r13, r9, r6, r7, r8)                              \
   \
   sbiw r30, 16                                                          \n\t

#else
#define DEC_ROUND \
   LDZ32(r18, r19, r20, r21)                                                 \
   \
   adiw r30, 12                                                         \n\t \
   \
   ROR1(r2, r3, r4, r5)                                                      \
   DEC_SUBR(r3, r4, r5, r2, r14, r15, r16, r17)                              \
   \
   ROR3(r6, r7, r8, r9)                                                      \
   DEC_SUBR(r9, r6, r7, r8, r3, r4, r5, r2)                                  \
   \
   ROL3(r10, r11, r12, r13)                                                  \
   DEC_SUBR(r10, r11, r12, r13, r9, r6, r7, r8)                              \
   \
   sbiw r30, 20                                                         \n\t

#endif

#define DEC_REORDER(T) \
   ROL8( r9, r10, r14,  r2)                                                  \
   ROL8( r6, r11, r15,  r3)                                                  \
   ROL8( r7, r12, r16,  r4)                                                  \
   ROL8( r8, r13, r17,  r5)
 
#endif
#endif
