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

#define TMP  r0
#define TMPR r6
#define TMP2 r7
#define TMP3 r8

/*---------------------------------------------------------------------------
 * Save & restore registers
 *---------------------------------------------------------------------------*/
#define ENC_PUSH \
   push  r2                                                             \n\t \
   push  r3                                                             \n\t \
   push  r4                                                             \n\t \
   push  r5                                                             \n\t \
   push  r6                                                             \n\t \
   push  r7                                                             \n\t \
   push  r8                                                             \n\t \
   push r17                                                             \n\t
   
#define ENC_POP \
   pop r17                                                              \n\t \
   pop  r8                                                              \n\t \
   pop  r7                                                              \n\t \
   pop  r6                                                              \n\t \
   pop  r5                                                              \n\t \
   pop  r4                                                              \n\t \
   pop  r3                                                              \n\t \
   pop  r2                                                              \n\t

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
   push r17                                                             \n\t \
   push r28                                                             \n\t \
   push r29                                                             \n\t

#define EKS_POP \
   pop r29                                                              \n\t \
   pop r28                                                              \n\t \
   pop r17                                                              \n\t \
   pop r13                                                              \n\t \
   pop r12                                                              \n\t \
   pop r11                                                              \n\t \
   pop r10                                                              \n\t \
   pop  r9                                                              \n\t \
   pop  r8                                                              \n\t \
   pop  r7                                                              \n\t \
   pop  r6                                                              \n\t \
   pop  r5                                                              \n\t \
   pop  r4                                                              \n\t \
   pop  r3                                                              \n\t \
   pop  r2                                                              \n\t

/*---------------------------------------------------------------------------
 * Load & save plaintext/ciphertext
 *---------------------------------------------------------------------------*/   
#define LDX_BLOCK \
   ld r18, x+                                                           \n\t \
   ld r19, x+                                                           \n\t \
   ld r20, x+                                                           \n\t \
   ld r21, x+                                                           \n\t \
   ld r22, x+                                                           \n\t \
   ld r23, x+                                                           \n\t \
   ld r24, x+                                                           \n\t \
   ld r25, x                                                            \n\t

#if defined(SCENARIO) & (SCENARIO_2 == SCENARIO)
#define LDZ_RKS \
   lpm r2, z+                                                           \n\t \
   lpm r3, z+                                                           \n\t \
   lpm r4, z+                                                           \n\t \
   lpm r5, z+                                                           \n\t

#else
#define LDZ_RKS \
   ld r2, z+                                                            \n\t \
   ld r3, z+                                                            \n\t \
   ld r4, z+                                                            \n\t \
   ld r5, z+                                                            \n\t

#endif
   
#define STX_BLOCK \
   st  x, r25                                                           \n\t \
   st -x, r24                                                           \n\t \
   st -x, r23                                                           \n\t \
   st -x, r22                                                           \n\t \
   st -x, r21                                                           \n\t \
   st -x, r20                                                           \n\t \
   st -x, r19                                                           \n\t \
   st -x, r18                                                           \n\t
   
/*---------------------------------------------------------------------------
 * F functions
 *---------------------------------------------------------------------------*/
#define F0(X) \
   clr TMP3                                                             \n\t \
   mov TMPR, X                                                          \n\t \
   mov TMP2, X                                                          \n\t \
   bst TMPR, 0                                                          \n\t \
   ror TMPR                                                             \n\t \
   bld TMPR, 7                                                          \n\t \
   lsl TMP2                                                             \n\t \
   adc TMP2, TMP3                                                       \n\t \
   eor TMPR, TMP2                                                       \n\t \
   lsl TMP2                                                             \n\t \
   adc TMP2, TMP3                                                       \n\t \
   eor TMPR, TMP2                                                       \n\t
   
#define F1(X) \
   mov TMPR, X                                                          \n\t \
   mov TMP2, X                                                          \n\t \
   lsr TMP2                                                             \n\t \
   ror TMPR                                                             \n\t \
   lsr TMP2                                                             \n\t \
   ror TMPR                                                             \n\t \
   mov TMP3, TMPR                                                       \n\t \
   lsr TMP2                                                             \n\t \
   ror TMP3                                                             \n\t \
   lsr TMP2                                                             \n\t \
   ror TMP3                                                             \n\t \
   eor TMPR, TMP3                                                       \n\t \
   lsr TMP2                                                             \n\t \
   ror TMP3                                                             \n\t \
   eor TMPR, TMP3                                                       \n\t
   
/*---------------------------------------------------------------------------
 * Macros for EKS
 *---------------------------------------------------------------------------*/
#define LDX_MK \
   ld  r2, x+                                                           \n\t \
   ld  r3, x+                                                           \n\t \
   ld  r4, x+                                                           \n\t \
   ld  r5, x+                                                           \n\t \
   ld  r6, x+                                                           \n\t \
   ld  r7, x+                                                           \n\t \
   ld  r8, x+                                                           \n\t \
   ld  r9, x+                                                           \n\t \
   ld r10, x+                                                           \n\t \
   ld r11, x+                                                           \n\t \
   ld r12, x+                                                           \n\t \
   ld r13, x+                                                           \n\t \
   ld r18, x+                                                           \n\t \
   ld r19, x+                                                           \n\t \
   ld r20, x+                                                           \n\t \
   ld r21, x                                                            \n\t
   
#define LPM_DELTA \
   lpm r22, z+                                                          \n\t \
   lpm r23, z+                                                          \n\t \
   lpm r24, z+                                                          \n\t \
   lpm r25, z+                                                          \n\t
   
#define STY_WKEY \
   st y+, r18                                                           \n\t \
   st y+, r19                                                           \n\t \
   st y+, r20                                                           \n\t \
   st y+, r21                                                           \n\t \
   st y+,  r2                                                           \n\t \
   st y+,  r3                                                           \n\t \
   st y+,  r4                                                           \n\t \
   st y+,  r5                                                           \n\t
   
#define ST_RK(M, D) \
   mov TMP, M                                                           \n\t \
   add TMP, D                                                           \n\t \
   st   y+, TMP                                                         \n\t \
   
#define STY_RK(V1, V2, V3, V4) \
   ST_RK(V1, r22)                                                            \
   ST_RK(V2, r23)                                                            \
   ST_RK(V3, r24)                                                            \
   ST_RK(V4, r25)
   
#define EKS_ROUND \
   LPM_DELTA                                                                 \
   STY_RK(r2, r3, r4, r5)                                                    \
   LPM_DELTA                                                                 \
   STY_RK(r6, r7, r8, r9)                                                    \
   LPM_DELTA                                                                 \
   STY_RK(r10, r11, r12, r13)                                                \
   LPM_DELTA                                                                 \
   STY_RK(r18, r19, r20, r21) 
   
#define EKS_REORDER \
   mov TMP, r9                                                          \n\t \
   mov  r9, r8                                                          \n\t \
   mov  r8, r7                                                          \n\t \
   mov  r7, r6                                                          \n\t \
   mov  r6, r5                                                          \n\t \
   mov  r5, r4                                                          \n\t \
   mov  r4, r3                                                          \n\t \
   mov  r3, r2                                                          \n\t \
   mov  r2, TMP                                                         \n\t \
   mov TMP, r21                                                         \n\t \
   mov r21, r20                                                         \n\t \
   mov r20, r19                                                         \n\t \
   mov r19, r18                                                         \n\t \
   mov r18, r13                                                         \n\t \
   mov r13, r12                                                         \n\t \
   mov r12, r11                                                         \n\t \
   mov r11, r10                                                         \n\t \
   mov r10, TMP                                                         \n\t

/*---------------------------------------------------------------------------
 * Macros for encryption
 *
 *        r0 : temp
 *        r1 : 0
 *  r2 ~  r5 : round keys
 *  r6 ~  r8 : temp
 * r18 ~ r25 : block
 *       r17 : loop counter
 *---------------------------------------------------------------------------*/
#define ENC_F0(O, I, K) \
   F0(I)                                                                     \
   add TMPR,    K                                                       \n\t \
   eor    O, TMPR                                                       \n\t
   
#define ENC_F1(O, I, K) \
   F1(I)                                                                     \
   eor TMPR,    K                                                       \n\t \
   add    O, TMPR                                                       \n\t
 
#define ENC_INIT \
   add r18, r2                                                          \n\t \
   eor r20, r3                                                          \n\t \
   add r22, r4                                                          \n\t \
   eor r24, r5                                                          \n\t
   
#define ENC_FINAL \
   mov TMP, r18                                                         \n\t \
   mov r18, r19                                                         \n\t \
   mov r19, r20                                                         \n\t \
   mov r20, r21                                                         \n\t \
   mov r21, r22                                                         \n\t \
   mov r22, r23                                                         \n\t \
   mov r23, r24                                                         \n\t \
   mov r24, r25                                                         \n\t \
   mov r25, TMP                                                         \n\t \
   add r18,  r2                                                         \n\t \
   eor r20,  r3                                                         \n\t \
   add r22,  r4                                                         \n\t \
   eor r24,  r5                                                         \n\t   
   
#define ENC_ROUND \
   mov TMP, r25                                                         \n\t \
   mov r25, r24                                                         \n\t \
   mov r24, r23                                                         \n\t \
   mov r23, r22                                                         \n\t \
   mov r22, r21                                                         \n\t \
   mov r21, r20                                                         \n\t \
   mov r20, r19                                                         \n\t \
   mov r19, r18                                                         \n\t \
   mov r18, TMP                                                         \n\t \
   ENC_F1(r24, r23, r4)                                                      \
   ENC_F0(r22, r21, r3)                                                      \
   ENC_F1(r20, r19, r2)                                                      \
   ENC_F0(r18, r25, r5)   
   
/*---------------------------------------------------------------------------
 * Macros for decryption
 *
 *        r0 : temp
 *        r1 : 0
 *  r2 ~  r5 : round keys
 *  r6 ~  r8 : temp
 * r18 ~ r25 : block
 *       r17 : loop counter
 *---------------------------------------------------------------------------*/
#define DEC_F0(O, I, K) \
   F0(I)                                                                     \
   add TMPR,    K                                                       \n\t \
   eor    O, TMPR                                                       \n\t
   
#define DEC_F1(O, I, K) \
   F1(I)                                                                     \
   eor TMPR,    K                                                       \n\t \
   sub    O, TMPR                                                       \n\t

#if defined(SCENARIO) & (SCENARIO_2 == SCENARIO)
#define DEC_LDZ_RKS \
   lpm  r2, z+                                                          \n\t \
   lpm  r3, z+                                                          \n\t \
   lpm  r4, z+                                                          \n\t \
   lpm  r5, z+                                                          \n\t \
   sbiw r30, 8                                                          \n\t
   
#else
#define DEC_LDZ_RKS \
   ld r5, -z                                                            \n\t \
   ld r4, -z                                                            \n\t \
   ld r3, -z                                                            \n\t \
   ld r2, -z                                                            \n\t

#endif
   
#define DEC_INIT \
   sub r18, r2                                                          \n\t \
   eor r20, r3                                                          \n\t \
   sub r22, r4                                                          \n\t \
   eor r24, r5                                                          \n\t

#define DEC_FINAL \
   DEC_INIT                                                                  \
   mov TMP, r25                                                         \n\t \
   mov r25, r24                                                         \n\t \
   mov r24, r23                                                         \n\t \
   mov r23, r22                                                         \n\t \
   mov r22, r21                                                         \n\t \
   mov r21, r20                                                         \n\t \
   mov r20, r19                                                         \n\t \
   mov r19, r18                                                         \n\t \
   mov r18, TMP                                                         \n\t   
   
#define DEC_ROUND \
   mov TMP, r18                                                         \n\t \
   mov r18, r19                                                         \n\t \
   mov r19, r20                                                         \n\t \
   mov r20, r21                                                         \n\t \
   mov r21, r22                                                         \n\t \
   mov r22, r23                                                         \n\t \
   mov r23, r24                                                         \n\t \
   mov r24, r25                                                         \n\t \
   mov r25, TMP                                                         \n\t \
   DEC_F1(r19, r18, r2)                                                      \
   DEC_F0(r21, r20, r3)                                                      \
   DEC_F1(r23, r22, r4)                                                      \
   DEC_F0(r25, r24, r5)
   
#endif
#endif
