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

#define CV1   #1
#define CV4   #4
#define CV128 #128

#define TMP0 r10
#define TMP1 r11
#define TMP2 r12

/*---------------------------------------------------------------------------
 * Save & restore registers
 *
 * r4 ~ r11 should be pushed before use
 *---------------------------------------------------------------------------*/
#define PUSH_ALL \
   push  r6                                                             \n\t \
   push  r7                                                             \n\t \
   push  r8                                                             \n\t \
   push  r9                                                             \n\t \
   push r10                                                             \n\t \
   push r11                                                             \n\t
   
#define POP_ALL  \
   pop r11                                                              \n\t \
   pop r10                                                              \n\t \
   pop  r9                                                              \n\t \
   pop  r8                                                              \n\t \
   pop  r7                                                              \n\t \
   pop  r6                                                              \n\t
   
#define PUSH_EKS \
   push  r9                                                             \n\t \
   push r10                                                             \n\t \
   push r11                                                             \n\t
   
#define POP_EKS  \
   pop r11                                                              \n\t \
   pop r10                                                              \n\t \
   pop  r9                                                              \n\t
   
/*---------------------------------------------------------------------------
 * Load & save block data
 *---------------------------------------------------------------------------*/
#define LD_BLOCK \
   mov @r15+, r6                                                        \n\t \
   mov @r15+, r7                                                        \n\t \
   mov @r15+, r8                                                        \n\t \
   mov @r15,  r9                                                        \n\t
   
#define ST_BLOCK \
   mov r9,  0(r15)                                                      \n\t \
   mov r8, -2(r15)                                                      \n\t \
   mov r7, -4(r15)                                                      \n\t \
   mov r6, -6(r15)                                                      \n\t

/*---------------------------------------------------------------------------
 * 64-bit rotations
 *---------------------------------------------------------------------------*/
#define SWAP_LOW(X, Y, T) \
   mov.b X, T                                                           \n\t \
   xor.b Y, T                                                           \n\t \
   xor   T, X                                                           \n\t \
   xor   T, Y                                                           \n\t
   
#define SWAP_BLOCKS(B0, B1, B2, B3) \
   swpb B0                                                              \n\t \
   swpb B1                                                              \n\t \
   swpb B2                                                              \n\t \
   swpb B3                                                              \n\t
   
#define ROR64_8_WO_SWP(B0, B1, B2, B3, T) \
   SWAP_LOW(B3, B2, T)                                                       \
   SWAP_LOW(B2, B1, T)                                                       \
   SWAP_LOW(B1, B0, T)
   
#define ROL64_8_WO_SWP(B0, B1, B2, B3, T) \
   SWAP_LOW(B1, B0, T)                                                       \
   SWAP_LOW(B2, B1, T)                                                       \
   SWAP_LOW(B3, B2, T)

#define ROR64_8(B0, B1, B2, B3, T) \
   SWAP_BLOCKS(B0, B1, B2, B3)                                               \
   ROR64_8_WO_SWP(B0, B1, B2, B3, T)
   
#define ROL64_8(B0, B1, B2, B3, T) \
   ROL64_8_WO_SWP(B0, B1, B2, B3, T)                                         \
   SWAP_BLOCKS(B0, B1, B2, B3)
   
/*---------------------------------------------------------------------------
 * F functions
 *---------------------------------------------------------------------------*/   
#define M_F0(X, T) \
   mov   X, T                                                           \n\t \
   bit.b CV1, X                                                         \n\t \
   rrc.b X                                                              \n\t \
   bit.b CV128, T                                                       \n\t \
   rlc.b T                                                              \n\t \
   xor   T, X                                                           \n\t \
   bit.b CV128, T                                                       \n\t \
   rlc.b T                                                              \n\t \
   xor   T, X                                                           \n\t
   
#define M_F1(X, T0, T1) \
   mov.b  X, T0                                                         \n\t \
   rrc.b T0                                                             \n\t \
   rrc.b  X                                                             \n\t \
   rrc.b T0                                                             \n\t \
   rrc.b  X                                                             \n\t \
   mov.b  X, T1                                                         \n\t \
   rrc.b T0                                                             \n\t \
   rrc.b T1                                                             \n\t \
   rrc.b T0                                                             \n\t \
   rrc.b T1                                                             \n\t \
   xor.b T1,  X                                                         \n\t \
   rrc.b T0                                                             \n\t \
   rrc.b T1                                                             \n\t \
   xor.b T1,  X                                                         \n\t 
   
/*---------------------------------------------------------------------------
 * Macros for EKS
 *
 *  r9 - temp
 * r10 - delta ptr
 * r11 - delta index
 * r12 - loop counter
 * r13 - loop counter
 * r14 - round keys ptr
 * r15 - master key
 *---------------------------------------------------------------------------*/
#define ST_WKEY \
   mov 12(r15), 0(r14)                                                   \n\t\
   mov 14(r15), 2(r14)                                                   \n\t\
   mov  0(r15), 4(r14)                                                   \n\t\
   mov  2(r15), 6(r14)                                                   \n\t
   
#define EKS_SUBROUND1 \
   mov.b 0(r11), r9    \n\t \
   add.b 0(r10), r9    \n\t \
   mov.b     r9, 8(r14) \n\t

#define EKS_SUBROUND2 \
   mov.b 8(r11), r9     \n\t \
   add.b 8(r10), r9     \n\t \
   mov.b     r9, 16(r14) \n\t
   
/*---------------------------------------------------------------------------
 * Macros for encryption
 *
 *  r4 ~  r7 : block 
 *       r14 : round keys ptr
 *       r15 : block ptr
 *---------------------------------------------------------------------------*/
#define ENC_F0(X, K, T0, T1) \
   mov.b  X, T0                                                         \n\t \
   M_F0(T0, T1)                                                              \
   mov    K, T1                                                         \n\t \
   swpb  T1                                                             \n\t \
   add.b T1, T0                                                         \n\t \
   swpb   X                                                             \n\t \
   xor.b  X, T0                                                         \n\t \
   xor.b  X, T0                                                         \n\t \
   xor   T0,  X                                                         \n\t
   
#define ENC_F1(X, K, T0, T1, T2) \
   mov.b  X, T0                                                         \n\t \
   M_F1(T0, T1, T2)                                                          \
   xor.b  K, T0                                                         \n\t \
   swpb   X                                                             \n\t \
   add.b  X, T0                                                         \n\t \
   xor.b  X, T0                                                         \n\t \
   xor   T0,  X                                                         \n\t 
   
#define ENC_INIT_ADD(X, K, T) \
   mov.b X, T                                                           \n\t \
   add.b K, T                                                           \n\t \
   xor.b X, T                                                           \n\t \
   xor   T, X                                                           \n\t
   
#define ENC_INIT_XOR(X, K, T0, T1) \
   mov.b  X, T0                                                         \n\t \
   mov    K, T1                                                         \n\t \
   swpb  T1                                                             \n\t \
   xor.b T1, T0                                                         \n\t \
   xor.b  X, T0                                                         \n\t \
   xor   T0,  X                                                         \n\t
   
#define ENC_INIT \
   ENC_INIT_ADD(r6, 0(r14), TMP0)                                            \
   ENC_INIT_XOR(r7, 0(r14), TMP0, TMP1)                                      \
   ENC_INIT_ADD(r8, 2(r14), TMP0)                                            \
   ENC_INIT_XOR(r9, 2(r14), TMP0, TMP1)

#define ENC_FINAL \
   ROL64_8(r6, r7, r8, r9, TMP0)                                             \
   ENC_INIT
   
#define ENC_ROUND                                                            \
   ENC_F1(r6, 0(r14), TMP0, TMP1, TMP2)                                      \
   ENC_F0(r7, 0(r14), TMP0, TMP1)                                            \
   ENC_F1(r8, 2(r14), TMP0, TMP1, TMP2)                                      \
   ENC_F0(r9, 2(r14), TMP0, TMP1)                                            \
   ROR64_8_WO_SWP(r6, r7, r8, r9, TMP0)

/*---------------------------------------------------------------------------
 * Macros for decryption
 *
 *  r4 ~  r7 : block 
 *       r14 : round keys ptr
 *       r15 : block ptr
 *---------------------------------------------------------------------------*/
#define DEC_F0(X, K, T0, T1) \
   mov.b  X, T0                                                         \n\t \
   M_F0(T0, T1)                                                              \
   mov    K, T1                                                         \n\t \
   swpb  T1                                                             \n\t \
   add.b T1, T0                                                         \n\t \
   mov    X, T1                                                         \n\t \
   swpb  T1                                                             \n\t \
   xor.b T0, T1                                                         \n\t \
   swpb  T1                                                             \n\t \
   mov.b  X,  X                                                         \n\t \
   xor   T1,  X                                                         \n\t

#define DEC_F1(X, K, T0, T1, T2) \
   mov.b  X, T0                                                         \n\t \
   M_F1(T0, T1, T2)                                                          \
   xor.b  K, T0                                                         \n\t \
   mov    X, T1                                                         \n\t \
   swpb  T1                                                             \n\t \
   sub.b T0, T1                                                         \n\t \
   swpb  T1                                                             \n\t \
   mov.b  X,  X                                                         \n\t \
   xor   T1,  X                                                         \n\t

#define DEC_INIT_EVEN(X, K, T, T1) \
   mov    X,  T                                                         \n\t \
   sub.b  K,  T                                                         \n\t \
   mov.b  X, T1                                                         \n\t \
   xor.b  T, T1                                                         \n\t \
   xor   T1,  X                                                         \n\t

#define DEC_INIT_ODD(X, K, T, T1) \
   mov    X,  T                                                         \n\t \
   mov    K, T1                                                         \n\t \
   swpb  T1                                                             \n\t \
   xor.b T1,  T                                                         \n\t \
   mov.b  X, T1                                                         \n\t \
   xor.b  T, T1                                                         \n\t \
   xor   T1,  X                                                         \n\t
   
#define DEC_INIT_SUB(X, K, T) \
   mov.b X, T                                                           \n\t \
   sub.b K, T                                                           \n\t \
   xor.b X, T                                                           \n\t \
   xor   T, X                                                           \n\t
   
#define DEC_INIT_XOR(X, K, T0, T1) \
   mov.b  X, T0                                                         \n\t \
   mov    K, T1                                                         \n\t \
   swpb  T1                                                             \n\t \
   xor.b T1, T0                                                         \n\t \
   xor.b  X, T0                                                         \n\t \
   xor   T0,  X                                                         \n\t
   
#define DEC_INIT \
   DEC_INIT_SUB(r6, 0(r14), TMP0)                                            \
   DEC_INIT_XOR(r7, 0(r14), TMP0, TMP1)                                      \
   DEC_INIT_SUB(r8, 2(r14), TMP0)                                            \
   DEC_INIT_XOR(r9, 2(r14), TMP0, TMP1)
   
#define DEC_FINAL \
   DEC_INIT                                                                  \
   ROR64_8(r6, r7, r8, r9, TMP0)

#define DEC_ROUND \
   ROL64_8(r6, r7, r8, r9, TMP0)                                             \
   DEC_F1(r6, 0(r14), TMP0, TMP1, TMP2)                                      \
   DEC_F0(r7, 0(r14), TMP0, TMP1)                                            \
   DEC_F1(r8, 2(r14), TMP0, TMP1, TMP2)                                      \
   DEC_F0(r9, 2(r14), TMP0, TMP1)   
 
#endif
#endif
