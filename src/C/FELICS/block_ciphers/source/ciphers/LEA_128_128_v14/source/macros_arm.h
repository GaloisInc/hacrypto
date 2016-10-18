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

#ifndef _MACROS_ARM_H_
#define _MACROS_ARM_H_
#if defined(ARM)

#include "strfy.h"

#define NAKED __attribute__((naked))

#define TMP r3

#define  RL1 #31
#define  RL2 #30
#define  RL3 #29
#define  RL4 #28
#define  RL5 #27
#define  RL6 #26
#define  RL9 #23
#define RL11 #21
#define  RR3  #3
#define  RR5  #5
#define  RR9  #9

/*---------------------------------------------------------------------------
 * Macros for key scheduling
 *---------------------------------------------------------------------------*/
#define EKS_ROUND(T0, T1, T2, T3, D) \
   add    T0, T0, D, ror RL1                                            \n\t \
   mov    T0, T0, ror RL3                                               \n\t \
   add    T1, T1, D, ror RL3                                            \n\t \
   mov    T1, T1, ror RL11                                              \n\t \
   add    T2, T2, D, ror RL2                                            \n\t \
   mov    T2, T2, ror RL6                                               \n\t \
   add    T3, T3, D                                                     \n\t \
   mov    T3, T3, ror RL1                                               \n\t \
   stmia r1!, {T0-T3}                                                   \n\t
   
#define KEY_REORDER(K0, K1, K2, K3) \
   mov TMP,  K0                                                         \n\t \
   mov  K0,  K1                                                         \n\t \
   mov  K1,  K3                                                         \n\t \
   mov  K3, TMP                                                         \n\t
   
#define EKS_REORDER(D1, D2, D3, D4) \
   mov TMP, D1, ror RL4                                                 \n\t \
   mov  D1, D2                                                          \n\t \
   mov  D2, D3                                                          \n\t \
   mov  D3, D4                                                          \n\t \
   mov  D4, TMP                                                         \n\t
   
/*---------------------------------------------------------------------------
 * Macros for encryption
 *---------------------------------------------------------------------------*/
#define ENC_SUBR(B1, B2, K0, KN) \
   eor B1, K0, B1                                                       \n\t \
   eor KN, KN, B2                                                       \n\t \
   add B1, B1, KN                                                       \n\t

#define ENC_ROUND(B0, B1, B2, B3) \
   ldmia r1!, {r8-r11}                                                  \n\t \
   ENC_SUBR(B3, B2, r8,  r9)                                                 \
   ENC_SUBR(B2, B1, r8, r10)                                                 \
   ENC_SUBR(B1, B0, r8, r11)
   
#define ENC_REORDER(B1, B2, B3, B4) \
   mov TMP,  B1                                                         \n\t \
   mov  B1,  B2, ror RL9                                                \n\t \
   mov  B2,  B3, ror RR5                                                \n\t \
   mov  B3,  B4, ror RR3                                                \n\t \
   mov  B4, TMP                                                         \n\t
 
/*---------------------------------------------------------------------------
 * Macros for decryption
 *---------------------------------------------------------------------------*/
#define DEC_SUBR(B1, B2, K0, KN, RT) \
   eor KN, KN, B2                                                       \n\t \
   rsb B1, KN, B1, ror RT                                               \n\t \
   eor B1, B1, K0                                                       \n\t

#define DEC_ROUND(B0, B1, B2, B3) \
   ldmdb r1!, {r8-r11}                                                  \n\t \
   DEC_SUBR(B0, B3, r8, r11, RR9)                                            \
   DEC_SUBR(B1, B0, r8, r10, RL5)                                            \
   DEC_SUBR(B2, B1, r8,  r9, RL3)
   
#define DEC_REORDER(B1, B2, B3, B4) \
   mov TMP,  B4                                                         \n\t \
   mov  B4,  B3                                                         \n\t \
   mov  B3,  B2                                                         \n\t \
   mov  B2,  B1                                                         \n\t \
   mov  B1, TMP                                                         \n\t

#endif
#endif
