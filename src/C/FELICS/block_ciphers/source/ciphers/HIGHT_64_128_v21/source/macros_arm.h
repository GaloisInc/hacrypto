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

#define CV1 #1
#define CV2 #2
#define CV3 #3
#define CV4 #4
#define CV5 #5
#define CV6 #6
#define CV7 #7
#define CV8 #8
#define CV16 #16
#define CV24 #24

#define MASK0  #0x000000ff
#define MASK3  #0xff000000

#define MASK01 #0x0000ffff
#define MASK02 #0x00ff00ff
#define MASK13 #0xff00ff00
#define MASK23 #0xffff0000

#define TMP0 r10
#define TMP1 r11

/*---------------------------------------------------------------------------
 * F functions
 *---------------------------------------------------------------------------*/
#define F0(I, O) \
   lsl O, I, CV1                                                        \n\t \
   eor O, O, I, lsr CV7                                                 \n\t \
   eor O, O, I, lsl CV2                                                 \n\t \
   eor O, O, I, lsr CV6                                                 \n\t \
   eor O, O, I, lsl CV7                                                 \n\t \
   eor O, O, I, lsr CV1                                                 \n\t

#define F1(I, O) \
   lsl O, I, CV3                                                        \n\t \
   eor O, O, I, lsr CV5                                                 \n\t \
   eor O, O, I, lsl CV4                                                 \n\t \
   eor O, O, I, lsr CV4                                                 \n\t \
   eor O, O, I, lsl CV6                                                 \n\t \
   eor O, O, I, lsr CV2                                                 \n\t
   
/*---------------------------------------------------------------------------
 * Basic operations
 *---------------------------------------------------------------------------*/
#define LD_SWAPMASK \
   ldr r9, =MASK01                                                      \n\t

#define HSWAP(A, B) \
   eor TMP0, A, B                                                       \n\t \
   and TMP0, TMP0, r9, ror CV16                                         \n\t \
   eor A, TMP0                                                          \n\t \
   eor B, TMP0                                                          \n\t

#define ROR64_8(A, B) \
   mov A, A, ror CV24                                                   \n\t \
   mov B, B, ror CV24                                                   \n\t \
   eor TMP0, A, B                                                       \n\t \
   and TMP0, MASK0                                                      \n\t \
   eor A, TMP0                                                          \n\t \
   eor B, TMP0                                                          \n\t
   
#define ROL64_8(A, B) \
   mov A, A, ror CV8                                                    \n\t \
   mov B, B, ror CV8                                                    \n\t \
   eor TMP0, A, B                                                       \n\t \
   and TMP0, MASK3                                                      \n\t \
   eor A, TMP0                                                          \n\t \
   eor B, TMP0                                                          \n\t
   
#define HADD8(A, B) \
   add A, B                                                             \n\t \
   ADD_MASK(A, B)
   
#define HSUB8(A, B) \
   mov TMP0, A                                                          \n\t \
   sub    A, B                                                          \n\t \
   ADD_MASK(A, TMP0)
   
#define ADD_ENC_KEY(Rd, Rm, K) \
   add Rm, Rd, K                                                        \n\t \
   ADD_MASK(Rd, Rm)
   
#define SUB_KEY(Rd, Rm, K) \
   sub Rm, Rd, K                                                        \n\t \
   ADD_MASK(Rd, Rm)
   
#define ADD_MASK(A, B) \
   and A, MASK13                                                        \n\t \
   and B, MASK02                                                        \n\t \
   orr A, B                                                             \n\t
   
/*---------------------------------------------------------------------------
 * Macros for EKS
 *---------------------------------------------------------------------------*/
#define ADDU8(O, A, B) \
   and TMP0, A, MASK02                                                  \n\t \
   and TMP1, B, MASK02                                                  \n\t \
   add TMP0, TMP1                                                       \n\t \
   and TMP0, MASK02                                                     \n\t \
   and    O, A, MASK13                                                  \n\t \
   and TMP1, B, MASK13                                                  \n\t \
   add    O, TMP1                                                       \n\t \
   and    O, MASK13                                                     \n\t \
   orr    O, TMP0                                                       \n\t

/*---------------------------------------------------------------------------
 * Macros for encryption
 *---------------------------------------------------------------------------*/
#define ENC_F0(I, O, K) \
   and TMP0, I, MASK02                                                  \n\t \
   F0(TMP0, O)                                                               \
   ADD_ENC_KEY(O, TMP0, K)                                                   \
   and O, MASK02                                                        \n\t
   
#define ENC_F1(I, O, K) \
   and TMP0, I, MASK02                                                  \n\t \
   F1(TMP0, O)                                                               \
   eor O, K                                                             \n\t \
   and O, MASK02                                                        \n\t

#define ENC_MASK_KEY \
   mov r3, r2, ror CV24                                                 \n\t \
   and r2, MASK02                                                       \n\t \
   and r3, MASK02                                                       \n\t
   
#define ENC_LDKEY \
   ldmia r1!, {r2}                                                      \n\t \
   ENC_MASK_KEY
   
#define ENC_LDKEY_INIT \
   ldm r1, {r2}                                                         \n\t \
   ENC_MASK_KEY
   
#define ENC_INIT \
   ENC_LDKEY_INIT                                                            \
   mov r5, r5, ror CV16                                                 \n\t \
   HSWAP(r4, r5)                                                             \
   mov r6, r4                                                           \n\t \
   \
   ADD_ENC_KEY(r4, r6, r2)                                              \n\t \
   eor r5, r3                                                           \n\t \
   \
   HSWAP(r4, r5)                                                             \
   mov r5, r5, ror CV16                                                  \n\t

#define ENC_ROUND \
   ENC_LDKEY                                                                 \
   mov r6, r4                                                           \n\t \
   mov r7, r5, ror CV16                                                 \n\t \
   HSWAP(r6, r7)                                                             \
   \
   ENC_F1(r6, r4, r2)                                                        \
   ENC_F0(r7, r5, r3)                                                        \
   \
   ROR64_8(r4, r5)                                                           \
   HADD8(r4, r6)                                                             \
   eor r5, r7                                                           \n\t \
   \
   HSWAP(r4, r5)                                                             \
   mov r5, r5, ror CV16                                                 \n\t \
   ROR64_8(r4, r5)
   
#define ENC_FINAL \
   ROL64_8(r4, r5)                                                           \
   ENC_INIT
   
/*---------------------------------------------------------------------------
 * Macros for decryption
 *---------------------------------------------------------------------------*/
#define DEC_F0(O, K) \
   and TMP0, O, MASK13                                                  \n\t \
   F0(TMP0, O)                                                               \
   ADD_DEC_KEY(O, TMP0, K)                                                   \
   and O, MASK13                                                        \n\t
   
#define DEC_F1(O, K) \
   and TMP0, O, MASK13                                                  \n\t \
   F1(TMP0, O)                                                               \
   and O, MASK13                                                        \n\t \
   eor O, K                                                             \n\t
 
#define ADD_DEC_KEY(Rd, Rm, K) \
   add Rm, Rd, K                                                        \n\t \
   and Rd, MASK02                                                       \n\t \
   and Rm, MASK13                                                       \n\t \
   orr Rd, Rm                                                           \n\t
   
#define DEC_MASK_KEY \
   mov r3, r2, ror CV24                                                 \n\t \
   and r2, MASK02                                                       \n\t \
   and r3, MASK02                                                       \n\t
      
#define DEC_LDKEY \
   ldmdb r1!, {r2}                                                      \n\t \
   and    r3, r2, MASK13                                                \n\t \
   and    r2, MASK02                                                    \n\t \
   mov    r2, r2, ror CV24                                              \n\t \
   mov    r3, r3, ror CV16                                              \n\t
   
#define DEC_LDKEY_INIT \
   ldm r1, {r2}                                                         \n\t \
   DEC_MASK_KEY
   
#define DEC_INIT \
   DEC_LDKEY_INIT                                                            \
   mov r5, r5, ror CV16                                                 \n\t \
   HSWAP(r4, r5)                                                             \
   mov r6, r4                                                           \n\t \
   \
   SUB_KEY(r4, r6, r2)                                                  \n\t \
   eor r5, r3                                                           \n\t \
   \
   HSWAP(r4, r5)                                                             \
   mov r5, r5, ror CV16                                                 \n\t

#define DEC_ROUND \
   DEC_LDKEY                                                                 \
   mov r5, r5, ror CV16                                                 \n\t \
   mov r6, r4                                                           \n\t \
   mov r7, r5                                                           \n\t \
   HSWAP(r6, r7)                                                             \
   \
   DEC_F1(r6, r2)                                                            \
   DEC_F0(r7, r3)                                                            \
   mov r7, r7, ror CV16                                                 \n\t \
   \
   ROL64_8(r4, r5)                                                           \
   HSUB8(r4, r6)                                                             \
   eor r5, r7                                                           \n\t \
   \
   ROR64_8(r4, r5)                                                           \
   mov r5, r5, ror CV16                                                 \n\t \
   ROL64_8(r4, r5)
   
#define DEC_FINAL \
   DEC_INIT                                                                  \
   ROR64_8(r4, r5)   
   
#endif
#endif
