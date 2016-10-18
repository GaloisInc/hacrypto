/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef ARM_MACROS_H
#define ARM_MACROS_H


#include "stringify.h"


#define HALFWORD_MASK #0x0000ffff

#define CV2 #2
#define CV4 #4
#define CV6 #6
#define CV7 #7
#define CV8 #8
#define CV9 #9
#define CV10 #10
#define CV12 #12
#define CV14 #14
#define CV16 #16
#define CV24 #24


#define SET_MASK_(mask)           \
    ldr mask, =HALFWORD_MASK \n\t


#define EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3, k4, k5) \
    strh k0, [r1]                                \n\t \
    strh k1, [r1, CV2]                           \n\t \
                                                      \
    strh k2, [r1, CV4]                           \n\t \
    strh k3, [r1, CV6]                           \n\t \
                                                      \
    strh k4, [r1, CV8]                           \n\t \
    strh k5, [r1, CV10]                          \n\t \
    add r1, r1, CV12                             \n\t


#define EKS_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, mask, c) \
    lsr t0, k0, CV7                                                 \n\t \
    orr k0, t0, k0, lsl CV9                                         \n\t \
    add k0, k0, k1                                                  \n\t \
    and k0, k0, mask                                                \n\t \
                                                                         \
    lsr t0, k1, CV14                                                \n\t \
    orr k1, t0, k1, lsl CV2                                         \n\t \
    eor k1, k0, k1                                                  \n\t \
    and k1, k1, mask                                                \n\t \
                                                                         \
                                                                         \
    mov t0, k6                                                      \n\t \
    add t1, k7, c                                                   \n\t \
    and t1, t1, mask                                                \n\t \
                                                                         \
                                                                         \
    mov k6, k4                                                      \n\t \
    mov k7, k5                                                      \n\t \
                                                                         \
                                                                         \
    add k4, k0, k2                                                  \n\t \
    and k4, k4, mask                                                \n\t \
                                                                         \
    add k5, k1, k3                                                  \n\t \
    and k5, k5, mask                                                \n\t \
                                                                         \
                                                                         \
    mov k2, k0                                                      \n\t \
    mov k3, k1                                                      \n\t \
                                                                         \
                                                                         \
    mov k0, t0                                                      \n\t \
    mov k1, t1                                                      \n\t


#define EKS_WHITENING_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, t0, mask, c) \
    lsr t0, k0, CV7                                                 \n\t \
    orr k0, t0, k0, lsl CV9                                         \n\t \
    add k0, k0, k1                                                  \n\t \
    and k0, k0, mask                                                \n\t \
                                                                         \
    lsr t0, k1, CV14                                                \n\t \
    orr k1, t0, k1, lsl CV2                                         \n\t \
    eor k1, k0, k1                                                  \n\t \
    and k1, k1, mask                                                \n\t \
                                                                         \
                                                                         \
    mov k2, k0                                                      \n\t \
    mov k3, k1                                                      \n\t \
                                                                         \
                                                                         \
    mov k0, k6                                                      \n\t \
    add k1, k7, c                                                   \n\t \
    and k1, k1, mask                                                \n\t


#define ENC_ADD_ROUND_KEY_(b0, b1, rk) \
    ldrh rk, [r1]                 \n\t \
    eor b0, b0, rk                \n\t \
    ldrh rk, [r1, CV2]            \n\t \
    eor b1, b1, rk                \n\t \
    add r1, r1, CV4               \n\t

#define DEC_ADD_ROUND_KEY_(b0, b1, rk) \
    ldrh rk, [r1]                 \n\t \
    eor b0, b0, rk                \n\t \
    ldrh rk, [r1, CV2]            \n\t \
    eor b1, b1, rk                \n\t \
    sub r1, r1, CV4               \n\t


#define ENC_A_(left, right, temp, mask)   \
    lsr temp, left, CV7              \n\t \
    orr left, temp, left, lsl CV9    \n\t \
    add left, left, right            \n\t \
    and left, left, mask             \n\t \
                                          \
    lsr temp, right, CV14            \n\t \
    orr right, temp, right, lsl CV2  \n\t \
    eor right, left, right           \n\t \
    and right, right, mask           \n\t

#define DEC_A_(left, right, temp, mask)   \
    eor right, left, right           \n\t \
    lsr temp, right, CV2             \n\t \
    orr right, temp, right, lsl CV14 \n\t \
    and right, right, mask           \n\t \
                                          \
    sub left, left, right            \n\t \
    and left, left, mask             \n\t \
    lsr temp, left, CV9              \n\t \
    orr left, temp, left, lsl CV7    \n\t \
    and left, left, mask             \n\t


#define L_(b, temp)               \
    eor b, b, temp, ror CV8  \n\t \
    eor b, b, temp, ror CV24 \n\t

// 16-bit oriented: same number of cycles, but 2 additional registers
#define ENC_L_(b0, b1, b2, b3, temp, mask) \
    orr b0, b0, b1, lsl CV16          \n\t \
    orr b1, b2, b3, lsl CV16          \n\t \
                                           \
    mov temp, b0                      \n\t \
                                           \
    L_(b0, temp)                           \
                                           \
    eor b0, b0, b1                    \n\t \
    mov b1, temp                      \n\t \
                                           \
    and b2, mask, b1                  \n\t \
    and b3, mask, b1, lsr CV16        \n\t \
                                           \
    and b1, mask, b0, lsr CV16        \n\t \
    and b0, mask, b0                  \n\t

// 16-bit oriented: same number of cycles, but 2 additional registers
#define DEC_L_(b0, b1, b2, b3, temp, mask) \
    orr b0, b0, b1, lsl CV16          \n\t \
    orr b1, b2, b3, lsl CV16          \n\t \
                                           \
    mov temp, b1                      \n\t \
                                           \
    L_(b1, temp)                           \
                                           \
    eor b1, b1, b0                    \n\t \
    mov b0, temp                      \n\t \
                                           \
    and b2, mask, b1                  \n\t \
    and b3, mask, b1, lsr CV16        \n\t \
                                           \
    and b1, mask, b0, lsr CV16        \n\t \
    and b0, mask, b0                  \n\t


#define ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk) \
    ldrh rk, [r1]                             \n\t \
    eor b0, b0, rk                            \n\t \
                                                   \
    ldrh rk, [r1, CV2]                        \n\t \
    eor b1, b1, rk                            \n\t \
                                                   \
    ldrh rk, [r1, CV4]                        \n\t \
    eor b2, b2, rk                            \n\t \
                                                   \
    ldrh rk, [r1, CV6]                        \n\t \
    eor b3, b3, rk                            \n\t


#define DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk) \
    ldrh rk, [r1]                             \n\t \
    eor b0, b0, rk                            \n\t \
                                                   \
    ldrh rk, [r1, CV2]                        \n\t \
    eor b1, b1, rk                            \n\t \
                                                   \
    ldrh rk, [r1, CV4]                        \n\t \
    eor b2, b2, rk                            \n\t \
                                                   \
    ldrh rk, [r1, CV6]                        \n\t \
    eor b3, b3, rk                            \n\t \
                                                   \
    sub r1, r1, CV4                           \n\t


#define SET_MASK(mask) \
    STR(SET_MASK_(mask))


#define EKS_STORE_ROUND_KEYS(k0, k1, k2, k3, k4, k5) \
    STR(EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3, k4, k5))


#define EKS_ROUND_KEYS(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, mask, c) \
    STR(EKS_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, mask, c))


#define EKS_WHITENING_KEYS(k0, k1, k2, k3, k4, k5, k6, k7, t0, mask, c) \
    STR(EKS_WHITENING_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, t0, mask, c))


#define ENC_ADD_ROUND_KEY(b0, b1, rk) \
    STR(ENC_ADD_ROUND_KEY_(b0, b1, rk))

#define DEC_ADD_ROUND_KEY(b0, b1, rk) \
    STR(DEC_ADD_ROUND_KEY_(b0, b1, rk))


#define ENC_A(left, right, temp, mask) \
    STR(ENC_A_(left, right, temp, mask))

#define DEC_A(left, right, temp, mask) \
    STR(DEC_A_(left, right, temp, mask))


#define L(b, temp) \
    STR(L_(b, temp))

#define ENC_L(b0, b1, b2, b3, temp, mask) \
    STR(ENC_L_(b0, b1, b2, b3, temp, mask))

#define DEC_L(b0, b1, b2, b3, temp, mask) \
    STR(DEC_L_(b0, b1, b2, b3, temp, mask))


#define ENC_ADD_WHITENING_KEY(bo, b1, b2, b3, rk) \
    STR(ENC_ADD_WHITENING_KEY_(bo, b1, b2, b3, rk))

#define DEC_ADD_WHITENING_KEY(bo, b1, b2, b3, rk) \
    STR(DEC_ADD_WHITENING_KEY_(bo, b1, b2, b3, rk))


#endif /* ARM_MACROS_H */
