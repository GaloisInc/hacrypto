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


#define EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7) \
    strh k0, [r1]                                        \n\t \
    strh k1, [r1, CV2]                                   \n\t \
                                                              \
    strh k2, [r1, CV4]                                   \n\t \
    strh k3, [r1, CV6]                                   \n\t \
                                                              \
    strh k4, [r1, CV8]                                   \n\t \
    strh k5, [r1, CV10]                                  \n\t \
                                                              \
    strh k6, [r1, CV12]                                  \n\t \
    strh k7, [r1, CV14]                                  \n\t \
                                                              \
    add r1, r1, CV16                                     \n\t


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
    lsr t0, k4, CV7                                                 \n\t \
    orr k4, t0, k4, lsl CV9                                         \n\t \
    add k4, k4, k5                                                  \n\t \
    and k4, k4, mask                                                \n\t \
                                                                         \
    lsr t0, k5, CV14                                                \n\t \
    orr k5, t0, k5, lsl CV2                                         \n\t \
    eor k5, k4, k5                                                  \n\t \
    and k5, k5, mask                                                \n\t \
                                                                         \
                                                                         \
    add t0, k4, k6                                                  \n\t \
    add t1, k5, k7                                                  \n\t \
    add t1, t1, c                                                   \n\t \
                                                                         \
    and t0, t0, mask                                                \n\t \
    and t1, t1, mask                                                \n\t \
                                                                         \
                                                                         \
    add k2, k2, k0                                                  \n\t \
    add k3, k3, k1                                                  \n\t \
                                                                         \
    and k2, k2, mask                                                \n\t \
    and k3, k3, mask                                                \n\t \
                                                                         \
                                                                         \
    mov k7, k5                                                      \n\t \
    mov k6, k4                                                      \n\t \
                                                                         \
    mov k5, k3                                                      \n\t \
    mov k4, k2                                                      \n\t \
                                                                         \
    mov k3, k1                                                      \n\t \
    mov k2, k0                                                      \n\t \
                                                                         \
    mov k1, t1                                                      \n\t \
    mov k0, t0                                                      \n\t


#define ENC_ADD_ROUND_KEY_(b0, b1, rk, mask) \
    ldm r1!, {rk}                       \n\t \
                                             \
    eor b0, b0, rk                      \n\t \
    and b0, b0, mask                    \n\t \
                                             \
    eor b1, b1, rk, lsr CV16            \n\t \
    and b1, b1, mask                    \n\t

#define DEC_ADD_ROUND_KEY_(b0, b1, rk, mask) \
    ldmdb r1!, {rk}                     \n\t \
                                             \
    eor b0, b0, rk                      \n\t \
    and b0, b0, mask                    \n\t \
                                             \
    eor b1, b1, rk, lsr CV16            \n\t \
    and b1, b1, mask                    \n\t


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


#define L_(b0, b1, t0, t1, mask)  \
    eor t0, b0, b1           \n\t \
    mov t1, t0, ror CV8      \n\t \
    eor t1, t1, t0, ror CV24 \n\t \
                                  \
    eor b0, b0, t1           \n\t \
    eor b1, b1, t1           \n\t \
                                  \
    mov t0, b0               \n\t \
    eor t0, t0, b1           \n\t \
    and t0, t0, mask         \n\t \
                                  \
    eor b0, b0, t0           \n\t \
    eor b1, b1, t0           \n\t

#define ENC_L_(b0, b1, b2, b3, b4, b5, b6, b7, mask) \
    eor b0, b0, b1, lsl CV16                    \n\t \
    eor b1, b2, b3, lsl CV16                    \n\t \
                                                     \
    eor b2, b4, b5, lsl CV16                    \n\t \
    eor b3, b6, b7, lsl CV16                    \n\t \
                                                     \
                                                     \
    mov b4, b0                                  \n\t \
    mov b5, b1                                  \n\t \
                                                     \
    L_(b0, b1, b6, b7, mask)                         \
                                                     \
    eor b0, b0, b2                              \n\t \
    mov b2, b4                                  \n\t \
                                                     \
    eor b1, b1, b3                              \n\t \
    mov b3, b5                                  \n\t \
                                                     \
                                                     \
    and b7, mask, b3, lsr CV16                  \n\t \
    and b6, mask, b3                            \n\t \
                                                     \
    and b5, mask, b2, lsr CV16                  \n\t \
    and b4, mask, b2                            \n\t \
                                                     \
    and b3, mask, b1, lsr CV16                  \n\t \
    and b2, mask, b1                            \n\t \
                                                     \
    and b1, mask, b0, lsr CV16                  \n\t \
    and b0, mask, b0                            \n\t


#define DEC_L_(b0, b1, b2, b3, b4, b5, b6, b7, mask) \
    eor b0, b0, b1, lsl CV16                    \n\t \
    eor b1, b2, b3, lsl CV16                    \n\t \
                                                     \
    eor b2, b4, b5, lsl CV16                    \n\t \
    eor b3, b6, b7, lsl CV16                    \n\t \
                                                     \
                                                     \
    mov b4, b2                                  \n\t \
    mov b5, b3                                  \n\t \
                                                     \
    L_(b2, b3, b6, b7, mask)                         \
                                                     \
    eor b2, b2, b0                              \n\t \
    mov b0, b4                                  \n\t \
                                                     \
    eor b3, b3, b1                              \n\t \
    mov b1, b5                                  \n\t \
                                                     \
                                                     \
    and b7, mask, b3, lsr CV16                  \n\t \
    and b6, mask, b3                            \n\t \
                                                     \
    and b5, mask, b2, lsr CV16                  \n\t \
    and b4, mask, b2                            \n\t \
                                                     \
    and b3, mask, b1, lsr CV16                  \n\t \
    and b2, mask, b1                            \n\t \
                                                     \
    and b1, mask, b0, lsr CV16                  \n\t \
    and b0, mask, b0                            \n\t


#define ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, b4, b5, b6, b7, rk, mask) \
    ldm r1!, {rk}                                                   \n\t \
                                                                         \
    eor b0, b0, rk                                                  \n\t \
    and b0, b0, mask                                                \n\t \
                                                                         \
    eor b1, b1, rk, lsr CV16                                        \n\t \
    and b1, b1, mask                                                \n\t \
                                                                         \
                                                                         \
    ldm r1!, {rk}                                                   \n\t \
                                                                         \
    eor b2, b2, rk                                                  \n\t \
    and b2, b2, mask                                                \n\t \
                                                                         \
    eor b3, b3, rk, lsr CV16                                        \n\t \
    and b3, b3, mask                                                \n\t \
                                                                         \
                                                                         \
    ldm r1!, {rk}                                                   \n\t \
                                                                         \
    eor b4, b4, rk                                                  \n\t \
    and b4, b4, mask                                                \n\t \
                                                                         \
    eor b5, b5, rk, lsr CV16                                        \n\t \
    and b5, b5, mask                                                \n\t \
                                                                         \
                                                                         \
    ldm r1!, {rk}                                                   \n\t \
                                                                         \
    eor b6, b6, rk                                                  \n\t \
    and b6, b6, mask                                                \n\t \
                                                                         \
    eor b7, b7, rk, lsr CV16                                        \n\t \
    and b7, b7, mask                                                \n\t


#define DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, b4, b5, b6, b7, rk, mask) \
    ldmdb r1!, {rk}                                                 \n\t \
                                                                         \
    eor b6, b6, rk                                                  \n\t \
    and b6, b6, mask                                                \n\t \
                                                                         \
    eor b7, b7, rk, lsr CV16                                        \n\t \
    and b7, b7, mask                                                \n\t \
                                                                         \
                                                                         \
    ldmdb r1!, {rk}                                                 \n\t \
                                                                         \
    eor b4, b4, rk                                                  \n\t \
    and b4, b4, mask                                                \n\t \
                                                                         \
    eor b5, b5, rk, lsr CV16                                        \n\t \
    and b5, b5, mask                                                \n\t \
                                                                         \
                                                                         \
    ldmdb r1!, {rk}                                                 \n\t \
                                                                         \
    eor b2, b2, rk                                                  \n\t \
    and b2, b2, mask                                                \n\t \
                                                                         \
    eor b3, b3, rk, lsr CV16                                        \n\t \
    and b3, b3, mask                                                \n\t \
                                                                         \
                                                                         \
    ldmdb r1!, {rk}                                                 \n\t \
                                                                         \
    eor b0, b0, rk                                                  \n\t \
    and b0, b0, mask                                                \n\t \
                                                                         \
    eor b1, b1, rk, lsr CV16                                        \n\t \
    and b1, b1, mask                                                \n\t

#define SET_MASK(mask) \
    STR(SET_MASK_(mask))


#define EKS_STORE_ROUND_KEYS(k0, k1, k2, k3, k4, k5, k6, k7) \
    STR(EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7))


#define EKS_ROUND_KEYS(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, mask, c) \
    STR(EKS_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, mask, c))


#define ENC_ADD_ROUND_KEY(b0, b1, rk, mask) \
    STR(ENC_ADD_ROUND_KEY_(b0, b1, rk, mask))

#define DEC_ADD_ROUND_KEY(b0, b1, rk, mask) \
    STR(DEC_ADD_ROUND_KEY_(b0, b1, rk, mask))


#define ENC_A(left, right, temp, mask) \
    STR(ENC_A_(left, right, temp, mask))

#define DEC_A(b, left, right, mask) \
    STR(DEC_A_(b, left, right, mask))


#define L(b0, b1, t0, t1, mask) \
    STR(L_(b0, b1, t0, t1, mask))

#define ENC_L(b0, b1, b2, b3, b4, b5, b6, b7, mask) \
    STR(ENC_L_(b0, b1, b2, b3, b4, b5, b6, b7, mask))

#define DEC_L(b0, b1, b2, b3, b4, b5, b6, b7, mask) \
    STR(DEC_L_(b0, b1, b2, b3, b4, b5, b6, b7, mask))


#define ENC_ADD_WHITENING_KEY(b0, b1, b2, b3, b4, b5, b6, b7, rk, mask) \
    STR(ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, b4, b5, b6, b7, rk, mask))

#define DEC_ADD_WHITENING_KEY(b0, b1, b2, b3, b4, b5, b6, b7, rk, mask) \
    STR(DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, b4, b5, b6, b7, rk, mask))


#endif /* ARM_MACROS_H */
