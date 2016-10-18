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
#define CV7 #7
#define CV8 #8
#define CV9 #9
#define CV14 #14
#define CV16 #16
#define CV24 #24


#define SET_MASK_(mask)           \
    ldr mask, =HALFWORD_MASK \n\t


#define EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3) \
    stm r1!, {k0, k1, k2, k3}            \n\t


#define EKS_ROUND_KEYS_(k0, k1, k2, k3, t0, t1, t2, t3, mask, c) \
    and t0, mask, k2                                        \n\t \
    and t1, mask, k2, lsr CV16                              \n\t \
                                                                 \
    lsr t2, t0, CV7                                         \n\t \
    orr t0, t2, t0, lsl CV9                                 \n\t \
    add t0, t0, t1                                          \n\t \
                                                                 \
    lsr t2, t1, CV14                                        \n\t \
    orr t1, t2, t1, lsl CV2                                 \n\t \
    eor t1, t0, t1                                          \n\t \
                                                                 \
    and t0, t0, mask                                        \n\t \
    and t1, t1, mask                                        \n\t \
                                                                 \
                                                                 \
    and t2, mask, k3                                        \n\t \
    and t3, mask, k3, lsr CV16                              \n\t \
                                                                 \
    add t2, t2, t0                                          \n\t \
    add t3, t3, t1                                          \n\t \
    add t3, t3, c                                           \n\t \
                                                                 \
    and t2, t2, mask                                        \n\t \
    and t3, t3, mask                                        \n\t \
                                                                 \
                                                                 \
    orr k3, t0, t1, lsl CV16                                \n\t \
                                                                 \
                                                                 \
    and t0, mask, k0                                        \n\t \
    and t1, mask, k0, lsr CV16                              \n\t \
                                                                 \
                                                                 \
    orr k0, t2, t3, lsl CV16                                \n\t \
                                                                 \
                                                                 \
    lsr t2, t0, CV7                                         \n\t \
    orr t0, t2, t0, lsl CV9                                 \n\t \
    add t0, t0, t1                                          \n\t \
                                                                 \
    lsr t2, t1, CV14                                        \n\t \
    orr t1, t2, t1, lsl CV2                                 \n\t \
    eor t1, t0, t1                                          \n\t \
                                                                 \
    and t0, t0, mask                                        \n\t \
    and t1, t1, mask                                        \n\t \
                                                                 \
                                                                 \
    and t2, mask, k1                                        \n\t \
    and t3, mask, k1, lsr CV16                              \n\t \
                                                                 \
    add t2, t2, t0                                          \n\t \
    add t3, t3, t1                                          \n\t \
                                                                 \
    and t2, t2, mask                                        \n\t \
    and t3, t3, mask                                        \n\t \
                                                                 \
                                                                 \
    orr k2, t2, t3, lsl CV16                                \n\t \
    orr k1, t0, t1, lsl CV16                                \n\t



#define ENC_ADD_ROUND_KEY_(b, rk) \
    ldm r1!, {rk}            \n\t \
    eor b, b, rk             \n\t

#define DEC_ADD_ROUND_KEY_(b, rk) \
    ldmdb r1!, {rk}          \n\t \
    eor b, b, rk             \n\t


#define ENC_A_(b, left, right, mask)   \
    and left, mask, b             \n\t \
    and right, mask, b, lsr CV16  \n\t \
                                       \
    lsr b, left, CV7              \n\t \
    orr left, b, left, lsl CV9    \n\t \
    add left, left, right         \n\t \
                                       \
    lsr b, right, CV14            \n\t \
    orr right, b, right, lsl CV2  \n\t \
    eor right, left, right        \n\t \
                                       \
    and left, left, mask          \n\t \
    and right, right, mask        \n\t \
                                       \
    orr b, left, right, lsl CV16  \n\t

#define DEC_A_(b, left, right, mask)   \
    and left, mask, b             \n\t \
    and right, mask, b, lsr CV16  \n\t \
                                       \
    eor right, left, right        \n\t \
    lsr b, right, CV2             \n\t \
    orr right, b, right, lsl CV14 \n\t \
    and right, right, mask        \n\t \
                                       \
    sub left, left, right         \n\t \
    and left, left, mask          \n\t \
    lsr b, left, CV9              \n\t \
    orr left, b, left, lsl CV7    \n\t \
    and left, left, mask          \n\t \
                                       \
    orr b, left, right, lsl CV16  \n\t


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

#define ENC_L_(b0, b1, b2, b3, t0, t1, t2, t3, mask) \
    mov t0, b0                                  \n\t \
    mov t1, b1                                  \n\t \
                                                     \
    L_(b0, b1, t2, t3, mask)                         \
                                                     \
    eor b0, b0, b2                              \n\t \
    mov b2, t0                                  \n\t \
                                                     \
    eor b1, b1, b3                              \n\t \
    mov b3, t1                                  \n\t

#define DEC_L_(b0, b1, b2, b3, t0, t1, t2, t3, mask) \
    mov t0, b2                                  \n\t \
    mov t1, b3                                  \n\t \
                                                     \
    L_(b2, b3, t2, t3, mask)                         \
                                                     \
    eor b2, b2, b0                              \n\t \
    mov b0, t0                                  \n\t \
                                                     \
    eor b3, b3, b1                              \n\t \
    mov b1, t1                                  \n\t


#define ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk) \
    ldm r1!, {rk}                             \n\t \
    eor b0, b0, rk                            \n\t \
                                                   \
    ldm r1!, {rk}                             \n\t \
    eor b1, b1, rk                            \n\t \
                                                   \
    ldm r1!, {rk}                             \n\t \
    eor b2, b2, rk                            \n\t \
                                                   \
    ldm r1!, {rk}                             \n\t \
    eor b3, b3, rk                            \n\t

#define DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk) \
    ldmdb r1!, {rk}                           \n\t \
    eor b3, b3, rk                            \n\t \
                                                   \
    ldmdb r1!, {rk}                           \n\t \
    eor b2, b2, rk                            \n\t \
                                                   \
    ldmdb r1!, {rk}                           \n\t \
    eor b1, b1, rk                            \n\t \
                                                   \
    ldmdb r1!, {rk}                           \n\t \
    eor b0, b0, rk                            \n\t


#define SET_MASK(mask) \
    STR(SET_MASK_(mask))


#define EKS_STORE_ROUND_KEYS(k0, k1, k2, k3) \
    STR(EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3))


#define EKS_ROUND_KEYS(k0, k1, k2, k3, t0, t1, t2, t3, mask, c) \
    STR(EKS_ROUND_KEYS_(k0, k1, k2, k3, t0, t1, t2, t3, mask, c))


#define ENC_ADD_ROUND_KEY(b, rk) \
    STR(ENC_ADD_ROUND_KEY_(b, rk))

#define DEC_ADD_ROUND_KEY(b, rk) \
    STR(DEC_ADD_ROUND_KEY_(b, rk))


#define ENC_A(b, left, right, mask) \
    STR(ENC_A_(b, left, right, mask))

#define DEC_A(b, left, right, mask) \
    STR(DEC_A_(b, left, right, mask))


#define L(b0, b1, t0, t1, mask) \
    STR(L_(b0, b1, t0, t1, mask))

#define ENC_L(b0, b1, b2, b3, t0, t1, t2, t3, mask) \
    STR(ENC_L_(b0, b1, b2, b3, t0, t1, t2, t3, mask))

#define DEC_L(b0, b1, b2, b3, t0, t1, t2, t3, mask) \
    STR(DEC_L_(b0, b1, b2, b3, t0, t1,  t2, t3, mask))


#define ENC_ADD_WHITENING_KEY(b0, b1, b2, b3, rk) \
    STR(ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk))

#define DEC_ADD_WHITENING_KEY(b0, b1, b2, b3, rk) \
    STR(DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk))


#endif /* ARM_MACROS_H */
