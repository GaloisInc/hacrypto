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


#define EKS_STORE_ROUND_KEYS_(k0, k1, k2) \
    stm r1!, {k0, k1, k2}            \n\t


#define EKS_ROUND_KEYS_(k0, k1, k2, k3, t0, t1, t2, t3, t4, mask, c) \
    and t0, mask, k3                                            \n\t \
    and t1, mask, k3, lsr CV16                                  \n\t \
    add t1, c                                                   \n\t \
    and t1, t1, mask                                            \n\t \
    orr t4, t0, t1, lsl CV16                                    \n\t \
                                                                     \
    mov k3, k2                                                  \n\t \
                                                                     \
    and t0, mask, k0                                            \n\t \
    and t1, mask, k0, lsr CV16                                  \n\t \
                                                                     \
    lsr k2, t0, CV7                                             \n\t \
    orr t0, k2, t0, lsl CV9                                     \n\t \
    add t0, t0, t1                                              \n\t \
                                                                     \
    lsr k2, t1, CV14                                            \n\t \
    orr t1, k2, t1, lsl CV2                                     \n\t \
    eor t1, t0, t1                                              \n\t \
                                                                     \
    and t0, t0, mask                                            \n\t \
    and t1, t1, mask                                            \n\t \
                                                                     \
    and t2, mask, k1                                            \n\t \
    and t3, mask, k1, lsr CV16                                  \n\t \
                                                                     \
    add t2, t2, t0                                              \n\t \
    and t2, mask, t2                                            \n\t \
                                                                     \
    add t3, t3, t1                                              \n\t \
    and t3, mask, t3                                            \n\t \
                                                                     \
    orr k2, t2, t3, lsl CV16                                    \n\t \
                                                                     \
    orr k1, t0, t1, lsl CV16                                    \n\t \
                                                                     \
    mov k0, t4                                                  \n\t



#define EKS_WHITENING_KEYS_(k0, k1, k2, k3, t0, t1, mask, c) \
    and t0, mask, k0                                    \n\t \
    and t1, mask, k0, lsr CV16                          \n\t \
                                                             \
    lsr k2, t0, CV7                                     \n\t \
    orr t0, k2, t0, lsl CV9                             \n\t \
    add t0, t0, t1                                      \n\t \
                                                             \
    lsr k2, t1, CV14                                    \n\t \
    orr t1, k2, t1, lsl CV2                             \n\t \
    eor t1, t0, t1                                      \n\t \
                                                             \
    and t0, t0, mask                                    \n\t \
    and t1, t1, mask                                    \n\t \
                                                             \
    orr k1, t0, t1, lsl CV16                            \n\t \
                                                             \
    and t0, mask, k3                                    \n\t \
    and t1, mask, k3, lsr CV16                          \n\t \
    add t1, c                                           \n\t \
    and t1, t1, mask                                    \n\t \
                                                             \
    orr k0, t0, t1, lsl CV16                            \n\t


#define ENC_ADD_ROUND_KEY_(b, rk) \
    ldm r1!, {rk}            \n\t \
    eor b, b, rk             \n\t

#define DEC_ADD_ROUND_KEY_(b, rk) \
    ldmdb r1!, {rk}          \n\t \
    eor b, b, rk             \n\t


#define ENC_A_(b, left, right, temp, mask) \
    and left, mask, b                 \n\t \
    and right, mask, b, lsr CV16      \n\t \
                                           \
    lsr temp, left, CV7               \n\t \
    orr left, temp, left, lsl CV9     \n\t \
    add left, left, right             \n\t \
                                           \
    lsr temp, right, CV14             \n\t \
    orr right, temp, right, lsl CV2   \n\t \
    eor right, left, right            \n\t \
                                           \
    and left, left, mask              \n\t \
    and right, right, mask            \n\t \
                                           \
    orr b, left, right, lsl CV16      \n\t

#define DEC_A_(b, left, right, temp, mask) \
    and left, mask, b                 \n\t \
    and right, mask, b, lsr CV16      \n\t \
                                           \
    eor right, left, right            \n\t \
    lsr temp, right, CV2              \n\t \
    orr right, temp, right, lsl CV14  \n\t \
    and right, right, mask            \n\t \
                                           \
    sub left, left, right             \n\t \
    and left, left, mask              \n\t \
    lsr temp, left, CV9               \n\t \
    orr left, temp, left, lsl CV7     \n\t \
    and left, left, mask              \n\t \
                                           \
    orr b, left, right, lsl CV16      \n\t


#define L_(b0, b1)                \
    eor b1, b1, b0           \n\t \
    eor b1, b1, b0, ror CV8  \n\t \
    eor b1, b1, b0, ror CV24 \n\t


#define ENC_ADD_WHITENING_KEY_(b0, b1, rk) \
    ldm r1!, {rk}                     \n\t \
    eor b0, b0, rk                    \n\t \
                                           \
    ldm r1!, {rk}                     \n\t \
    eor b1, b1, rk                    \n\t

#define DEC_ADD_WHITENING_KEY_(b0, b1, rk) \
    ldmdb r1!, {rk}                   \n\t \
    eor b1, b1, rk                    \n\t \
                                           \
    ldmdb r1!, {rk}                   \n\t \
    eor b0, b0, rk                    \n\t


#define SET_MASK(mask) \
    STR(SET_MASK_(mask))


#define EKS_STORE_ROUND_KEYS(k0, k1, k2) \
    STR(EKS_STORE_ROUND_KEYS_(k0, k1, k2))


#define EKS_ROUND_KEYS(k0, k1, k2, k3, t0, t1, t2, t3, t4, mask, c) \
    STR(EKS_ROUND_KEYS_(k0, k1, k2, k3, t0, t1, t2, t3, t4, mask, c))


#define EKS_WHITENING_KEYS(k0, k1, k2, k3, t0, t1, mask, c) \
    STR(EKS_WHITENING_KEYS_(k0, k1, k2, k3, t0, t1, mask, c))


#define ENC_ADD_ROUND_KEY(b, rk) \
    STR(ENC_ADD_ROUND_KEY_(b, rk))

#define DEC_ADD_ROUND_KEY(b, rk) \
    STR(DEC_ADD_ROUND_KEY_(b, rk))


#define ENC_A(b, left, right, temp, mask) \
    STR(ENC_A_(b, left, right, temp, mask))

#define DEC_A(b, left, right, temp, mask) \
    STR(DEC_A_(b, left, right, temp, mask))


#define L(b, temp) \
    STR(L_(b, temp))


#define ENC_ADD_WHITENING_KEY(bo, b1, rk) \
    STR(ENC_ADD_WHITENING_KEY_(bo, b1, rk))

#define DEC_ADD_WHITENING_KEY(bo, b1, rk) \
    STR(DEC_ADD_WHITENING_KEY_(bo, b1, rk))


#endif /* ARM_MACROS_H */
