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

#ifndef MSP_MACROS_H
#define MSP_MACROS_H


#include "stringify.h"


#define CV1 #1
#define CV8 #8
#define CV12 #12


#define EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3, k4, k5) \
    mov k0, 0(r14)                               \n\t \
    mov k1, 2(r14)                               \n\t \
                                                      \
    mov k2, 4(r14)                               \n\t \
    mov k3, 6(r14)                               \n\t \
                                                      \
    mov k4, 8(r14)                               \n\t \
    mov k5, 10(r14)                              \n\t \
                                                      \
    add CV12, r14                                \n\t


#define EKS_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, c) \
    add c, k7                                         \n\t \
                                                           \
                                                           \
    swpb k0                                           \n\t \
    rla k0                                            \n\t \
    adc k0                                            \n\t \
                                                           \
    add k1, k0                                        \n\t \
                                                           \
    rla k1                                            \n\t \
    adc k1                                            \n\t \
    rla k1                                            \n\t \
    adc k1                                            \n\t \
                                                           \
    xor k0, k1                                        \n\t \
                                                           \
                                                           \
    add k0, k2                                        \n\t \
    add k1, k3                                        \n\t


#define EKS_WHITENING_KEYS_(k0, k1, k7, c) \
    swpb k0                           \n\t \
    rla k0                            \n\t \
    adc k0                            \n\t \
                                           \
    add k1, k0                        \n\t \
                                           \
    rla k1                            \n\t \
    adc k1                            \n\t \
    rla k1                            \n\t \
    adc k1                            \n\t \
                                           \
    xor k0, k1                        \n\t \
                                           \
    add c, k7                         \n\t


#define ENC_ADD_ROUND_KEY_(b0, b1, rk) \
    mov @r14+, rk                 \n\t \
    xor rk, b0                    \n\t \
                                       \
    mov @r14+, rk                 \n\t \
    xor rk, b1                    \n\t

#define DEC_ADD_ROUND_KEY_(b0, b1, rk) \
    mov @r14+, rk                 \n\t \
    xor rk, b0                    \n\t \
                                       \
    mov @r14+, rk                 \n\t \
    xor rk, b1                    \n\t \
                                       \
    sub CV8, r14                  \n\t


#define ENC_A_(b0, b1) \
    swpb b0       \n\t \
    rla b0        \n\t \
    adc b0        \n\t \
                       \
    add b1, b0    \n\t \
                       \
    rla b1        \n\t \
    adc b1        \n\t \
    rla b1        \n\t \
    adc b1        \n\t \
                       \
    xor b0, b1    \n\t

#define DEC_A_(b0, b1) \
    xor b0, b1    \n\t \
                       \
    bit CV1, b1   \n\t \
    rrc b1        \n\t \
    bit CV1, b1   \n\t \
    rrc b1        \n\t \
                       \
    sub b1, b0    \n\t \
                       \
    swpb b0       \n\t \
    bit CV1, b0   \n\t \
    rrc b0        \n\t


#define L_(b0, b1, b2, b3, temp) \
    mov b0, temp            \n\t \
    xor b1, temp            \n\t \
                                 \
    swpb temp               \n\t \
    xor temp, b2            \n\t \
    xor temp, b3            \n\t \
                                 \
    xor b0, b2              \n\t \
    xor b1, b3              \n\t


#define ENC_ADD_WHITENING_KEY_(b0, b1, rk) \
    mov @r14+, rk                     \n\t \
    xor rk, b0                        \n\t \
                                           \
    mov @r14+, rk                     \n\t \
    xor rk, b1                        \n\t


#define DEC_ADD_WHITENING_KEY_(b0, b1, rk) \
    mov @r14+, rk                     \n\t \
    xor rk, b0                        \n\t \
                                           \
    mov @r14+, rk                     \n\t \
    xor rk, b1                        \n\t \
                                           \
    sub CV8, r14                      \n\t


#define EKS_STORE_ROUND_KEYS(k0, k1, k2, k3, k4, k5) \
    STR(EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3, k4, k5))


#define EKS_ROUND_KEYS(k0, k1, k2, k3, k4, k5, k6, k7, c) \
    STR(EKS_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, c))


#define EKS_WHITENING_KEYS(k0, k1, k7, c) \
    STR(EKS_WHITENING_KEYS_(k0, k1, k7, c))


#define ENC_ADD_ROUND_KEY(b0, b1, rk) \
    STR(ENC_ADD_ROUND_KEY_(b0, b1, rk))

#define DEC_ADD_ROUND_KEY(b0, b1, rk) \
    STR(DEC_ADD_ROUND_KEY_(b0, b1, rk))


#define ENC_A(b0, b1) \
    STR(ENC_A_(b0, b1))

#define DEC_A(b0, b1) \
    STR(DEC_A_(b0, b1))


#define L(b0, b1, b2, b3, temp) \
    STR(L_(b0, b1, b2, b3, temp))


#define ENC_ADD_WHITENING_KEY(b0, b1, rk) \
    STR(ENC_ADD_WHITENING_KEY_(b0, b1, rk))

#define DEC_ADD_WHITENING_KEY(b0, b1, rk) \
    STR(DEC_ADD_WHITENING_KEY_(b0, b1, rk))


#endif /* MSP_MACROS_H */
