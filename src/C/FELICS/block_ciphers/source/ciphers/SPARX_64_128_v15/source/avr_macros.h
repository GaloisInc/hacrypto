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

#ifndef AVR_MACROS_H
#define AVR_MACROS_H


#include "stringify.h"


#define EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11) \
    st z+, k0                                                              \n\t \
    st z+, k1                                                              \n\t \
    st z+, k2                                                              \n\t \
    st z+, k3                                                              \n\t \
                                                                                \
    st z+, k4                                                              \n\t \
    st z+, k5                                                              \n\t \
    st z+, k6                                                              \n\t \
    st z+, k7                                                              \n\t \
                                                                                \
    st z+, k8                                                              \n\t \
    st z+, k9                                                              \n\t \
    st z+, k10                                                             \n\t \
    st z+, k11                                                             \n\t


#define EKS_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, t0, t1, t2, t3, c) \
    mov t0, k12                                                                                             \n\t \
    mov t1, k13                                                                                             \n\t \
    mov t2, k14                                                                                             \n\t \
    mov t3, k15                                                                                             \n\t \
    add t2, c                                                                                               \n\t \
    adc t3, __zero_reg__                                                                                    \n\t \
                                                                                                                 \
    mov k12, k8                                                                                             \n\t \
    mov k13, k9                                                                                             \n\t \
    mov k14, k10                                                                                            \n\t \
    mov k15, k11                                                                                            \n\t \
                                                                                                                 \
    eor k0, k1                                                                                              \n\t \
    eor k1, k0                                                                                              \n\t \
    eor k0, k1                                                                                              \n\t \
    lsl k0                                                                                                  \n\t \
    rol k1                                                                                                  \n\t \
    adc k0, __zero_reg__                                                                                    \n\t \
                                                                                                                 \
    add k0, k2                                                                                              \n\t \
    adc k1, k3                                                                                              \n\t \
                                                                                                                 \
    lsl k2                                                                                                  \n\t \
    rol k3                                                                                                  \n\t \
    adc k2, __zero_reg__                                                                                    \n\t \
    lsl k2                                                                                                  \n\t \
    rol k3                                                                                                  \n\t \
    adc k2, __zero_reg__                                                                                    \n\t \
                                                                                                                 \
    eor k2, k0                                                                                              \n\t \
    eor k3, k1                                                                                              \n\t \
                                                                                                                 \
    add k4, k0                                                                                              \n\t \
    adc k5, k1                                                                                              \n\t \
    add k6, k2                                                                                              \n\t \
    adc k7, k3                                                                                              \n\t \
                                                                                                                 \
    mov k8, k4                                                                                              \n\t \
    mov k9, k5                                                                                              \n\t \
    mov k10, k6                                                                                             \n\t \
    mov k11, k7                                                                                             \n\t \
                                                                                                                 \
    mov k4, k0                                                                                              \n\t \
    mov k5, k1                                                                                              \n\t \
    mov k6, k2                                                                                              \n\t \
    mov k7, k3                                                                                              \n\t \
                                                                                                                 \
    mov k0, t0                                                                                              \n\t \
    mov k1, t1                                                                                              \n\t \
    mov k2, t2                                                                                              \n\t \
    mov k3, t3                                                                                              \n\t



#define EKS_WHITENING_KEYS_(k0, k1, k2, k3, k14, k15, c) \
    eor k0, k1  \n\t \
    eor k1, k0 \n\t \
    eor k0, k1 \n\t \
    lsl k0 \n\t \
    rol k1 \n\t \
    adc k0, __zero_reg__ \n\t \
                                \
    add k0, k2 \n\t \
    adc k1, k3 \n\t \
                        \
    lsl k2 \n\t \
    rol k3 \n\t \
    adc k2, __zero_reg__ \n\t \
    lsl k2 \n\t \
    rol k3 \n\t \
    adc k2, __zero_reg__ \n\t \
                    \
    eor k2, k0 \n\t \
    eor k3, k1 \n\t \
                     \
    add k14, c \n\t \
    adc k15, __zero_reg__ \n\t


#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define ENC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    lpm rk0, z+                                           \n\t \
    lpm rk1, z+                                           \n\t \
    lpm rk2, z+                                           \n\t \
    lpm rk3, z+                                           \n\t \
                                                               \
    eor b0, rk0                                           \n\t \
    eor b1, rk1                                           \n\t \
    eor b2, rk2                                           \n\t \
    eor b3, rk3                                           \n\t
#else
#define ENC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    ld rk0, z+                                            \n\t \
    ld rk1, z+                                            \n\t \
    ld rk2, z+                                            \n\t \
    ld rk3, z+                                            \n\t \
                                                               \
    eor b0, rk0                                           \n\t \
    eor b1, rk1                                           \n\t \
    eor b2, rk2                                           \n\t \
    eor b3, rk3                                           \n\t
#endif

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define DEC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    lpm rk0, z+                                           \n\t \
    lpm rk1, z+                                           \n\t \
    lpm rk2, z+                                           \n\t \
    lpm rk3, z+                                           \n\t \
    sbiw r30, 8                                           \n\t \
                                                               \
    eor b3, rk3                                           \n\t \
    eor b2, rk2                                           \n\t \
    eor b1, rk1                                           \n\t \
    eor b0, rk0                                           \n\t
#else
#define DEC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    ld rk3, -z                                            \n\t \
    ld rk2, -z                                            \n\t \
    ld rk1, -z                                            \n\t \
    ld rk0, -z                                            \n\t \
                                                               \
    eor b3, rk3                                           \n\t \
    eor b2, rk2                                           \n\t \
    eor b1, rk1                                           \n\t \
    eor b0, rk0                                           \n\t
#endif


#define ENC_A_(b0, b1, b2, b3) \
    eor b0, b1            \n\t \
    eor b1, b0            \n\t \
    eor b0, b1            \n\t \
    lsl b0                \n\t \
    rol b1                \n\t \
    adc b0, __zero_reg__  \n\t \
                               \
    add b0, b2            \n\t \
    adc b1, b3            \n\t \
                               \
    lsl b2                \n\t \
    rol b3                \n\t \
    adc b2, __zero_reg__  \n\t \
    lsl b2                \n\t \
    rol b3                \n\t \
    adc b2, __zero_reg__  \n\t \
                               \
    eor b2, b0            \n\t \
    eor b3, b1            \n\t

#define DEC_A_(b0, b1, b2, b3) \
    eor b2, b0            \n\t \
    eor b3, b1            \n\t \
                               \
    bst b2, 0             \n\t \
    ror b3                \n\t \
    ror b2                \n\t \
    bld b3, 7             \n\t \
    bst b2, 0             \n\t \
    ror b3                \n\t \
    ror b2                \n\t \
    bld b3, 7             \n\t \
                               \
    sub b0, b2            \n\t \
    sbc b1, b3            \n\t \
                               \
    eor b0, b1            \n\t \
    eor b1, b0            \n\t \
    eor b0, b1            \n\t \
    bst b1, 0             \n\t \
    ror b0                \n\t \
    ror b1                \n\t \
    bld b0, 7             \n\t


#define L_(b0, b1, b2, b3, b4, b5, b6, b7, t0, t1, t2, t3) \
    eor b0, t1                                        \n\t \
    eor b1, t2                                        \n\t \
    eor b2, t3                                        \n\t \
    eor b3, t0                                        \n\t \
                                                           \
    eor b0, t3                                        \n\t \
    eor b1, t0                                        \n\t \
    eor b2, t1                                        \n\t \
    eor b3, t2                                        \n\t \
                                                           \
    eor b0, b4                                        \n\t \
    eor b1, b5                                        \n\t \
    eor b2, b6                                        \n\t \
    eor b3, b7                                        \n\t

#define ENC_L_(b0, b1, b2, b3, b4, b5, b6, b7, t0, t1, t2, t3) \
    mov t0, b0                                            \n\t \
    mov t1, b1                                            \n\t \
    mov t2, b2                                            \n\t \
    mov t3, b3                                            \n\t \
                                                               \
    L_(b0, b1, b2, b3, b4, b5, b6, b7, t0, t1, t2, t3)         \
                                                               \
    mov b4, t0                                            \n\t \
    mov b5, t1                                            \n\t \
    mov b6, t2                                            \n\t \
    mov b7, t3                                            \n\t

#define DEC_L_(b0, b1, b2, b3, b4, b5, b6, b7, t0, t1, t2, t3) \
    mov t0, b4                                            \n\t \
    mov t1, b5                                            \n\t \
    mov t2, b6                                            \n\t \
    mov t3, b7                                            \n\t \
                                                               \
    L_(b4, b5, b6, b7, b0, b1, b2, b3, t0, t1, t2, t3)         \
                                                               \
    mov b0, t0                                            \n\t \
    mov b1, t1                                            \n\t \
    mov b2, t2                                            \n\t \
    mov b3, t3                                            \n\t


#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    lpm rk0, z+                                               \n\t \
    lpm rk1, z+                                               \n\t \
    lpm rk2, z+                                               \n\t \
    lpm rk3, z+                                               \n\t \
                                                                   \
    eor b0, rk0                                               \n\t \
    eor b1, rk1                                               \n\t \
    eor b2, rk2                                               \n\t \
    eor b3, rk3                                               \n\t
#else
#define ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    ld rk0, z+                                                \n\t \
    ld rk1, z+                                                \n\t \
    ld rk2, z+                                                \n\t \
    ld rk3, z+                                                \n\t \
                                                                   \
    eor b0, rk0                                               \n\t \
    eor b1, rk1                                               \n\t \
    eor b2, rk2                                               \n\t \
    eor b3, rk3                                               \n\t
#endif

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    lpm rk0, z+                                               \n\t \
    lpm rk1, z+                                               \n\t \
    lpm rk2, z+                                               \n\t \
    lpm rk3, z+                                               \n\t \
    sbiw r30, 8                                               \n\t \
                                                                   \
    eor b3, rk3                                               \n\t \
    eor b2, rk2                                               \n\t \
    eor b1, rk1                                               \n\t \
    eor b0, rk0                                               \n\t
#else
#define DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    ld rk3, -z                                                \n\t \
    ld rk2, -z                                                \n\t \
    ld rk1, -z                                                \n\t \
    ld rk0, -z                                                \n\t \
                                                                   \
    eor b3, rk3                                               \n\t \
    eor b2, rk2                                               \n\t \
    eor b1, rk1                                               \n\t \
    eor b0, rk0                                               \n\t
#endif


#define EKS_STORE_ROUND_KEYS(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11) \
    STR(EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11))


#define EKS_ROUND_KEYS(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, t0, t1, t2, t3, c) \
    STR(EKS_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, t0, t1, t2, t3, c))


#define EKS_WHITENING_KEYS(k0, k1, k2, k3, k14, k15, c) \
    STR(EKS_WHITENING_KEYS_(k0, k1, k2, k3, k14, k15, c))


#define ENC_ADD_ROUND_KEY(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    STR(ENC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3))

#define DEC_ADD_ROUND_KEY(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    STR(DEC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3))


#define ENC_A(b0, b1, b2, b3) \
    STR(ENC_A_(b0, b1, b2, b3))

#define DEC_A(b0, b1, b2, b3) \
    STR(DEC_A_(b0, b1, b2, b3))


#define L(b0, b1, b2, b3, b4, b5, b6, b7, t0, t1, t2, t3) \
    STR(L_(b0, b1, b2, b3, b4, b5, b6, b7, t0, t1, t2, t3))

#define ENC_L(b0, b1, b2, b3, b4, b5, b6, b7, t0, t1, t2, t3) \
    STR(ENC_L_(b0, b1, b2, b3, b4, b5, b6, b7, t0, t1, t2, t3))

#define DEC_L(b0, b1, b2, b3, b4, b5, b6, b7, t0, t1, t2, t3) \
    STR(DEC_L_(b0, b1, b2, b3, b4, b5, b6, b7, t0, t1, t2, t3))


#define ENC_ADD_WHITENING_KEY(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    STR(ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3))

#define DEC_ADD_WHITENING_KEY(b0, b1, b2, b3, rk0, rk1, rk2, rk3) \
    STR(DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk0, rk1, rk2, rk3))


#endif /* AVR_MACROS_H */
