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


#define EKS_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, c) \
    add k14, c                                                                              \n\t \
    adc k15, __zero_reg__                                                                   \n\t \
                                                                                                 \
    eor k0, k1                                                                              \n\t \
    eor k1, k0                                                                              \n\t \
    eor k0, k1                                                                              \n\t \
    lsl k0                                                                                  \n\t \
    rol k1                                                                                  \n\t \
    adc k0, __zero_reg__                                                                    \n\t \
                                                                                                 \
    add k0, k2                                                                              \n\t \
    adc k1, k3                                                                              \n\t \
                                                                                                 \
    lsl k2                                                                                  \n\t \
    rol k3                                                                                  \n\t \
    adc k2, __zero_reg__                                                                    \n\t \
    lsl k2                                                                                  \n\t \
    rol k3                                                                                  \n\t \
    adc k2, __zero_reg__                                                                    \n\t \
                                                                                                 \
    eor k2, k0                                                                              \n\t \
    eor k3, k1                                                                              \n\t \
                                                                                                 \
    add k4, k0                                                                              \n\t \
    adc k5, k1                                                                              \n\t \
    add k6, k2                                                                              \n\t \
    adc k7, k3                                                                              \n\t



#define EKS_WHITENING_KEYS_(k0, k1, k2, k3, k14, k15, c) \
    eor k0, k1                                      \n\t \
    eor k1, k0                                      \n\t \
    eor k0, k1                                      \n\t \
    lsl k0                                          \n\t \
    rol k1                                          \n\t \
    adc k0, __zero_reg__                            \n\t \
                                                         \
    add k0, k2                                      \n\t \
    adc k1, k3                                      \n\t \
                                                         \
    lsl k2                                          \n\t \
    rol k3                                          \n\t \
    adc k2, __zero_reg__                            \n\t \
    lsl k2                                          \n\t \
    rol k3                                          \n\t \
    adc k2, __zero_reg__                            \n\t \
                                                         \
    eor k2, k0                                      \n\t \
    eor k3, k1                                      \n\t \
                                                         \
    add k14, c                                      \n\t \
    adc k15, __zero_reg__                           \n\t


#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define ENC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk) \
    lpm rk, z+                            \n\t \
    eor b0, rk                            \n\t \
                                               \
    lpm rk, z+                            \n\t \
    eor b1, rk                            \n\t \
                                               \
    lpm rk, z+                            \n\t \
    eor b2, rk                            \n\t \
                                               \
    lpm rk, z+                            \n\t \
    eor b3, rk                            \n\t
#else
#define ENC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk) \
    ld rk, z+                             \n\t \
    eor b0, rk                            \n\t \
                                               \
    ld rk, z+                             \n\t \
    eor b1, rk                            \n\t \
                                               \
    ld rk, z+                             \n\t \
    eor b2, rk                            \n\t \
                                               \
    ld rk, z+                             \n\t \
    eor b3, rk                            \n\t
#endif

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define DEC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk) \
    lpm rk, z+                            \n\t \
    eor b3, rk                            \n\t \
                                               \
    lpm rk, z+                            \n\t \
    eor b2, rk                            \n\t \
                                               \
    lpm rk, z+                            \n\t \
    eor b1, rk                            \n\t \
                                               \
    lpm rk, z+                            \n\t \
    eor b0, rk                            \n\t \
                                               \
    sbiw r30, 8                            \n\t
#else
#define DEC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk) \
    ld rk, -z                             \n\t \
    eor b3, rk                            \n\t \
                                               \
    ld rk, -z                             \n\t \
    eor b2, rk                            \n\t \
                                               \
    ld rk, -z                             \n\t \
    eor b1, rk                            \n\t \
                                               \
    ld rk, -z                             \n\t \
    eor b0, rk                            \n\t
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


#define L_(b0, b1, b2, b3, b4, b5, b6, b7) \
    eor b4, b0                        \n\t \
    eor b4, b1                        \n\t \
    eor b4, b3                        \n\t \
                                           \
    eor b5, b0                        \n\t \
    eor b5, b1                        \n\t \
    eor b5, b2                        \n\t \
                                           \
    eor b6, b1                        \n\t \
    eor b6, b2                        \n\t \
    eor b6, b3                        \n\t \
                                           \
    eor b7, b0                        \n\t \
    eor b7, b2                        \n\t \
    eor b7, b3                        \n\t


#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk) \
    lpm rk, z+                                \n\t \
    eor b0, rk                                \n\t \
                                                   \
    lpm rk, z+                                \n\t \
    eor b1, rk                                \n\t \
                                                   \
    lpm rk, z+                                \n\t \
    eor b2, rk                                \n\t \
                                                   \
    lpm rk, z+                                \n\t \
    eor b3, rk                                \n\t
#else
#define ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk) \
    ld rk, z+                                 \n\t \
    eor b0, rk                                \n\t \
                                                   \
    ld rk, z+                                 \n\t \
                                                   \
    eor b1, rk                                \n\t \
    ld rk, z+                                 \n\t \
    eor b2, rk                                \n\t \
                                                   \
    ld rk, z+                                 \n\t \
    eor b3, rk                                \n\t
#endif

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk) \
    lpm rk, z+                                \n\t \
    eor b0, rk                                \n\t \
                                                   \
    lpm rk, z+                                \n\t \
    eor b1, rk                                \n\t \
                                                   \
    lpm rk, z+                                \n\t \
    eor b2, rk                                \n\t \
                                                   \
    lpm rk, z+                                \n\t \
    eor b3, rk                                \n\t \
                                                   \
    sbiw r30, 8                               \n\t
#else
#define DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk) \
    ld rk, -z                                 \n\t \
    eor b3, rk                                \n\t \
                                                   \
    ld rk, -z                                 \n\t \
    eor b2, rk                                \n\t \
                                                   \
    ld rk, -z                                 \n\t \
    eor b1, rk                                \n\t \
                                                   \
    ld rk, -z                                 \n\t \
    eor b0, rk                                \n\t
#endif


#define EKS_STORE_ROUND_KEYS(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11) \
    STR(EKS_STORE_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11))


#define EKS_ROUND_KEYS(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, c) \
    STR(EKS_ROUND_KEYS_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, c))


#define EKS_WHITENING_KEYS(k0, k1, k2, k3, k14, k15, c) \
    STR(EKS_WHITENING_KEYS_(k0, k1, k2, k3, k14, k15, c))


#define ENC_ADD_ROUND_KEY(b0, b1, b2, b3, rk) \
    STR(ENC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk))

#define DEC_ADD_ROUND_KEY(b0, b1, b2, b3, rk) \
    STR(DEC_ADD_ROUND_KEY_(b0, b1, b2, b3, rk))


#define ENC_A(b0, b1, b2, b3) \
    STR(ENC_A_(b0, b1, b2, b3))

#define DEC_A(b0, b1, b2, b3) \
    STR(DEC_A_(b0, b1, b2, b3))


#define L(b0, b1, b2, b3, b4, b5, b6, b7) \
    STR(L_(b0, b1, b2, b3, b4, b5, b6, b7))


#define ENC_ADD_WHITENING_KEY(b0, b1, b2, b3, rk) \
    STR(ENC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk))

#define DEC_ADD_WHITENING_KEY(b0, b1, b2, b3, rk) \
    STR(DEC_ADD_WHITENING_KEY_(b0, b1, b2, b3, rk))


#endif /* AVR_MACROS_H */
