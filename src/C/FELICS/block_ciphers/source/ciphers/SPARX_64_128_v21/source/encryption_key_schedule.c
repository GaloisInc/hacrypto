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

#include <stdint.h>

#include "cipher.h"
#include "constants.h"

#include "speckey.h"


#if !defined(ARM) && !defined(AVR) && !defined(MSP)

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint8_t i;
    uint16_t temp[2];

    uint16_t *Key = (uint16_t *)key;
    uint16_t *RoundKeys = (uint16_t *)roundKeys;


    RoundKeys[0] = Key[0];
    RoundKeys[1] = Key[1];

    RoundKeys[2] = Key[2];
    RoundKeys[3] = Key[3];

    RoundKeys[4] = Key[4];
    RoundKeys[5] = Key[5];

    temp[0] = Key[6];
    temp[1] = Key[7];


    for(i = 1; i < 2 * NUMBER_OF_ROUNDS; i++)
    {
        RoundKeys[6 * i + 0] = temp[0];
        RoundKeys[6 * i + 1] = temp[1] + i;

        temp[0] = RoundKeys[6 * (i - 1) + 0];
        temp[1] = RoundKeys[6 * (i - 1) + 1];
        speckey(temp, temp + 1);

        RoundKeys[6 * i + 2] = temp[0];
        RoundKeys[6 * i + 3] = temp[1];

        RoundKeys[6 * i + 4] = temp[0] + RoundKeys[6 * (i - 1) + 2]; 
        RoundKeys[6 * i + 5] = temp[1] + RoundKeys[6 * (i - 1) + 3];

        temp[0] = RoundKeys[6 * (i - 1) + 4];
        temp[1] = RoundKeys[6 * (i - 1) + 5];
    }


    RoundKeys[6 * 2 * NUMBER_OF_ROUNDS + 0] = temp[0];
    RoundKeys[6 * 2 * NUMBER_OF_ROUNDS + 1] = temp[1] + 2 * NUMBER_OF_ROUNDS;

    temp[0] = RoundKeys[6 * (2 * NUMBER_OF_ROUNDS - 1) + 0];
    temp[1] = RoundKeys[6 * (2 * NUMBER_OF_ROUNDS - 1) + 1];
    speckey(temp, temp + 1);

    RoundKeys[6 * 2 * NUMBER_OF_ROUNDS + 2] = temp[0];
    RoundKeys[6 * 2 * NUMBER_OF_ROUNDS + 3] = temp[1];
}

#elif defined(ARM)

/* ARM ASM implementation - begin */

#include "arm_macros.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r0 - *key
            r1 - *roundKeys
        */

        /*
            r0 - loop counter

            r2 - round key 0
            r3 - round key 1
            r4 - round key 2 / temp
            r5 - round key 3

            r6 - temp
            r7 - temp
            r8 - temp

            r9 - halfword mask
        */


        /* save context */
        "stmdb sp!, {r2-r9}" "\n\t"


        /* set halfword mask */
        SET_MASK(r9)


        /* load key */
        "ldm r0, {r2-r5}" "\n\t"


        /* store round keys */
        EKS_STORE_ROUND_KEYS(r2, r3, r4)


        /* initialize loop counter */
        "mov r0, #1" "\n\t"
        "step:" "\n\t"


        EKS_ROUND_KEYS(r2, r3, r4, r5, r6, r7, r8, r9, r0)
        EKS_STORE_ROUND_KEYS(r5, r2, r3)
        "add r0, r0, #1" "\n\t"


        EKS_ROUND_KEYS(r5, r2, r3, r4, r6, r7, r8, r9, r0)
        EKS_STORE_ROUND_KEYS(r4, r5, r2)
        "add r0, r0, #1" "\n\t"


        EKS_ROUND_KEYS(r4, r5, r2, r3, r6, r7, r8, r9, r0)
        EKS_STORE_ROUND_KEYS(r3, r4, r5)
        "add r0, r0, #1" "\n\t"


        EKS_ROUND_KEYS(r3, r4, r5, r2, r6, r7, r8, r9, r0)
        EKS_STORE_ROUND_KEYS(r2, r3, r4)
        "add r0, r0, #1" "\n\t"


        /* loop end */
        "cmp r0, #13" "\n\t"
        "bne step" "\n\t"


        EKS_ROUND_KEYS(r2, r3, r4, r5, r6, r7, r8, r9, r0)
        EKS_STORE_ROUND_KEYS(r5, r2, r3)
        "add r0, r0, #1" "\n\t"


        EKS_ROUND_KEYS(r5, r2, r3, r4, r6, r7, r8, r9, r0)
        EKS_STORE_ROUND_KEYS(r4, r5, r2)
        "add r0, r0, #1" "\n\t"


        EKS_ROUND_KEYS(r4, r5, r2, r3, r6, r7, r8, r9, r0)
        EKS_STORE_ROUND_KEYS(r3, r4, r5)
        "add r0, r0, #1" "\n\t"


        /* post whitening keys */
        EKS_WHITENING_KEYS(r3, r4, r5, r2, r6, r7, r9, r0)


        /* store round keys */
        "stm r1!, {r2, r3}" "\n\t"


        /* restore context */
        "ldmia sp!, {r2-r9}" "\n\t"
    );
}

/* ARM ASM implementation - end */

#elif defined(AVR)

#include "avr_macros.h"

void /*__attribute__((naked))*/ RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r25, r24 - *key
            r23, r22 - *roundKeys
        */

        /*
            r11 - round key 0
            r12 - round key 0
            r13 - round key 0
            r14 - round key 0

            r15 - round key 1
            r16 - round key 1
            r17 - round key 1
            r18 - round key 1

            r19 - round key 2
            r20 - round key 2
            r21 - round key 2
            r22 - round key 3

            r23 - round key 3
            r24 - round key 3
            r25 - round key 3
            r26 - round key 3

            r27 - loop counter
        */


        /* save context */
        "push r11" "\n\t"
        "push r12" "\n\t"
        "push r13" "\n\t"
        "push r14" "\n\t"
        "push r15" "\n\t"
        "push r16" "\n\t"
        "push r17" "\n\t"


        /* set key pointer: X (r27, r26) */
        "movw r26, r24" "\n\t"
        /* set round keys pointer: Z (r31, r30) */
        "movw r30, r22" "\n\t"


        /* load key */
        "ld r11, x+" "\n\t"
        "ld r12, x+" "\n\t"
        "ld r13, x+" "\n\t"
        "ld r14, x+" "\n\t"

        "ld r15, x+" "\n\t"
        "ld r16, x+" "\n\t"
        "ld r17, x+" "\n\t"
        "ld r18, x+" "\n\t"

        "ld r19, x+" "\n\t"
        "ld r20, x+" "\n\t"
        "ld r21, x+" "\n\t"
        "ld r22, x+" "\n\t"

        "ld r23, x+" "\n\t"
        "ld r24, x+" "\n\t"
        "ld r25, x+" "\n\t"
        "ld r26, x+" "\n\t"


        /* store round keys */
        EKS_STORE_ROUND_KEYS(r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22)


        /* initialize loop counter */
        "ldi r27, 1" "\n\t"
        "step:" "\n\t"


        EKS_ROUND_KEYS(r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27)
        EKS_STORE_ROUND_KEYS(r23, r24, r25, r26, r11, r12, r13, r14, r15, r16, r17, r18)
        "inc r27" "\n\t"


        EKS_ROUND_KEYS(r23, r24, r25, r26, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r27)
        EKS_STORE_ROUND_KEYS(r19, r20, r21, r22, r23, r24, r25, r26, r11, r12, r13, r14)
        "inc r27" "\n\t"


        EKS_ROUND_KEYS(r19, r20, r21, r22, r23, r24, r25, r26, r11, r12, r13, r14, r15, r16, r17, r18, r27)
        EKS_STORE_ROUND_KEYS(r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26)
        "inc r27" "\n\t"


        EKS_ROUND_KEYS(r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r11, r12, r13, r14, r27)
        EKS_STORE_ROUND_KEYS(r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22)
        "inc r27" "\n\t"


        /* loop end */
        "cpi r27, 13" "\n\t"
        "breq end_step" "\n\t"
        "jmp step" "\n\t"
        "end_step:"


        EKS_ROUND_KEYS(r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27)
        EKS_STORE_ROUND_KEYS(r23, r24, r25, r26, r11, r12, r13, r14, r15, r16, r17, r18)
        "inc r27" "\n\t"


        EKS_ROUND_KEYS(r23, r24, r25, r26, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r27)
        EKS_STORE_ROUND_KEYS(r19, r20, r21, r22, r23, r24, r25, r26, r11, r12, r13, r14)
        "inc r27" "\n\t"


        EKS_ROUND_KEYS(r19, r20, r21, r22, r23, r24, r25, r26, r11, r12, r13, r14, r15, r16, r17, r18, r27)
        EKS_STORE_ROUND_KEYS(r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26)
        "inc r27" "\n\t"



        /* post whitening keys */
        EKS_WHITENING_KEYS(r15, r16, r17, r18, r13, r14, r27)


        /* store round keys */
        "st z+, r11" "\n\t"
        "st z+, r12" "\n\t"
        "st z+, r13" "\n\t"
        "st z+, r14" "\n\t"

        "st z+, r15" "\n\t"
        "st z+, r16" "\n\t"
        "st z+, r17" "\n\t"
        "st z+, r18" "\n\t"


        /* restore context */
        "pop r17" "\n\t"
        "pop r16" "\n\t"
        "pop r15" "\n\t"
        "pop r14" "\n\t"
        "pop r13" "\n\t"
        "pop r12" "\n\t"
        "pop r11" "\n\t"
    );
}

#elif defined(MSP)

#include "msp_macros.h"

void /*__attribute__((naked))*/ RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r15 - *key
            r14 - *roundKeys
        */

        /*
            r6 - round key 0
            r7 - round key 0

            r8 - round key 1
            r9 - round key 1

            r10 - round key 2
            r11 - round key 2

            r12 - round key 3
            r13 - round key 3

            r15 - loop counter
        */


        /* save context */
        "push r6" "\n\t"
        "push r7" "\n\t"
        "push r8" "\n\t"
        "push r9" "\n\t"
        "push r10" "\n\t"
        "push r11" "\n\t"


        /* load key */
        "mov @r15+, r6" "\n\t"
        "mov @r15+, r7" "\n\t"

        "mov @r15+, r8" "\n\t"
        "mov @r15+, r9" "\n\t"

        "mov @r15+, r10" "\n\t"
        "mov @r15+, r11" "\n\t"

        "mov @r15+, r12" "\n\t"
        "mov @r15+, r13" "\n\t"


        /* store round keys */
        EKS_STORE_ROUND_KEYS(r6, r7, r8, r9, r10, r11)


        /* initialize loop counter */
        "mov #1, r15" "\n\t"
        "step:" "\n\t"


        EKS_ROUND_KEYS(r6, r7, r8, r9, r10, r11, r12, r13, r15)
        EKS_STORE_ROUND_KEYS(r12, r13, r6, r7, r8, r9)
        "inc r15" "\n\t"


        EKS_ROUND_KEYS(r12, r13, r6, r7, r8, r9, r10, r11, r15)
        EKS_STORE_ROUND_KEYS(r10, r11, r12, r13, r6, r7)
        "inc r15" "\n\t"


        EKS_ROUND_KEYS(r10, r11, r12, r13, r6, r7, r8, r9, r15)
        EKS_STORE_ROUND_KEYS(r8, r9, r10, r11, r12, r13)
        "inc r15" "\n\t"


        EKS_ROUND_KEYS(r8, r9, r10, r11, r12, r13, r6, r7, r15)
        EKS_STORE_ROUND_KEYS(r6, r7, r8, r9, r10, r11)
        "inc r15" "\n\t"


        /* loop end */
        "cmp #13, r15" "\n\t"
        "jne step" "\n\t"


        EKS_ROUND_KEYS(r6, r7, r8, r9, r10, r11, r12, r13, r15)
        EKS_STORE_ROUND_KEYS(r12, r13, r6, r7, r8, r9)
        "inc r15" "\n\t"


        EKS_ROUND_KEYS(r12, r13, r6, r7, r8, r9, r10, r11, r15)
        EKS_STORE_ROUND_KEYS(r10, r11, r12, r13, r6, r7)
        "inc r15" "\n\t"


        EKS_ROUND_KEYS(r10, r11, r12, r13, r6, r7, r8, r9, r15)
        EKS_STORE_ROUND_KEYS(r8, r9, r10, r11, r12, r13)
        "inc r15" "\n\t"    


        /* post whitening keys */
        EKS_WHITENING_KEYS(r8, r9, r7, r15)


        /* store round keys */
        "mov r6, 0(r14)" "\n\t"
        "mov r7, 2(r14)" "\n\t"

        "mov r8, 4(r14)" "\n\t"
        "mov r9, 6(r14)" "\n\t"


        /* restore context */
        "pop r11" "\n\t"
        "pop r10" "\n\t"
        "pop r9" "\n\t"
        "pop r8" "\n\t"
        "pop r7" "\n\t"
        "pop r6" "\n\t"
    );
}

#endif
