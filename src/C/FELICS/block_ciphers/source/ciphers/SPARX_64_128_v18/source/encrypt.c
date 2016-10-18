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

#include "round.h"


#if !defined(ARM) && !defined(AVR) && !defined(MSP)

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    uint8_t i;

    uint32_t *left = (uint32_t *)block;
    uint32_t *right = (uint32_t *)block + 1;
    uint32_t *RoundKeys = (uint32_t *)roundKeys;


    for (i = 0; i < NUMBER_OF_ROUNDS; i++)
    {
        round_f(left, right, &RoundKeys[6 * i]);
    }


    /* post whitening */
    *left ^= READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[6 * NUMBER_OF_ROUNDS]);
    *right ^= READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[6 * NUMBER_OF_ROUNDS + 1]);
}

#elif defined(ARM)

/* ARM ASM implementation - begin */

#include "arm_macros.h"

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r0 - *block
            r1 - *roundKeys
        */

        /*
            r2 - left branch
            r3 - right branch

            r4 - round key / temp
            r5 - temp

            r6 - halfword mask
        */


        /* save context */
        "stmdb sp!, {r2-r6}" "\n\t"


        /* set halfword mask */
        SET_MASK(r6)


        /* load block */
        "ldm r0, {r2-r3}" "\n\t"


        /* Step 1 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)


        /* linear layer */
        L(r2, r3)
        /* Step 1 - end */


        /* Step 2 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)


        /* linear layer */
        L(r3, r2)
        /* Step 2 - end */


        /* Step 3 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)


        /* linear layer */
        L(r2, r3)
        /* Step 3 - end */


        /* Step 4 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)


        /* linear layer */
        L(r3, r2)
        /* Step 4 - end */


        /* Step 5 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)


        /* linear layer */
        L(r2, r3)
        /* Step 5 - end */


        /* Step 6 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)


        /* linear layer */
        L(r3, r2)
        /* Step 6 - end */


        /* Step 7 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)


        /* linear layer */
        L(r2, r3)
        /* Step 7 - end */


        /* Step 8 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r4, r5, r6)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r4, r5, r6)


        /* linear layer */
        L(r3, r2)
        /* Step 8 - end */


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r2, r3, r4)


        /* store block */
        "stm r0, {r2-r3}" "\n\t"


        /* restore context */
        "ldmia sp!, {r2-r6}" "\n\t"
    );
}

/* ARM ASM implementation - end */

#elif defined(AVR)

/* AVR ASM implementation - begin */

#include "avr_macros.h"

void /*__attribute__((naked))*/ Encrypt(uint8_t *block, uint8_t *roundKeys)
{
/*
References:
1) http://www.atmel.com/webdoc/avrassembler/avrassembler.wb_instructions.Branch_Instructions.html
*/

    asm volatile(
        /*
            r25, r24 - *block
            r23, r22 - *roundKeys
        */

        /*
            r17 - left branch (Speckey left branch)
            r18 - left branch (Speckey left branch)
            r19 - left branch (Speckey right branch)
            r20 - left branch (Speckey right branch)

            r21 - right branch (Speckey left branch)
            r22 - right branch (Speckey left branch)
            r23 - right branch (Speckey right branch)
            r24 - right branch (Speckey right branch)

            r25 - round key / temp
        */


        /* save context */
        "push r17" "\n\t"


        /* set block pointer: X (r27, r26) */
        "movw r26, r24" "\n\t"
        /* set key pointer: Z (r31, r30) */
        "movw r30, r22" "\n\t"


        /* load block */
        "ld r17, x+" "\n\t"
        "ld r18, x+" "\n\t"
        "ld r19, x+" "\n\t"
        "ld r20, x+" "\n\t"

        "ld r21, x+" "\n\t"
        "ld r22, x+" "\n\t"
        "ld r23, x+" "\n\t"
        "ld r24, x+" "\n\t"


        /* Step 1 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)
        /* Step 1 - end */


        /* Step 2 - begin */
        /* linear layer */
        L(r17, r18, r19, r20, r21, r22, r23, r24)


        /* process left branch */
        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        /* linear layer */
        L(r21, r22, r23, r24, r17, r18, r19, r20)
        /* Step 2 - end */


        /* Step 3 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)
        /* Step 3 - end */


        /* Step 4 - begin */
        /* linear layer */
        L(r17, r18, r19, r20, r21, r22, r23, r24)


        /* process left branch */
        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        /* linear layer */
        L(r21, r22, r23, r24, r17, r18, r19, r20)
        /* Step 4 - end */


        /* Step 5 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)
        /* Step 5 - end */


        /* Step 6 - begin */
        /* linear layer */
        L(r17, r18, r19, r20, r21, r22, r23, r24)


        /* process left branch */
        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        /* linear layer */
        L(r21, r22, r23, r24, r17, r18, r19, r20)
        /* Step 6 - end */


        /* Step 7 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)
        /* Step 7 - end */


        /* Step 8 - begin */
        /* linear layer */
        L(r17, r18, r19, r20, r21, r22, r23, r24)


        /* process left branch */
        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        ENC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)
        ENC_A(r21, r22, r23, r24)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        ENC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        ENC_A(r17, r18, r19, r20)


        /* linear layer */
        L(r21, r22, r23, r24, r17, r18, r19, r20)
        /* Step 8 - end */


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r17, r18, r19, r20, r25)
        ENC_ADD_WHITENING_KEY(r21, r22, r23, r24, r25)


        /* store block */
        "st -x, r24" "\n\t"
        "st -x, r23" "\n\t"
        "st -x, r22" "\n\t"
        "st -x, r21" "\n\t"

        "st -x, r20" "\n\t"
        "st -x, r19" "\n\t"
        "st -x, r18" "\n\t"
        "st -x, r17" "\n\t"


        /* restore context */
        "pop r17" "\n\t"
    );
}

/* AVR ASM implementation - end */

#elif defined(MSP)

/* MSP ASM implementation - begin */

#include "msp_macros.h"

void /*__attribute__((naked))*/ Encrypt(uint8_t *block, uint8_t *roundKeys)
{
/*
References:
1) http://www.ece.utep.edu/courses/web3376/Links_files/MSP430%20Quick%20Reference.pdf
*/

    asm volatile(
        /*
            r15 - *block
            r14 - *roundKeys
        */

        /*
            r9 - left branch (Speckey left branch)
            r10 - left branch (Speckey right branch)

            r11 - right branch (Speckey left branch)
            r12 - right branch (Speckey right branch)

            r13 - round key / temp
        */


        /* save context */
        "push r9" "\n\t"
        "push r10" "\n\t"
        "push r11" "\n\t"


        /* load block */
        "mov @r15+, r9" "\n\t"
        "mov @r15+, r10" "\n\t"
        "mov @r15+, r11" "\n\t"
        "mov @r15+, r12" "\n\t"


        /* Step 1 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        L(r9, r10, r11, r12, r13)
        /* Step 1 - end */


        /* Step 2 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        L(r11, r12, r9, r10, r13)
        /* Step 2 - end */


        /* Step 3 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        L(r9, r10, r11, r12, r13)
        /* Step 3 - end */


        /* Step 4 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        L(r11, r12, r9, r10, r13)
        /* Step 4 - end */


        /* Step 5 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        L(r9, r10, r11, r12, r13)
        /* Step 5 - end */


        /* Step 6 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        L(r11, r12, r9, r10, r13)
        /* Step 6 - end */


        /* Step 7 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        L(r9, r10, r11, r12, r13)
        /* Step 7 - end */


        /* Step 8 - begin */
        /* process left branch */
        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        ENC_ADD_ROUND_KEY(r11, r12, r13)
        ENC_A(r11, r12)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        ENC_ADD_ROUND_KEY(r9, r10, r13)
        ENC_A(r9, r10)


        L(r11, r12, r9, r10, r13)
        /* Step 8 - end */


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r9, r10, r13)
        ENC_ADD_WHITENING_KEY(r11, r12, r13)


        /* store block */
        "mov r9, -8(r15)" "\n\t"
        "mov r10, -6(r15)" "\n\t"
        "mov r11, -4(r15)" "\n\t"
        "mov r12, -2(r15)" "\n\t"


        /* restore context */
        "pop r11" "\n\t"
        "pop r10" "\n\t"
        "pop r9" "\n\t"
    );
}

/* MSP ASM implementation - end */

#endif
