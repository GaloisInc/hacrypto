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

#include "round_inverse.h"


#if !defined(ARM) && !defined(AVR) && !defined(MSP)

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    int8_t i;

    uint16_t *Block = (uint16_t *)block;
    uint16_t *RoundKeys = (uint16_t *)roundKeys;


    /* post whitening */
    for (i = 0; i < 8; i++)
    {
        Block[i] ^= READ_ROUND_KEY_WORD(RoundKeys[32 * NUMBER_OF_ROUNDS + i]);
    }


    for (i = NUMBER_OF_ROUNDS - 1; i >= 0 ; i--)
    {
        round_f_inverse(Block, &RoundKeys[32 * i]);
    }
}

#elif defined(ARM)

/* ARM ASM implementation - begin */

#include "arm_macros.h"

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r0 - *block
            r1 - *roundKeys
        */

        /*
            r2 - first branch
            r3 - second branch
            r4 - third branch
            r5 - fourth branch

            r6 - round key / temp
            r7 - temp
            r8 - temp

            r9 - halfword mask
            r10 - loop counter
        */


        /* save context */
        "stmdb sp!, {r2-r10}" "\n\t"


        SET_MASK(r9)


        /* set the pointer to round keys */
        "add r1, #528" "\n\t"


        /* load block */
        "ldm r0, {r2-r5}" "\n\t"


        /* post whitening */
        DEC_ADD_WHITENING_KEY(r2, r3, r4, r5, r6)


        /* initialize loop counter */
        "mov r10, 4" "\n\t"
        "step:" "\n\t"


        /* linear layer */
        L(r4, r5, r2, r3, r6, r7, r8, r9)


        /* process fourth branch */
        DEC_A(r3, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r3, r6)

        DEC_A(r3, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r3, r6)

        DEC_A(r3, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r3, r6)

        DEC_A(r3, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r3, r6)


        /* process third branch */
        DEC_A(r2, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r2, r6)

        DEC_A(r2, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r2, r6)

        DEC_A(r2, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r2, r6)

        DEC_A(r2, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r2, r6)


        /* process second branch */
        DEC_A(r5, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r5, r6)

        DEC_A(r5, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r5, r6)

        DEC_A(r5, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r5, r6)

        DEC_A(r5, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r5, r6)


        /* process first branch */
        DEC_A(r4, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r4, r6)

        DEC_A(r4, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r4, r6)

        DEC_A(r4, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r4, r6)

        DEC_A(r4, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r4, r6)


        /* linear layer */
        L(r2, r3, r4, r5, r6, r7, r8, r9)


        /* process fourth branch */
        DEC_A(r5, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r5, r6)

        DEC_A(r5, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r5, r6)

        DEC_A(r5, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r5, r6)

        DEC_A(r5, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r5, r6)


        /* process third branch */
        DEC_A(r4, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r4, r6)

        DEC_A(r4, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r4, r6)

        DEC_A(r4, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r4, r6)

        DEC_A(r4, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r4, r6)


        /* process second branch */
        DEC_A(r3, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r3, r6)

        DEC_A(r3, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r3, r6)

        DEC_A(r3, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r3, r6)

        DEC_A(r3, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r3, r6)


        /* process first branch */
        DEC_A(r2, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r2, r6)

        DEC_A(r2, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r2, r6)

        DEC_A(r2, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r2, r6)

        DEC_A(r2, r6, r7, r9)
        DEC_ADD_ROUND_KEY(r2, r6)


        /* loop end */
        "subs r10, r10, #1" "\n\t"
        "bne step" "\n\t"


        /* store block */
        "stm r0, {r2-r5}" "\n\t"


        /* restore context */
        "ldmia sp!, {r2-r10}" "\n\t"
    );
}

/* ARM ASM implementation - end */

#elif defined(AVR)

/* AVR ASM implementation - begin */

#include "avr_macros.h"

void /*__attribute__((naked))*/ Decrypt(uint8_t *block, uint8_t *roundKeys)
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
            r8 - first branch

            r9 - first branch
            r10 - first branch
            r11 - first branch
            r12 - first branch

            r13 - second branch
            r14 - second branch
            r15 - second branch
            r16 - second branch

            r17 - third branch
            r18 - third branch
            r19 - third branch
            r20 - third branch

            r21 - fourth branch
            r22 - fourth branch
            r23 - fourth branch
            r24 - fourth branch

            r25 - round key / temp
        */


        /* save context */
        "push r8" "\n\t"
        "push r9" "\n\t"
        "push r10" "\n\t"
        "push r11" "\n\t"
        "push r12" "\n\t"
        "push r13" "\n\t"
        "push r14" "\n\t"
        "push r15" "\n\t"
        "push r16" "\n\t"
        "push r17" "\n\t"


        /* set block pointer: X (r27, r26) */
        "movw r26, r24" "\n\t"
        /* set key pointer: Z (r31, r30) */
        "movw r30, r22" "\n\t"
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "ldi r25, 231" "\n\t"
#else
        "ldi r25, 233" "\n\t"
#endif
        "add r30, r25" "\n\t"
        "adc r31, __zero_reg__" "\n\t" // r1

        "add r30, r25" "\n\t"
        "adc r31, __zero_reg__" "\n\t" // r1

        "adiw r30, 62" "\n\t"


        /* load block */
        "ld r9, x+" "\n\t"
        "ld r10, x+" "\n\t"
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


        /* post whitening */
        DEC_ADD_WHITENING_KEY(r21, r22, r23, r24, r25)
        DEC_ADD_WHITENING_KEY(r17, r18, r19, r20, r25)
        DEC_ADD_WHITENING_KEY(r13, r14, r15, r16, r25)
        DEC_ADD_WHITENING_KEY(r9, r10, r11, r12, r25)


        /* Step 1 - begin */
        L(r17, r18, r19, r20, r21, r22, r23, r24, r9, r10, r11, r12, r13, r14, r15, r16, r25, r8)


        /* process fourth branch */
        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        /* process third branch */
        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        /* process second branch */
        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        /* process first branch */
        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        /* Step 1 - end */


        /* Step 2 - begin */
        L(r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r8)


        /* process fourth branch */
        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        /* process third branch */
        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        /* process second branch */
        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        /* process first branch */
        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)
        /* Step 2 - end */


        /* Step 3 - begin */
        L(r17, r18, r19, r20, r21, r22, r23, r24, r9, r10, r11, r12, r13, r14, r15, r16, r25, r8)


        /* process fourth branch */
        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        /* process third branch */
        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        /* process second branch */
        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        /* process first branch */
        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        /* Step 3 - end */


        /* Step 4 - begin */
        L(r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r8)


        /* process fourth branch */
        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        /* process third branch */
        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        /* process second branch */
        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        /* process first branch */
        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)
        /* Step 4 - end */


        /* Step 5 - begin */
        L(r17, r18, r19, r20, r21, r22, r23, r24, r9, r10, r11, r12, r13, r14, r15, r16, r25, r8)


        /* process fourth branch */
        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        /* process third branch */
        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        /* process second branch */
        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        /* process first branch */
        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        /* Step 5 - end */


        /* Step 6 - begin */
        L(r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r8)


        /* process fourth branch */
        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        /* process third branch */
        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        /* process second branch */
        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        /* process first branch */
        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)
        /* Step 6 - end */


        /* Step 7 - begin */
        L(r17, r18, r19, r20, r21, r22, r23, r24, r9, r10, r11, r12, r13, r14, r15, r16, r25, r8)


        /* process fourth branch */
        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        /* process third branch */
        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        /* process second branch */
        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        /* process first branch */
        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)
        /* Step 7 - end */


        /* Step 8 - begin */
        L(r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r8)


        /* process fourth branch */
        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        DEC_A(r21, r22, r23, r24)
        DEC_ADD_ROUND_KEY(r21, r22, r23, r24, r25)


        /* process third branch */
        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        DEC_A(r17, r18, r19, r20)
        DEC_ADD_ROUND_KEY(r17, r18, r19, r20, r25)


        /* process second branch */
        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        DEC_A(r13, r14, r15, r16)
        DEC_ADD_ROUND_KEY(r13, r14, r15, r16, r25)


        /* process first branch */
        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)


        DEC_A(r9, r10, r11, r12)
        DEC_ADD_ROUND_KEY(r9, r10, r11, r12, r25)
        /* Step 8 - end */


        /* store block */
        "st -x, r24" "\n\t"
        "st -x, r23" "\n\t"
        "st -x, r22" "\n\t"
        "st -x, r21" "\n\t"

        "st -x, r20" "\n\t"
        "st -x, r19" "\n\t"
        "st -x, r18" "\n\t"
        "st -x, r17" "\n\t"

        "st -x, r16" "\n\t"
        "st -x, r15" "\n\t"
        "st -x, r14" "\n\t"
        "st -x, r13" "\n\t"

        "st -x, r12" "\n\t"
        "st -x, r11" "\n\t"
        "st -x, r10" "\n\t"
        "st -x, r9" "\n\t"


        /* restore context */
        "pop r17" "\n\t"
        "pop r16" "\n\t"
        "pop r15" "\n\t"
        "pop r14" "\n\t"
        "pop r13" "\n\t"
        "pop r12" "\n\t"
        "pop r11" "\n\t"
        "pop r10" "\n\t"
        "pop r9" "\n\t"
        "pop r8" "\n\t"
    );
}

/* AVR ASM implementation - end */

#elif defined(MSP)

/* MSP ASM implementation - begin */

#include "msp_macros.h"

void /*__attribute__((naked))*/ Decrypt(uint8_t *block, uint8_t *roundKeys)
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
            r5 - first branch
            r6 - first branch

            r7 - second branch
            r8 - second branch

            r9 - third branch
            r10 - third branch

            r11 - fourth branch
            r12 - fourth branch

            r13 - round key / temp
        */


        /* save context */
        "push r5" "\n\t"
        "push r6" "\n\t"
        "push r7" "\n\t"
        "push r8" "\n\t"
        "push r9" "\n\t"
        "push r10" "\n\t"
        "push r11" "\n\t"


        /* load block */
        "mov @r15+, r5" "\n\t"
        "mov @r15+, r6" "\n\t"
        "mov @r15+, r7" "\n\t"
        "mov @r15+, r8" "\n\t"

        "mov @r15+, r9" "\n\t"
        "mov @r15+, r10" "\n\t"
        "mov @r15+, r11" "\n\t"
        "mov @r15+, r12" "\n\t"


        /* set key pointer */
        "add #524, r14"   "\n\t"


        /* post whitening */
        DEC_ADD_WHITENING_KEY(r11, r12, r13)
        DEC_ADD_WHITENING_KEY(r9, r10, r13)
        DEC_ADD_WHITENING_KEY(r7, r8, r13)
        DEC_ADD_WHITENING_KEY(r5, r6, r13)


        /* Step 1 - begin */
        L(r9, r10, r11, r12, r5, r6, r7, r8, r13)


        /* process fourth branch */
        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        /* process third branch */
        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        /* process second branch */
        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        /* process first branch */
        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)
        /* Step 1 - end */


        /* Step 2 - begin */
        L(r5, r6, r7, r8, r9, r10, r11, r12, r13)


        /* process fourth branch */
        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        /* process third branch */
        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        /* process second branch */
        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        /* process first branch */
        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)
        /* Step 2 - end */


        /* Step 3 - begin */
        L(r9, r10, r11, r12, r5, r6, r7, r8, r13)


        /* process fourth branch */
        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        /* process third branch */
        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        /* process second branch */
        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        /* process first branch */
        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)
        /* Step 3 - end */


        /* Step 4 - begin */
        L(r5, r6, r7, r8, r9, r10, r11, r12, r13)


        /* process fourth branch */
        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        /* process third branch */
        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        /* process second branch */
        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        /* process first branch */
        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)
        /* Step 4 - end */


        /* Step 5 - begin */
        L(r9, r10, r11, r12, r5, r6, r7, r8, r13)


        /* process fourth branch */
        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        /* process third branch */
        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        /* process second branch */
        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        /* process first branch */
        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)
        /* Step 5 - end */


        /* Step 6 - begin */
        L(r5, r6, r7, r8, r9, r10, r11, r12, r13)


        /* process fourth branch */
        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        /* process third branch */
        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        /* process second branch */
        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        /* process first branch */
        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)
        /* Step 6 - end */


        /* Step 7 - begin */
        L(r9, r10, r11, r12, r5, r6, r7, r8, r13)


        /* process fourth branch */
        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        /* process third branch */
        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        /* process second branch */
        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        /* process first branch */
        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)
        /* Step 7 - end */


        /* Step 8 - begin */
        L(r5, r6, r7, r8, r9, r10, r11, r12, r13)


        /* process fourth branch */
        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        DEC_A(r11, r12)
        DEC_ADD_ROUND_KEY(r11, r12, r13)


        /* process third branch */
        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        DEC_A(r9, r10)
        DEC_ADD_ROUND_KEY(r9, r10, r13)


        /* process second branch */
        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        DEC_A(r7, r8)
        DEC_ADD_ROUND_KEY(r7, r8, r13)


        /* process first branch */
        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)


        DEC_A(r5, r6)
        DEC_ADD_ROUND_KEY(r5, r6, r13)
        /* Step 8 - end */


        /* store block */
        "mov r5, -16(r15)" "\n\t"
        "mov r6, -14(r15)" "\n\t"
        "mov r7, -12(r15)" "\n\t"
        "mov r8, -10(r15)" "\n\t"

        "mov r9, -8(r15)" "\n\t"
        "mov r10, -6(r15)" "\n\t"
        "mov r11, -4(r15)" "\n\t"
        "mov r12, -2(r15)" "\n\t"


        /* restore context */
        "pop r11" "\n\t"
        "pop r10" "\n\t"
        "pop r9" "\n\t"
        "pop r8" "\n\t"
        "pop r7" "\n\t"
        "pop r6" "\n\t"
        "pop r5" "\n\t"
    );
}

/* MSP ASM implementation - end */

#endif
