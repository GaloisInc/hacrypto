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
            r4 - round key
            r5 - Speckey left branch
            r6 - Speckey right branch
            r7 - temp
            r8 - halfword mask
            r9 - loop counter
            r10 - loop counter
        */


        /* save context */
        "stmdb sp!, {r2-r10}" "\n\t"


        /* set halfword mask */
        SET_MASK(r8)


        /* load block */
        "ldm r0, {r2-r3}" "\n\t"


        /* initialize loop counter */
        "mov r9, 8" "\n\t"
        "step:" "\n\t"


        /* process left branch */
        /* initialize loop counter */
        "mov r10, 3" "\n\t"
        "left:" "\n\t"

        ENC_ADD_ROUND_KEY(r2, r4)
        ENC_A(r2, r5, r6, r7, r8)

        /* loop end */
        "subs r10, r10, #1" "\n\t"
        "bne left" "\n\t"


        /* process right branch */
        /* initialize loop counter */
        "mov r10, 3" "\n\t"
        "right:" "\n\t"

        ENC_ADD_ROUND_KEY(r3, r4)
        ENC_A(r3, r5, r6, r7, r8)

        /* loop end */
        "subs r10, r10, #1" "\n\t"
        "bne right" "\n\t"


        /* linear layer */
        ENC_L(r2, r3, r7)


        /* loop end */
        "subs r9, r9, #1" "\n\t"
        "bne step" "\n\t"


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r2, r3, r4)


        /* store block */
        "stm r0, {r2-r3}" "\n\t"


        /* restore context */
        "ldmia sp!, {r2-r10}" "\n\t"
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
            r2 - left branch (Speckey left branch)
            r3 - left branch (Speckey left branch)
            r4 - left branch (Speckey right branch)
            r5 - left branch (Speckey right branch)

            r6 - right branch (Speckey left branch)
            r7 - right branch (Speckey left branch)
            r8 - right branch (Speckey right branch)
            r9 - right branch (Speckey right branch)

            r10 - round key / temp
            r11 - round key / temp
            r12 - round key / temp
            r13 - round key / temp

            r18 - loop counter
            r19 - loop counter
        */


        /* save context */
        "push r0" "\n\t"
        "push r1" "\n\t"
        "push r2" "\n\t"
        "push r3" "\n\t"
        "push r4" "\n\t"
        "push r5" "\n\t"
        "push r6" "\n\t"
        "push r7" "\n\t"
        "push r8" "\n\t"
        "push r9" "\n\t"
        "push r10" "\n\t"
        "push r11" "\n\t"
        "push r12" "\n\t"
        "push r13" "\n\t"

        "push r18" "\n\t"
        "push r19" "\n\t"

        "push r27" "\n\t"
        "push r26" "\n\t"

        "push r31" "\n\t"
        "push r30" "\n\t"


        /* set block pointer: X (r27, r26) */
        "movw r26, r24" "\n\t"
        /* set key pointer: Z (r31, r30) */
        "movw r30, r22" "\n\t"


        /* load block */
        "ld r2, x+" "\n\t"
        "ld r3, x+" "\n\t"
        "ld r4, x+" "\n\t"
        "ld r5, x+" "\n\t"

        "ld r6, x+" "\n\t"
        "ld r7, x+" "\n\t"
        "ld r8, x+" "\n\t"
        "ld r9, x+" "\n\t"


        /* initialize loop counter */
        "ldi r18, 8" "\n\t"
        "step:" "\n\t"


        /* process left branch */
        /* initialize loop counter */
        "ldi r19, 3" "\n\t"
        "left:" "\n\t"
        ENC_ADD_ROUND_KEY(r2, r3, r4, r5, r10, r11, r12, r13)
        ENC_A(r2, r3, r4, r5)


        /* loop end */
        "dec r19" "\n\t"
        "brne left" "\n\t"


        /* process right branch */
        /* initialize loop counter */
        "ldi r19, 3" "\n\t"
        "right:" "\n\t"
        ENC_ADD_ROUND_KEY(r6, r7, r8, r9, r10, r11, r12, r13)
        ENC_A(r6, r7, r8, r9)


        /* loop end */
        "dec r19" "\n\t"
        "brne right" "\n\t"


        /* linear layer */
        ENC_L(r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13)


        /* loop end */
        "dec r18" "\n\t"
        "breq end_step" "\n\t"
        "jmp step" "\n\t"
        "end_step:" "\n\t"


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r2, r3, r4, r5, r10, r11, r12, r13)
        ENC_ADD_WHITENING_KEY(r6, r7, r8, r9, r10, r11, r12, r13)


        /* store block */
        "st -x, r9" "\n\t"
        "st -x, r8" "\n\t"
        "st -x, r7" "\n\t"
        "st -x, r6" "\n\t"

        "st -x, r5" "\n\t"
        "st -x, r4" "\n\t"
        "st -x, r3" "\n\t"
        "st -x, r2" "\n\t"


        /* restore context */
        "pop r30" "\n\t"
        "pop r31" "\n\t"

        "pop r26" "\n\t"
        "pop r27" "\n\t"

        "pop r19" "\n\t"
        "pop r18" "\n\t"

        "pop r13" "\n\t"
        "pop r12" "\n\t"
        "pop r11" "\n\t"
        "pop r10" "\n\t"
        "pop r9" "\n\t"
        "pop r8" "\n\t"
        "pop r7" "\n\t"
        "pop r6" "\n\t"
        "pop r5" "\n\t"
        "pop r4" "\n\t"
        "pop r3" "\n\t"
        "pop r2" "\n\t"
        "pop r1" "\n\t"
        "pop r0" "\n\t"
    );
}

/* AVR ASM implementation - end */

#elif defined(MSP)

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
            r4 - left branch (Speckey left branch)
            r5 - left branch (Speckey right branch)

            r6 - right branch (Speckey left branch)
            r7 - right branch (Speckey right branch)

            r8 - round key / temp
            r9 - round key / temp

            r10 - temp

            r11 - loop counter
            r12 - loop counter
        */


        /* save context */
        "push r4" "\n\t"
        "push r5" "\n\t"
        "push r6" "\n\t"
        "push r7" "\n\t"
        "push r8" "\n\t"
        "push r9" "\n\t"
        "push r10" "\n\t"
        "push r11" "\n\t"
        "push r12" "\n\t"


        /* load block */
        "mov @r15+, r4" "\n\t"
        "mov @r15+, r5" "\n\t"
        "mov @r15+, r6" "\n\t"
        "mov @r15+, r7" "\n\t"


        /* initialize loop counter */
        "mov #8, r11" "\n\t"
        "step:" "\n\t"


        /* initialize loop counter */
        "mov #3, r12" "\n\t"
        "left:" "\n\t"


        /* process left branch */
        ENC_ADD_ROUND_KEY(r4, r5, r8, r9)
        ENC_A(r4, r5)


        /* loop end */
        "dec r12" "\n\t"
        "jne left" "\n\t"


        /* initialize loop counter */
        "mov #3, r12" "\n\t"
        "right:" "\n\t"


        /* process right branch */
        ENC_ADD_ROUND_KEY(r6, r7, r8, r9)
        ENC_A(r6, r7)


        /* loop end */
        "dec r12" "\n\t"
        "jne right" "\n\t"


        ENC_L(r4, r5, r6, r7, r8, r9, r10)


        /* loop end */
        "dec r11" "\n\t"
        "jne step" "\n\t"


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r4, r5, r8, r9)
        ENC_ADD_WHITENING_KEY(r6, r7, r8, r9)


        /* store block */
        "mov r4, -8(r15)" "\n\t"
        "mov r5, -6(r15)" "\n\t"
        "mov r6, -4(r15)" "\n\t"
        "mov r7, -2(r15)" "\n\t"


        /* restore context */
        "pop r12" "\n\t"
        "pop r11" "\n\t"
        "pop r10" "\n\t"
        "pop r9" "\n\t"
        "pop r8" "\n\t"
        "pop r7" "\n\t"
        "pop r6" "\n\t"
        "pop r5" "\n\t"
        "pop r4" "\n\t"
    );
}

/* MSP ASM implementation - end */

#endif
