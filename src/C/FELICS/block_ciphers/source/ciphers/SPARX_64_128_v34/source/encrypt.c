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
            r2 - left branch (branch 0)
            r3 - left branch (branch 1)
            r4 - right branch (branch 2)
            r5 - right branch (branch 3)

            r6 - round key / temp
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
        "ldrh r2, [r0, #0]" "\n\t"
        "ldrh r3, [r0, #2]" "\n\t"
        "ldrh r4, [r0, #4]" "\n\t"
        "ldrh r5, [r0, #6]" "\n\t"


        /* initialize loop counter */
        "mov r9, 4" "\n\t"
        "step:" "\n\t"


        /* process left branch */
        /* initialize loop counter */
        "mov r10, 3" "\n\t"
        "b0:" "\n\t"

        ENC_ADD_ROUND_KEY(r2, r3, r6, r8)
        ENC_A(r2, r3, r6, r8)

        /* loop end */
        "subs r10, r10, #1" "\n\t"
        "bne b0" "\n\t"


        /* process right branch */
        "mov r10, 3" "\n\t"
        "b1:" "\n\t"

        ENC_ADD_ROUND_KEY(r4, r5, r6, r8)
        ENC_A(r4, r5, r6, r8)

        /* loop end */
        "subs r10, r10, #1" "\n\t"
        "bne b1" "\n\t"


        /* linear layer */
        L(r2, r3, r4, r5, r6, r7, r8)


        /* process left branch */
        "mov r10, 3" "\n\t"
        "b2:" "\n\t"

        ENC_ADD_ROUND_KEY(r4, r5, r6, r8)
        ENC_A(r4, r5, r6, r8)

        /* loop end */
        "subs r10, r10, #1" "\n\t"
        "bne b2" "\n\t"


        /* process right branch */
        "mov r10, 3" "\n\t"
        "b3:" "\n\t"

        ENC_ADD_ROUND_KEY(r2, r3, r6, r8)
        ENC_A(r2, r3, r6, r8)

        /* loop end */
        "subs r10, r10, #1" "\n\t"
        "bne b3" "\n\t"


        /* linear layer */
        L(r4, r5, r2, r3, r6, r7, r8)


        /* loop end */
        "subs r9, r9, #1" "\n\t"
        "bne step" "\n\t"


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r2, r3, r4, r5, r6, r8)


        /* store block */
        "strh r2, [r0, #0]" "\n\t"
        "strh r3, [r0, #2]" "\n\t"
        "strh r4, [r0, #4]" "\n\t"
        "strh r5, [r0, #6]" "\n\t"


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
            r16 - left branch (Speckey left branch)
            r17 - left branch (Speckey left branch)
            r18 - left branch (Speckey right branch)
            r19 - left branch (Speckey right branch)

            r20 - right branch (Speckey left branch)
            r21 - right branch (Speckey left branch)
            r22 - right branch (Speckey right branch)
            r23 - right branch (Speckey right branch)

            r24 - round key / temp

            r25 - loop counter
        */


        /* save context */
        "push r16" "\n\t"
        "push r17" "\n\t"


        /* set block pointer: X (r27, r26) */
        "movw r26, r24" "\n\t"
        /* set key pointer: Z (r31, r30) */
        "movw r30, r22" "\n\t"


        /* load block */
        "ld r16, x+" "\n\t"
        "ld r17, x+" "\n\t"
        "ld r18, x+" "\n\t"
        "ld r19, x+" "\n\t"

        "ld r20, x+" "\n\t"
        "ld r21, x+" "\n\t"
        "ld r22, x+" "\n\t"
        "ld r23, x+" "\n\t"


        /* initialize loop counter */
        "ldi r25, 8" "\n\t"
        "step:" "\n\t"


        /* process left branch */
        ENC_ADD_ROUND_KEY(r16, r17, r18, r19, r24)
        ENC_A(r16, r17, r18, r19)


        ENC_ADD_ROUND_KEY(r16, r17, r18, r19, r24)
        ENC_A(r16, r17, r18, r19)


        ENC_ADD_ROUND_KEY(r16, r17, r18, r19, r24)
        ENC_A(r16, r17, r18, r19)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r20, r21, r22, r23, r24)
        ENC_A(r20, r21, r22, r23)


        ENC_ADD_ROUND_KEY(r20, r21, r22, r23, r24)
        ENC_A(r20, r21, r22, r23)


        ENC_ADD_ROUND_KEY(r20, r21, r22, r23, r24)
        ENC_A(r20, r21, r22, r23)


        /* linear layer */
        ENC_L(r16, r17, r18, r19, r20, r21, r22, r23, r24)


        /* loop end */
        "dec r25" "\n\t"
        "breq end_step" "\n\t"
        "jmp step" "\n\t"
        "end_step:" "\n\t"


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r16, r17, r18, r19, r24)
        ENC_ADD_WHITENING_KEY(r20, r21, r22, r23, r24)


        /* store block */
        "st -x, r23" "\n\t"
        "st -x, r22" "\n\t"
        "st -x, r21" "\n\t"
        "st -x, r20" "\n\t"

        "st -x, r19" "\n\t"
        "st -x, r18" "\n\t"
        "st -x, r17" "\n\t"
        "st -x, r16" "\n\t"


        /* restore context */
        "pop r17" "\n\t"
        "pop r16" "\n\t"
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
            r6 - left branch (Speckey left branch)
            r7 - left branch (Speckey right branch)

            r8 - right branch (Speckey left branch)
            r9 - right branch (Speckey right branch)

            r10 - round key / temp
            r11 - temp
            r12 - temp

            r13 - loop counter
        */


        /* save context */
        "push r6" "\n\t"
        "push r7" "\n\t"
        "push r8" "\n\t"
        "push r9" "\n\t"
        "push r10" "\n\t"
        "push r11" "\n\t"


        /* load block */
        "mov @r15+, r6" "\n\t"
        "mov @r15+, r7" "\n\t"
        "mov @r15+, r8" "\n\t"
        "mov @r15+, r9" "\n\t"


        /* initialize loop counter */
        "mov #8, r13" "\n\t"
        "step:" "\n\t"


        /* process left branch */
        ENC_ADD_ROUND_KEY(r6, r7, r10)
        ENC_A(r6, r7)


        ENC_ADD_ROUND_KEY(r6, r7, r10)
        ENC_A(r6, r7)


        ENC_ADD_ROUND_KEY(r6, r7, r10)
        ENC_A(r6, r7)


        /* process right branch */
        ENC_ADD_ROUND_KEY(r8, r9, r10)
        ENC_A(r8, r9)


        ENC_ADD_ROUND_KEY(r8, r9, r10)
        ENC_A(r8, r9)


        ENC_ADD_ROUND_KEY(r8, r9, r10)
        ENC_A(r8, r9)


        ENC_L(r6, r7, r8, r9, r10, r11, r12)


        /* loop end */
        "dec r13" "\n\t"
        "jne step" "\n\t"


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r6, r7, r10)
        ENC_ADD_WHITENING_KEY(r8, r9, r10)


        /* store block */
        "mov r6, -8(r15)" "\n\t"
        "mov r7, -6(r15)" "\n\t"
        "mov r8, -4(r15)" "\n\t"
        "mov r9, -2(r15)" "\n\t"


        /* restore context */
        "pop r11" "\n\t"
        "pop r10" "\n\t"
        "pop r9" "\n\t"
        "pop r8" "\n\t"
        "pop r7" "\n\t"
        "pop r6" "\n\t"
    );
}

/* MSP ASM implementation - end */

#endif
