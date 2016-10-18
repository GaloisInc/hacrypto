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

    uint32_t *left = (uint32_t *)block;
    uint32_t *right = (uint32_t *)block + 1;
    uint32_t *RoundKeys = (uint32_t *)roundKeys;


    /* post whitening */
    *left ^= READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[6 * NUMBER_OF_ROUNDS]);
    *right ^= READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[6 * NUMBER_OF_ROUNDS + 1]);


    for (i = NUMBER_OF_ROUNDS - 1; i >= 0 ; i--)
    {
        round_f_inverse(left, right, &RoundKeys[6 * i]);
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
            r2 - left branch
            r3 - right branch

            r4 - round key / temp
            r5 - temp

            r6 - halfword mask

            r7 - loop counter
        */


        /* save context */
        "stmdb sp!, {r2-r7}" "\n\t"


        SET_MASK(r6)


        /* set the pointer to round keys */
        "add r1, #200" "\n\t"


        /* load block */
        "ldm r0, {r2-r3}" "\n\t"


        /* post whitening */
        DEC_ADD_WHITENING_KEY(r2, r3, r4)


        /* initialize loop counter */
        "mov r7, 8" "\n\t"
        "step:" "\n\t"


        /* linear layer */
        DEC_L(r2, r3, r4)


        /* process right branch */
        DEC_A(r3, r4, r5, r6)
        DEC_ADD_ROUND_KEY(r3, r4)

        DEC_A(r3, r4, r5, r6)
        DEC_ADD_ROUND_KEY(r3, r4)

        DEC_A(r3, r4, r5, r6)
        DEC_ADD_ROUND_KEY(r3, r4)


        /* process left branch */
        DEC_A(r2, r4, r5, r6)
        DEC_ADD_ROUND_KEY(r2, r4)

        DEC_A(r2, r4, r5, r6)
        DEC_ADD_ROUND_KEY(r2, r4)

        DEC_A(r2, r4, r5, r6)
        DEC_ADD_ROUND_KEY(r2, r4)


        /* loop end */
        "subs r7, r7, #1" "\n\t"
        "bne step" "\n\t"


        /* store block */
        "stm r0, {r2-r3}" "\n\t"


        /* restore context */
        "ldmia sp!, {r2-r7}" "\n\t"
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
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "ldi r24, 196" "\n\t"
#else
        "ldi r24, 200" "\n\t"
#endif
        "add r30, r24" "\n\t"
        "adc r31, __zero_reg__" "\n\t" // r1


        /* load block */
        "ld r16, x+" "\n\t"
        "ld r17, x+" "\n\t"
        "ld r18, x+" "\n\t"
        "ld r19, x+" "\n\t"

        "ld r20, x+" "\n\t"
        "ld r21, x+" "\n\t"
        "ld r22, x+" "\n\t"
        "ld r23, x+" "\n\t"


        /* post whitening */
        DEC_ADD_WHITENING_KEY(r20, r21, r22, r23, r24)
        DEC_ADD_WHITENING_KEY(r16, r17, r18, r19, r24)


        /* initialize loop counter */
        "ldi r25, 8" "\n\t"
        "step:" "\n\t"


        DEC_L(r16, r17, r18, r19, r20, r21, r22, r23, r24)


        /* process right branch */
        DEC_A(r20, r21, r22, r23)
        DEC_ADD_ROUND_KEY(r20, r21, r22, r23, r24)


        DEC_A(r20, r21, r22, r23)
        DEC_ADD_ROUND_KEY(r20, r21, r22, r23, r24)


        DEC_A(r20, r21, r22, r23)
        DEC_ADD_ROUND_KEY(r20, r21, r22, r23, r24)


        /* process left branch */
        DEC_A(r16, r17, r18, r19)
        DEC_ADD_ROUND_KEY(r16, r17, r18, r19, r24)


        DEC_A(r16, r17, r18, r19)
        DEC_ADD_ROUND_KEY(r16, r17, r18, r19, r24)


        DEC_A(r16, r17, r18, r19)
        DEC_ADD_ROUND_KEY(r16, r17, r18, r19, r24)



        /* loop end */
        "dec r25" "\n\t"
        "breq end_step" "\n\t"
        "jmp step" "\n\t"
        "end_step:" "\n\t"


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


        /* set key pointer */
        "add #196, r14"   "\n\t"


        /* post whitening */
        DEC_ADD_WHITENING_KEY(r8, r9, r10)
        DEC_ADD_WHITENING_KEY(r6, r7, r10)


        /* initialize loop counter */
        "mov #8, r13" "\n\t"
        "step:" "\n\t"


        DEC_L(r6, r7, r8, r9, r10, r11, r12)


        /* process right branch */
        DEC_A(r8, r9)
        DEC_ADD_ROUND_KEY(r8, r9, r10)


        DEC_A(r8, r9)
        DEC_ADD_ROUND_KEY(r8, r9, r10)


        DEC_A(r8, r9)
        DEC_ADD_ROUND_KEY(r8, r9, r10)


        /* process left branch */
        DEC_A(r6, r7)
        DEC_ADD_ROUND_KEY(r6, r7, r10)


        DEC_A(r6, r7)
        DEC_ADD_ROUND_KEY(r6, r7, r10)


        DEC_A(r6, r7)
        DEC_ADD_ROUND_KEY(r6, r7, r10)


        /* loop end */
        "dec r13" "\n\t"
        "jne step" "\n\t"


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
