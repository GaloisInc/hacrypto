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

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
/*
References:
1) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABHGAJI.html
2) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABCAEDD.html
3) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABIJDIC.html
4) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABBFHCJ.html
5) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/CIHFDDHB.html
6) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0337h/CHDIJAFG.html
7) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABJFJBD.html
8) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABBJGAG.html
9) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABJCCDH.html
10) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABEHFEF.html
11) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABFFEJF.html
12) http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0552a/BABBFHCJ.html
*/

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
        */


        /* save context */
        "stmdb sp!, {r2-r9}" "\n\t"


        /* set halfword mask */
        "ldr r8, =#0x0000ffff" "\n\t"


        /* set the pointer to round keys */
        "add r1, #200" "\n\t"


        /* load block */
        "ldm r0, {r2-r3}" "\n\t"


        /* post whitening */
        "ldmdb r1!, {r4}" "\n\t"
        "eor r3, r3, r4" "\n\t"
        "ldmdb r1!, {r4}" "\n\t"
        "eor r2, r2, r4" "\n\t"


        /* initialize loop counter */
        "mov r9, 8" "\n\t"
        "step:" "\n\t"


        /* linear layer */
        "mov r7, r3" "\n\t"

        /* L */
        "eor r3, r3, r7, ror #8" "\n\t"
        "eor r3, r3, r7, ror #24" "\n\t"

        "eor r3, r3, r2" "\n\t"
        "mov r2, r7" "\n\t"


        /* process right branch */
        /* speckey inverse */
        "and r5, r8, r3" "\n\t"
        "and r6, r8, r3, lsr #16" "\n\t"

        "eor r6, r5, r6" "\n\t"
        "lsr r7, r6, #2" "\n\t"
        "orr r6, r7, r6, lsl #14" "\n\t"
        "and r6, r6, r8" "\n\t"

        "sub r5, r5, r6" "\n\t"
        "and r5, r5, r8" "\n\t"
        "lsr r7, r5, #9" "\n\t"
        "orr r5, r7, r5, lsl #7" "\n\t"
        "and r5, r5, r8" "\n\t"

        "orr r3, r5, r6, lsl #16" "\n\t"
        /* load key */
        "ldmdb r1!, {r4}" "\n\t"
        /* xor key */
        "eor r3, r3, r4" "\n\t"

        /* speckey inverse */
        "and r5, r8, r3" "\n\t"
        "and r6, r8, r3, lsr #16" "\n\t"

        "eor r6, r5, r6" "\n\t"
        "lsr r7, r6, #2" "\n\t"
        "orr r6, r7, r6, lsl #14" "\n\t"
        "and r6, r6, r8" "\n\t"

        "sub r5, r5, r6" "\n\t"
        "and r5, r5, r8" "\n\t"
        "lsr r7, r5, #9" "\n\t"
        "orr r5, r7, r5, lsl #7" "\n\t"
        "and r5, r5, r8" "\n\t"

        "orr r3, r5, r6, lsl #16" "\n\t"
        /* load key */
        "ldmdb r1!, {r4}" "\n\t"
        /* xor key */
        "eor r3, r3, r4" "\n\t"

        /* speckey inverse */
        "and r5, r8, r3" "\n\t"
        "and r6, r8, r3, lsr #16" "\n\t"

        "eor r6, r5, r6" "\n\t"
        "lsr r7, r6, #2" "\n\t"
        "orr r6, r7, r6, lsl #14" "\n\t"
        "and r6, r6, r8" "\n\t"

        "sub r5, r5, r6" "\n\t"
        "and r5, r5, r8" "\n\t"
        "lsr r7, r5, #9" "\n\t"
        "orr r5, r7, r5, lsl #7" "\n\t"
        "and r5, r5, r8" "\n\t"

        "orr r3, r5, r6, lsl #16" "\n\t"
        /* load key */
        "ldmdb r1!, {r4}" "\n\t"
        /* xor key */
        "eor r3, r3, r4" "\n\t"


        /* process left branch */
        /* speckey inverse */
        "and r5, r8, r2" "\n\t"
        "and r6, r8, r2, lsr #16" "\n\t"

        "eor r6, r5, r6" "\n\t"
        "lsr r7, r6, #2" "\n\t"
        "orr r6, r7, r6, lsl #14" "\n\t"
        "and r6, r6, r8" "\n\t"

        "sub r5, r5, r6" "\n\t"
        "and r5, r5, r8" "\n\t"
        "lsr r7, r5, #9" "\n\t"
        "orr r5, r7, r5, lsl #7" "\n\t"
        "and r5, r5, r8" "\n\t"

        "orr r2, r5, r6, lsl #16" "\n\t"
        /* load key */
        "ldmdb r1!, {r4}" "\n\t"
        /* xor key */
        "eor r2, r2, r4" "\n\t"

        /* speckey inverse */
        "and r5, r8, r2" "\n\t"
        "and r6, r8, r2, lsr #16" "\n\t"

        "eor r6, r5, r6" "\n\t"
        "lsr r7, r6, #2" "\n\t"
        "orr r6, r7, r6, lsl #14" "\n\t"
        "and r6, r6, r8" "\n\t"

        "sub r5, r5, r6" "\n\t"
        "and r5, r5, r8" "\n\t"
        "lsr r7, r5, #9" "\n\t"
        "orr r5, r7, r5, lsl #7" "\n\t"
        "and r5, r5, r8" "\n\t"

        "orr r2, r5, r6, lsl #16" "\n\t"
        /* load key */
        "ldmdb r1!, {r4}" "\n\t"
        /* xor key */
        "eor r2, r2, r4" "\n\t"

        /* speckey inverse */
        "and r5, r8, r2" "\n\t"
        "and r6, r8, r2, lsr #16" "\n\t"

        "eor r6, r5, r6" "\n\t"
        "lsr r7, r6, #2" "\n\t"
        "orr r6, r7, r6, lsl #14" "\n\t"
        "and r6, r6, r8" "\n\t"

        "sub r5, r5, r6" "\n\t"
        "and r5, r5, r8" "\n\t"
        "lsr r7, r5, #9" "\n\t"
        "orr r5, r7, r5, lsl #7" "\n\t"
        "and r5, r5, r8" "\n\t"

        "orr r2, r5, r6, lsl #16" "\n\t"
        /* load key */
        "ldmdb r1!, {r4}" "\n\t"
        /* xor key */
        "eor r2, r2, r4" "\n\t"


        /* loop end */
        "subs r9, r9, #1" "\n\t"
        "bne step" "\n\t"


        /* store block */
        "stm r0, {r2-r3}" "\n\t"


        /* restore context */
        "ldmia sp!, {r2-r9}" "\n\t"
    );
}

/* ARM ASM implementation - end */

#elif defined(AVR)

/* AVR ASM implementation - begin */

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
            r2 - left branch (Speckey left branch)
            r3 - left branch (Speckey left branch)
            r4 - left branch (Speckey right branch)
            r5 - left branch (Speckey right branch)

            r6 - right branch (Speckey left branch)
            r7 - right branch (Speckey left branch)
            r8 - right branch (Speckey right branch)
            r9 - right branch (Speckey right branch)

            r14 - round key / temp
            r15 - round key / temp
            r16 - round key / temp
            r17 - round key / temp

            r18 - loop counter
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

        "push r14" "\n\t"
        "push r15" "\n\t"
        "push r16" "\n\t"
        "push r17" "\n\t"
        "push r18" "\n\t"

        "push r27" "\n\t"
        "push r26" "\n\t"

        "push r31" "\n\t"
        "push r30" "\n\t"


        /* set block pointer: X (r27, r26) */
        "movw r26, r24" "\n\t"
        /* set key pointer: Z (r31, r30) */
        "movw r30, r22" "\n\t"
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "ldi r17, 196" "\n\t"
#else
        "ldi r17, 200" "\n\t"
#endif
        "add r30, r17" "\n\t"
        "adc r31, __zero_reg__" "\n\t" // r1


        /* load block */
        "ld r2, x+" "\n\t"
        "ld r3, x+" "\n\t"
        "ld r4, x+" "\n\t"
        "ld r5, x+" "\n\t"

        "ld r6, x+" "\n\t"
        "ld r7, x+" "\n\t"
        "ld r8, x+" "\n\t"
        "ld r9, x+" "\n\t"


        /* post whitening */
        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r14, z+" "\n\t"
        "lpm r15, z+" "\n\t"
        "lpm r16, z+" "\n\t"
        "lpm r17, z+" "\n\t"
        "sbiw r30, 8" "\n\t"
#else
        "ld r17, -z" "\n\t"
        "ld r16, -z" "\n\t"
        "ld r15, -z" "\n\t"
        "ld r14, -z" "\n\t"
#endif
        /* xor key */
        "eor r9, r17" "\n\t"
        "eor r8, r16" "\n\t"
        "eor r7, r15" "\n\t"
        "eor r6, r14" "\n\t"

        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r14, z+" "\n\t"
        "lpm r15, z+" "\n\t"
        "lpm r16, z+" "\n\t"
        "lpm r17, z+" "\n\t"
        "sbiw r30, 8" "\n\t"
#else
        "ld r17, -z" "\n\t"
        "ld r16, -z" "\n\t"
        "ld r15, -z" "\n\t"
        "ld r14, -z" "\n\t"
#endif
        /* xor key */
        "eor r5, r17" "\n\t"
        "eor r4, r16" "\n\t"
        "eor r3, r15" "\n\t"
        "eor r2, r14" "\n\t"


        /* initialize loop counter */
        "ldi r18, 8" "\n\t"
        "step:" "\n\t"


        /* linear layer */
        "mov r14, r6" "\n\t"
        "mov r15, r7" "\n\t"
        "mov r16, r8" "\n\t"
        "mov r17, r9" "\n\t"


        /* L */
        "eor r6, r15" "\n\t"
        "eor r7, r16" "\n\t"
        "eor r8, r17" "\n\t"
        "eor r9, r14" "\n\t"

        "eor r6, r17" "\n\t"
        "eor r7, r14" "\n\t"
        "eor r8, r15" "\n\t"
        "eor r9, r16" "\n\t"

        "eor r6, r2" "\n\t"
        "eor r7, r3" "\n\t"
        "eor r8, r4" "\n\t"
        "eor r9, r5" "\n\t"


        "mov r2, r14" "\n\t"
        "mov r3, r15" "\n\t"
        "mov r4, r16" "\n\t"
        "mov r5, r17" "\n\t"


        /* process right branch */
        /* speckey */
        "eor r8, r6" "\n\t"
        "eor r9, r7" "\n\t"

        "bst r8, 0" "\n\t"
        "ror r9" "\n\t"
        "ror r8" "\n\t"
        "bld r9, 7" "\n\t"
        "bst r8, 0" "\n\t"
        "ror r9" "\n\t"
        "ror r8" "\n\t"
        "bld r9, 7" "\n\t"

        "sub r6, r8" "\n\t"
        "sbc r7, r9" "\n\t"

        "eor r6, r7" "\n\t"
        "eor r7, r6" "\n\t"
        "eor r6, r7" "\n\t"
        "bst r7, 0" "\n\t"
        "ror r6" "\n\t"
        "ror r7" "\n\t"
        "bld r6, 7" "\n\t"

        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r14, z+" "\n\t"
        "lpm r15, z+" "\n\t"
        "lpm r16, z+" "\n\t"
        "lpm r17, z+" "\n\t"
        "sbiw r30, 8" "\n\t"
#else
        "ld r17, -z" "\n\t"
        "ld r16, -z" "\n\t"
        "ld r15, -z" "\n\t"
        "ld r14, -z" "\n\t"
#endif
        /* xor key */
        "eor r9, r17" "\n\t"
        "eor r8, r16" "\n\t"
        "eor r7, r15" "\n\t"
        "eor r6, r14" "\n\t"


        /* speckey */
        "eor r8, r6" "\n\t"
        "eor r9, r7" "\n\t"

        "bst r8, 0" "\n\t"
        "ror r9" "\n\t"
        "ror r8" "\n\t"
        "bld r9, 7" "\n\t"
        "bst r8, 0" "\n\t"
        "ror r9" "\n\t"
        "ror r8" "\n\t"
        "bld r9, 7" "\n\t"

        "sub r6, r8" "\n\t"
        "sbc r7, r9" "\n\t"

        "eor r6, r7" "\n\t"
        "eor r7, r6" "\n\t"
        "eor r6, r7" "\n\t"
        "bst r7, 0" "\n\t"
        "ror r6" "\n\t"
        "ror r7" "\n\t"
        "bld r6, 7" "\n\t"

        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r14, z+" "\n\t"
        "lpm r15, z+" "\n\t"
        "lpm r16, z+" "\n\t"
        "lpm r17, z+" "\n\t"
        "sbiw r30, 8" "\n\t"
#else
        "ld r17, -z" "\n\t"
        "ld r16, -z" "\n\t"
        "ld r15, -z" "\n\t"
        "ld r14, -z" "\n\t"
#endif
        /* xor key */
        "eor r9, r17" "\n\t"
        "eor r8, r16" "\n\t"
        "eor r7, r15" "\n\t"
        "eor r6, r14" "\n\t"


        /* speckey */
        "eor r8, r6" "\n\t"
        "eor r9, r7" "\n\t"

        "bst r8, 0" "\n\t"
        "ror r9" "\n\t"
        "ror r8" "\n\t"
        "bld r9, 7" "\n\t"
        "bst r8, 0" "\n\t"
        "ror r9" "\n\t"
        "ror r8" "\n\t"
        "bld r9, 7" "\n\t"

        "sub r6, r8" "\n\t"
        "sbc r7, r9" "\n\t"

        "eor r6, r7" "\n\t"
        "eor r7, r6" "\n\t"
        "eor r6, r7" "\n\t"
        "bst r7, 0" "\n\t"
        "ror r6" "\n\t"
        "ror r7" "\n\t"
        "bld r6, 7" "\n\t"

        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r14, z+" "\n\t"
        "lpm r15, z+" "\n\t"
        "lpm r16, z+" "\n\t"
        "lpm r17, z+" "\n\t"
        "sbiw r30, 8" "\n\t"
#else
        "ld r17, -z" "\n\t"
        "ld r16, -z" "\n\t"
        "ld r15, -z" "\n\t"
        "ld r14, -z" "\n\t"
#endif
        /* xor key */
        "eor r9, r17" "\n\t"
        "eor r8, r16" "\n\t"
        "eor r7, r15" "\n\t"
        "eor r6, r14" "\n\t"


        /* process left branch */
        /* speckey */
        "eor r4, r2" "\n\t"
        "eor r5, r3" "\n\t"

        "bst r4, 0" "\n\t"
        "ror r5" "\n\t"
        "ror r4" "\n\t"
        "bld r5, 7" "\n\t"
        "bst r4, 0" "\n\t"
        "ror r5" "\n\t"
        "ror r4" "\n\t"
        "bld r5, 7" "\n\t"

        "sub r2, r4" "\n\t"
        "sbc r3, r5" "\n\t"

        "eor r2, r3" "\n\t"
        "eor r3, r2" "\n\t"
        "eor r2, r3" "\n\t"
        "bst r3, 0" "\n\t"
        "ror r2" "\n\t"
        "ror r3" "\n\t"
        "bld r2, 7" "\n\t"

        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r14, z+" "\n\t"
        "lpm r15, z+" "\n\t"
        "lpm r16, z+" "\n\t"
        "lpm r17, z+" "\n\t"
        "sbiw r30, 8" "\n\t"
#else
        "ld r17, -z" "\n\t"
        "ld r16, -z" "\n\t"
        "ld r15, -z" "\n\t"
        "ld r14, -z" "\n\t"
#endif
        /* xor key */
        "eor r5, r17" "\n\t"
        "eor r4, r16" "\n\t"
        "eor r3, r15" "\n\t"
        "eor r2, r14" "\n\t"


        /* speckey */
        "eor r4, r2" "\n\t"
        "eor r5, r3" "\n\t"

        "bst r4, 0" "\n\t"
        "ror r5" "\n\t"
        "ror r4" "\n\t"
        "bld r5, 7" "\n\t"
        "bst r4, 0" "\n\t"
        "ror r5" "\n\t"
        "ror r4" "\n\t"
        "bld r5, 7" "\n\t"

        "sub r2, r4" "\n\t"
        "sbc r3, r5" "\n\t"

        "eor r2, r3" "\n\t"
        "eor r3, r2" "\n\t"
        "eor r2, r3" "\n\t"
        "bst r3, 0" "\n\t"
        "ror r2" "\n\t"
        "ror r3" "\n\t"
        "bld r2, 7" "\n\t"

        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r14, z+" "\n\t"
        "lpm r15, z+" "\n\t"
        "lpm r16, z+" "\n\t"
        "lpm r17, z+" "\n\t"
        "sbiw r30, 8" "\n\t"
#else
        "ld r17, -z" "\n\t"
        "ld r16, -z" "\n\t"
        "ld r15, -z" "\n\t"
        "ld r14, -z" "\n\t"
#endif
        /* xor key */
        "eor r5, r17" "\n\t"
        "eor r4, r16" "\n\t"
        "eor r3, r15" "\n\t"
        "eor r2, r14" "\n\t"


        /* speckey */
        "eor r4, r2" "\n\t"
        "eor r5, r3" "\n\t"

        "bst r4, 0" "\n\t"
        "ror r5" "\n\t"
        "ror r4" "\n\t"
        "bld r5, 7" "\n\t"
        "bst r4, 0" "\n\t"
        "ror r5" "\n\t"
        "ror r4" "\n\t"
        "bld r5, 7" "\n\t"

        "sub r2, r4" "\n\t"
        "sbc r3, r5" "\n\t"

        "eor r2, r3" "\n\t"
        "eor r3, r2" "\n\t"
        "eor r2, r3" "\n\t"
        "bst r3, 0" "\n\t"
        "ror r2" "\n\t"
        "ror r3" "\n\t"
        "bld r2, 7" "\n\t"

        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r14, z+" "\n\t"
        "lpm r15, z+" "\n\t"
        "lpm r16, z+" "\n\t"
        "lpm r17, z+" "\n\t"
        "sbiw r30, 8" "\n\t"
#else
        "ld r17, -z" "\n\t"
        "ld r16, -z" "\n\t"
        "ld r15, -z" "\n\t"
        "ld r14, -z" "\n\t"
#endif
        /* xor key */
        "eor r5, r17" "\n\t"
        "eor r4, r16" "\n\t"
        "eor r3, r15" "\n\t"
        "eor r2, r14" "\n\t"


        /* loop end */
        "dec r18" "\n\t"
        "breq end_step" "\n\t"
        "jmp step" "\n\t"
        "end_step:" "\n\t"


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

        "pop r18" "\n\t"
        "pop r17" "\n\t"
        "pop r16" "\n\t"
        "pop r15" "\n\t"
        "pop r14" "\n\t"

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

/* MSP ASM implementation - begin */

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
            r4 - left branch (Speckey left branch)
            r5 - left branch (Speckey right branch)

            r6 - right branch (Speckey left branch)
            r7 - right branch (Speckey right branch)

            r8 - round key / temp
            r9 - round key / temp

            r10 - temp

            r11 - loop counter
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


        /* load block */
        "mov @r15+, r4" "\n\t"
        "mov @r15+, r5" "\n\t"
        "mov @r15+, r6" "\n\t"
        "mov @r15+, r7" "\n\t"


        /* set key pointer */
        "add #196, r14"   "\n\t"


        /* post whitening */
        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        "sub #8, r14" "\n\t"
        /* xor key */
        "xor r8, r6" "\n\t"
        "xor r9, r7" "\n\t"

        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        "sub #8, r14" "\n\t"
        /* xor key */
        "xor r8, r4" "\n\t"
        "xor r9, r5" "\n\t"


        /* initialize loop counter */
        "mov #8, r11" "\n\t"
        "step:" "\n\t"


        /* linear layer */
        "mov r6, r8" "\n\t"
        "mov r7, r9" "\n\t"

        /* L */
        "mov r6, r10" "\n\t"
        "xor r7, r10" "\n\t"
        "swpb r10" "\n\t"
        "xor r10, r6" "\n\t"
        "xor r10, r7" "\n\t"

        "xor r4, r6" "\n\t"
        "xor r5, r7" "\n\t"


        "mov r8, r4" "\n\t"
        "mov r9, r5" "\n\t"


        /* process right branch */
        /* speckey */
        "xor r6, r7" "\n\t"

        "bit #1, r7" "\n\t"
        "rrc r7" "\n\t"
        "bit #1, r7" "\n\t"
        "rrc r7" "\n\t"

        "sub r7, r6" "\n\t"

        "swpb r6" "\n\t"
        "bit #1, r6" "\n\t"
        "rrc r6" "\n\t"

        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        "sub #8, r14" "\n\t"
        /* xor key */
        "xor r8, r6" "\n\t"
        "xor r9, r7" "\n\t"


        /* speckey */
        "xor r6, r7" "\n\t"

        "bit #1, r7" "\n\t"
        "rrc r7" "\n\t"
        "bit #1, r7" "\n\t"
        "rrc r7" "\n\t"

        "sub r7, r6" "\n\t"

        "swpb r6" "\n\t"
        "bit #1, r6" "\n\t"
        "rrc r6" "\n\t"

        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        "sub #8, r14" "\n\t"
        /* xor key */
        "xor r8, r6" "\n\t"
        "xor r9, r7" "\n\t"


        /* speckey */
        "xor r6, r7" "\n\t"

        "bit #1, r7" "\n\t"
        "rrc r7" "\n\t"
        "bit #1, r7" "\n\t"
        "rrc r7" "\n\t"

        "sub r7, r6" "\n\t"

        "swpb r6" "\n\t"
        "bit #1, r6" "\n\t"
        "rrc r6" "\n\t"

        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        "sub #8, r14" "\n\t"
        /* xor key */
        "xor r8, r6" "\n\t"
        "xor r9, r7" "\n\t"


        /* process left branch */
        /* speckey */
        "xor r4, r5" "\n\t"

        "bit #1, r5" "\n\t"
        "rrc r5" "\n\t"
        "bit #1, r5" "\n\t"
        "rrc r5" "\n\t"

        "sub r5, r4" "\n\t"

        "swpb r4" "\n\t"
        "bit #1, r4" "\n\t"
        "rrc r4" "\n\t"

        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        "sub #8, r14" "\n\t"
        /* xor key */
        "xor r8, r4" "\n\t"
        "xor r9, r5" "\n\t"


        /* speckey */
        "xor r4, r5" "\n\t"

        "bit #1, r5" "\n\t"
        "rrc r5" "\n\t"
        "bit #1, r5" "\n\t"
        "rrc r5" "\n\t"

        "sub r5, r4" "\n\t"

        "swpb r4" "\n\t"
        "bit #1, r4" "\n\t"
        "rrc r4" "\n\t"

        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        "sub #8, r14" "\n\t"
        /* xor key */
        "xor r8, r4" "\n\t"
        "xor r9, r5" "\n\t"


        /* speckey */
        "xor r4, r5" "\n\t"

        "bit #1, r5" "\n\t"
        "rrc r5" "\n\t"
        "bit #1, r5" "\n\t"
        "rrc r5" "\n\t"

        "sub r5, r4" "\n\t"

        "swpb r4" "\n\t"
        "bit #1, r4" "\n\t"
        "rrc r4" "\n\t"

        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        "sub #8, r14" "\n\t"
        /* xor key */
        "xor r8, r4" "\n\t"
        "xor r9, r5" "\n\t"


        /* loop end */
        "dec r11" "\n\t"
        "jne step" "\n\t"


        /* store block */
        "mov r4, -8(r15)" "\n\t"
        "mov r5, -6(r15)" "\n\t"
        "mov r6, -4(r15)" "\n\t"
        "mov r7, -2(r15)" "\n\t"


        /* restore context */
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
