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

void Encrypt(uint8_t *block, uint8_t *roundKeys)
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


        /* load block */
        "ldm r0, {r2-r3}" "\n\t"


        /* initialize loop counter */
        "mov r9, 8" "\n\t"
        "step:" "\n\t"


        /* process left branch */
        /* load key */
        "ldm r1!, {r4}" "\n\t"
        /* xor key */
        "eor r2, r2, r4" "\n\t"
        /* speckey */
        "and r5, r8, r2" "\n\t"
        "and r6, r8, r2, lsr #16" "\n\t"

        "lsr r7, r5, #7" "\n\t"
        "orr r5, r7, r5, lsl #9" "\n\t"
        "add r5, r5, r6" "\n\t"

        "lsr r7, r6, #14" "\n\t"
        "orr r6, r7, r6, lsl #2" "\n\t"
        "eor r6, r5, r6" "\n\t"

        "and r5, r5, r8" "\n\t"
        "and r6, r6, r8" "\n\t"

        "orr r2, r5, r6, lsl #16" "\n\t"


        /* load key */
        "ldm r1!, {r4}" "\n\t"
        /* xor key */
        "eor r2, r2, r4" "\n\t"
        /* speckey */
        "and r5, r8, r2" "\n\t"
        "and r6, r8, r2, lsr #16" "\n\t"

        "lsr r7, r5, #7" "\n\t"
        "orr r5, r7, r5, lsl #9" "\n\t"
        "add r5, r5, r6" "\n\t"

        "lsr r7, r6, #14" "\n\t"
        "orr r6, r7, r6, lsl #2" "\n\t"
        "eor r6, r5, r6" "\n\t"

        "and r5, r5, r8" "\n\t"
        "and r6, r6, r8" "\n\t"

        "orr r2, r5, r6, lsl #16" "\n\t"

        /* load key */
        "ldm r1!, {r4}" "\n\t"
        /* xor key */
        "eor r2, r2, r4" "\n\t"
        /* speckey */
        "and r5, r8, r2" "\n\t"
        "and r6, r8, r2, lsr #16" "\n\t"

        "lsr r7, r5, #7" "\n\t"
        "orr r5, r7, r5, lsl #9" "\n\t"
        "add r5, r5, r6" "\n\t"

        "lsr r7, r6, #14" "\n\t"
        "orr r6, r7, r6, lsl #2" "\n\t"
        "eor r6, r5, r6" "\n\t"

        "and r5, r5, r8" "\n\t"
        "and r6, r6, r8" "\n\t"

        "orr r2, r5, r6, lsl #16" "\n\t"


        /* process right branch */
        /* load key */
        "ldm r1!, {r4}" "\n\t"
        /* xor key */
        "eor r3, r3, r4" "\n\t"
        /* speckey */
        "and r5, r8, r3" "\n\t"
        "and r6, r8, r3, lsr #16" "\n\t"

        "lsr r7, r5, #7" "\n\t"
        "orr r5, r7, r5, lsl #9" "\n\t"
        "add r5, r5, r6" "\n\t"

        "lsr r7, r6, #14" "\n\t"
        "orr r6, r7, r6, lsl #2" "\n\t"
        "eor r6, r5, r6" "\n\t"

        "and r5, r5, r8" "\n\t"
        "and r6, r6, r8" "\n\t"

        "orr r3, r5, r6, lsl #16" "\n\t"

        /* load key */
        "ldm r1!, {r4}" "\n\t"
        /* xor key */
        "eor r3, r3, r4" "\n\t"
        /* speckey */
        "and r5, r8, r3" "\n\t"
        "and r6, r8, r3, lsr #16" "\n\t"

        "lsr r7, r5, #7" "\n\t"
        "orr r5, r7, r5, lsl #9" "\n\t"
        "add r5, r5, r6" "\n\t"

        "lsr r7, r6, #14" "\n\t"
        "orr r6, r7, r6, lsl #2" "\n\t"
        "eor r6, r5, r6" "\n\t"

        "and r5, r5, r8" "\n\t"
        "and r6, r6, r8" "\n\t"

        "orr r3, r5, r6, lsl #16" "\n\t"

        /* load key */
        "ldm r1!, {r4}" "\n\t"
        /* xor key */
        "eor r3, r3, r4" "\n\t"
        /* speckey */
        "and r5, r8, r3" "\n\t"
        "and r6, r8, r3, lsr #16" "\n\t"

        "lsr r7, r5, #7" "\n\t"
        "orr r5, r7, r5, lsl #9" "\n\t"
        "add r5, r5, r6" "\n\t"

        "lsr r7, r6, #14" "\n\t"
        "orr r6, r7, r6, lsl #2" "\n\t"
        "eor r6, r5, r6" "\n\t"

        "and r5, r5, r8" "\n\t"
        "and r6, r6, r8" "\n\t"

        "orr r3, r5, r6, lsl #16" "\n\t"


        /* linear layer */
        "mov r7, r2" "\n\t"

        /* L */
        "eor r2, r2, r7, ror #8" "\n\t"
        "eor r2, r2, r7, ror #24" "\n\t"

        "eor r2, r2, r3" "\n\t"
        "mov r3, r7" "\n\t"


        /* loop end */
        "subs r9, r9, #1" "\n\t"
        "bne step" "\n\t"


        /* post whitening */
        "ldm r1!, {r4}" "\n\t"
        "eor r2, r2, r4" "\n\t"
        "ldm r1!, {r4}" "\n\t"
        "eor r3, r3, r4" "\n\t"


        /* store block */
        "stm r0, {r2-r3}" "\n\t"


        /* restore context */
        "ldmia sp!, {r2-r9}" "\n\t"
    );
}

/* ARM ASM implementation - end */

#elif defined(AVR)

/* AVR ASM implementation - begin */

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
        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r10, z+" "\n\t"
        "lpm r11, z+" "\n\t"
        "lpm r12, z+" "\n\t"
        "lpm r13, z+" "\n\t"
#else
        "ld r10, z+" "\n\t"
        "ld r11, z+" "\n\t"
        "ld r12, z+" "\n\t"
        "ld r13, z+" "\n\t"
#endif
        /* xor key */
        "eor r2, r10" "\n\t"
        "eor r3, r11" "\n\t"
        "eor r4, r12" "\n\t"
        "eor r5, r13" "\n\t"

        /* speckey */
        "eor r2, r3" "\n\t"
        "eor r3, r2" "\n\t"
        "eor r2, r3" "\n\t"
        "lsl r2" "\n\t"
        "rol r3" "\n\t"
        "adc r2, __zero_reg__" "\n\t" // r1

        "add r2, r4" "\n\t"
        "adc r3, r5" "\n\t"

        "lsl r4" "\n\t"
        "rol r5" "\n\t"
        "adc r4, __zero_reg__" "\n\t" // r1
        "lsl r4" "\n\t"
        "rol r5" "\n\t"
        "adc r4, __zero_reg__" "\n\t" // r1

        "eor r4, r2" "\n\t"
        "eor r5, r3" "\n\t"


        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r10, z+" "\n\t"
        "lpm r11, z+" "\n\t"
        "lpm r12, z+" "\n\t"
        "lpm r13, z+" "\n\t"
#else
        "ld r10, z+" "\n\t"
        "ld r11, z+" "\n\t"
        "ld r12, z+" "\n\t"
        "ld r13, z+" "\n\t"
#endif
        /* xor key */
        "eor r2, r10" "\n\t"
        "eor r3, r11" "\n\t"
        "eor r4, r12" "\n\t"
        "eor r5, r13" "\n\t"

        /* speckey */
        "eor r2, r3" "\n\t"
        "eor r3, r2" "\n\t"
        "eor r2, r3" "\n\t"
        "lsl r2" "\n\t"
        "rol r3" "\n\t"
        "adc r2, __zero_reg__" "\n\t" // r1

        "add r2, r4" "\n\t"
        "adc r3, r5" "\n\t"

        "lsl r4" "\n\t"
        "rol r5" "\n\t"
        "adc r4, __zero_reg__" "\n\t" // r1
        "lsl r4" "\n\t"
        "rol r5" "\n\t"
        "adc r4, __zero_reg__" "\n\t" // r1

        "eor r4, r2" "\n\t"
        "eor r5, r3" "\n\t"


        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r10, z+" "\n\t"
        "lpm r11, z+" "\n\t"
        "lpm r12, z+" "\n\t"
        "lpm r13, z+" "\n\t"
#else
        "ld r10, z+" "\n\t"
        "ld r11, z+" "\n\t"
        "ld r12, z+" "\n\t"
        "ld r13, z+" "\n\t"
#endif
        /* xor key */
        "eor r2, r10" "\n\t"
        "eor r3, r11" "\n\t"
        "eor r4, r12" "\n\t"
        "eor r5, r13" "\n\t"

        /* speckey */
        "eor r2, r3" "\n\t"
        "eor r3, r2" "\n\t"
        "eor r2, r3" "\n\t"
        "lsl r2" "\n\t"
        "rol r3" "\n\t"
        "adc r2, __zero_reg__" "\n\t" // r1

        "add r2, r4" "\n\t"
        "adc r3, r5" "\n\t"

        "lsl r4" "\n\t"
        "rol r5" "\n\t"
        "adc r4, __zero_reg__" "\n\t" // r1
        "lsl r4" "\n\t"
        "rol r5" "\n\t"
        "adc r4, __zero_reg__" "\n\t" // r1

        "eor r4, r2" "\n\t"
        "eor r5, r3" "\n\t"


        /* process right branch */
        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r10, z+" "\n\t"
        "lpm r11, z+" "\n\t"
        "lpm r12, z+" "\n\t"
        "lpm r13, z+" "\n\t"
#else
        "ld r10, z+" "\n\t"
        "ld r11, z+" "\n\t"
        "ld r12, z+" "\n\t"
        "ld r13, z+" "\n\t"
#endif
        /* xor key */
        "eor r6, r10" "\n\t"
        "eor r7, r11" "\n\t"
        "eor r8, r12" "\n\t"
        "eor r9, r13" "\n\t"

        /* speckey */
        "eor r6, r7" "\n\t"
        "eor r7, r6" "\n\t"
        "eor r6, r7" "\n\t"
        "lsl r6" "\n\t"
        "rol r7" "\n\t"
        "adc r6, __zero_reg__" "\n\t" // r1

        "add r6, r8" "\n\t"
        "adc r7, r9" "\n\t"

        "lsl r8" "\n\t"
        "rol r9" "\n\t"
        "adc r8, __zero_reg__" "\n\t" // r1
        "lsl r8" "\n\t"
        "rol r9" "\n\t"
        "adc r8, __zero_reg__" "\n\t" // r1

        "eor r8, r6" "\n\t"
        "eor r9, r7" "\n\t"


        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r10, z+" "\n\t"
        "lpm r11, z+" "\n\t"
        "lpm r12, z+" "\n\t"
        "lpm r13, z+" "\n\t"
#else
        "ld r10, z+" "\n\t"
        "ld r11, z+" "\n\t"
        "ld r12, z+" "\n\t"
        "ld r13, z+" "\n\t"
#endif
        /* xor key */
        "eor r6, r10" "\n\t"
        "eor r7, r11" "\n\t"
        "eor r8, r12" "\n\t"
        "eor r9, r13" "\n\t"

        /* speckey */
        "eor r6, r7" "\n\t"
        "eor r7, r6" "\n\t"
        "eor r6, r7" "\n\t"
        "lsl r6" "\n\t"
        "rol r7" "\n\t"
        "adc r6, __zero_reg__" "\n\t" // r1

        "add r6, r8" "\n\t"
        "adc r7, r9" "\n\t"

        "lsl r8" "\n\t"
        "rol r9" "\n\t"
        "adc r8, __zero_reg__" "\n\t" // r1
        "lsl r8" "\n\t"
        "rol r9" "\n\t"
        "adc r8, __zero_reg__" "\n\t" // r1

        "eor r8, r6" "\n\t"
        "eor r9, r7" "\n\t"


        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r10, z+" "\n\t"
        "lpm r11, z+" "\n\t"
        "lpm r12, z+" "\n\t"
        "lpm r13, z+" "\n\t"
#else
        "ld r10, z+" "\n\t"
        "ld r11, z+" "\n\t"
        "ld r12, z+" "\n\t"
        "ld r13, z+" "\n\t"
#endif
        /* xor key */
        "eor r6, r10" "\n\t"
        "eor r7, r11" "\n\t"
        "eor r8, r12" "\n\t"
        "eor r9, r13" "\n\t"

        /* speckey */
        "eor r6, r7" "\n\t"
        "eor r7, r6" "\n\t"
        "eor r6, r7" "\n\t"
        "lsl r6" "\n\t"
        "rol r7" "\n\t"
        "adc r6, __zero_reg__" "\n\t" // r1

        "add r6, r8" "\n\t"
        "adc r7, r9" "\n\t"

        "lsl r8" "\n\t"
        "rol r9" "\n\t"
        "adc r8, __zero_reg__" "\n\t" // r1
        "lsl r8" "\n\t"
        "rol r9" "\n\t"
        "adc r8, __zero_reg__" "\n\t" // r1

        "eor r8, r6" "\n\t"
        "eor r9, r7" "\n\t"


        /* linear layer */
        "mov r10, r2" "\n\t"
        "mov r11, r3" "\n\t"
        "mov r12, r4" "\n\t"
        "mov r13, r5" "\n\t"


        /* L */
        "eor r2, r11" "\n\t"
        "eor r3, r12" "\n\t"
        "eor r4, r13" "\n\t"
        "eor r5, r10" "\n\t"

        "eor r2, r13" "\n\t"
        "eor r3, r10" "\n\t"
        "eor r4, r11" "\n\t"
        "eor r5, r12" "\n\t"

        "eor r2, r6" "\n\t"
        "eor r3, r7" "\n\t"
        "eor r4, r8" "\n\t"
        "eor r5, r9" "\n\t"


        "mov r6, r10" "\n\t"
        "mov r7, r11" "\n\t"
        "mov r8, r12" "\n\t"
        "mov r9, r13" "\n\t"


        /* loop end */
        "dec r18" "\n\t"
        "breq end_step" "\n\t"
        "jmp step" "\n\t"
        "end_step:" "\n\t"


        /* post whitening */
        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r10, z+" "\n\t"
        "lpm r11, z+" "\n\t"
        "lpm r12, z+" "\n\t"
        "lpm r13, z+" "\n\t"
#else
        "ld r10, z+" "\n\t"
        "ld r11, z+" "\n\t"
        "ld r12, z+" "\n\t"
        "ld r13, z+" "\n\t"
#endif
        /* xor key */
        "eor r2, r10" "\n\t"
        "eor r3, r11" "\n\t"
        "eor r4, r12" "\n\t"
        "eor r5, r13" "\n\t"

        /* load key */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "lpm r10, z+" "\n\t"
        "lpm r11, z+" "\n\t"
        "lpm r12, z+" "\n\t"
        "lpm r13, z+" "\n\t"
#else
        "ld r10, z+" "\n\t"
        "ld r11, z+" "\n\t"
        "ld r12, z+" "\n\t"
        "ld r13, z+" "\n\t"
#endif
        /* xor key */
        "eor r6, r10" "\n\t"
        "eor r7, r11" "\n\t"
        "eor r8, r12" "\n\t"
        "eor r9, r13" "\n\t"


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

/* MSP ASM implementation - begin */

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


        /* initialize loop counter */
        "mov #8, r11" "\n\t"
        "step:" "\n\t"


        /* process left branch */
        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        /* xor key */
        "xor r8, r4" "\n\t"
        "xor r9, r5" "\n\t"

        /* speckey */
        "swpb r4" "\n\t"
        "rla r4" "\n\t"
        "adc r4" "\n\t"

        "add r5, r4" "\n\t"

        "rla r5" "\n\t"
        "adc r5" "\n\t"
        "rla r5" "\n\t"
        "adc r5" "\n\t"

        "xor r4, r5" "\n\t"


        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        /* xor key */
        "xor r8, r4" "\n\t"
        "xor r9, r5" "\n\t"

        /* speckey */
        "swpb r4" "\n\t"
        "rla r4" "\n\t"
        "adc r4" "\n\t"

        "add r5, r4" "\n\t"

        "rla r5" "\n\t"
        "adc r5" "\n\t"
        "rla r5" "\n\t"
        "adc r5" "\n\t"

        "xor r4, r5" "\n\t"


        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        /* xor key */
        "xor r8, r4" "\n\t"
        "xor r9, r5" "\n\t"

        /* speckey */
        "swpb r4" "\n\t"
        "rla r4" "\n\t"
        "adc r4" "\n\t"

        "add r5, r4" "\n\t"

        "rla r5" "\n\t"
        "adc r5" "\n\t"
        "rla r5" "\n\t"
        "adc r5" "\n\t"

        "xor r4, r5" "\n\t"


        /* process right branch */
        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        /* xor key */
        "xor r8, r6" "\n\t"
        "xor r9, r7" "\n\t"

        /* speckey */
        "swpb r6" "\n\t"
        "rla r6" "\n\t"
        "adc r6" "\n\t"

        "add r7, r6" "\n\t"

        "rla r7" "\n\t"
        "adc r7" "\n\t"
        "rla r7" "\n\t"
        "adc r7" "\n\t"

        "xor r6, r7" "\n\t"


        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        /* xor key */
        "xor r8, r6" "\n\t"
        "xor r9, r7" "\n\t"

        /* speckey */
        "swpb r6" "\n\t"
        "rla r6" "\n\t"
        "adc r6" "\n\t"

        "add r7, r6" "\n\t"

        "rla r7" "\n\t"
        "adc r7" "\n\t"
        "rla r7" "\n\t"
        "adc r7" "\n\t"

        "xor r6, r7" "\n\t"


        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        /* xor key */
        "xor r8, r6" "\n\t"
        "xor r9, r7" "\n\t"

        /* speckey */
        "swpb r6" "\n\t"
        "rla r6" "\n\t"
        "adc r6" "\n\t"

        "add r7, r6" "\n\t"

        "rla r7" "\n\t"
        "adc r7" "\n\t"
        "rla r7" "\n\t"
        "adc r7" "\n\t"

        "xor r6, r7" "\n\t"


        /* linear layer */
        "mov r4, r8" "\n\t"
        "mov r5, r9" "\n\t"


        /* L */
        "mov r4, r10" "\n\t"
        "xor r5, r10" "\n\t"
        "swpb r10" "\n\t"
        "xor r10, r4" "\n\t"
        "xor r10, r5" "\n\t"

        "xor r6, r4" "\n\t"
        "xor r7, r5" "\n\t"


        "mov r8, r6" "\n\t"
        "mov r9, r7" "\n\t"


        /* loop end */
        "dec r11" "\n\t"
        "jne step" "\n\t"


        /* post whitening */
        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        /* xor key */
        "xor r8, r4" "\n\t"
        "xor r9, r5" "\n\t"

        /* load key */
        "mov @r14+, r8" "\n\t"
        "mov @r14+, r9" "\n\t"
        /* xor key */
        "xor r8, r6" "\n\t"
        "xor r9, r7" "\n\t"


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
