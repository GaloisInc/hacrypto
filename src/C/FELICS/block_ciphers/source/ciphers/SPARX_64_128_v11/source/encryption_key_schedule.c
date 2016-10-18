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

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r0 - *key
            r1 - *roundKeys
        */

        /*
            r2 - round key 0
            r3 - round key 1
            r4 - round key 2 / temp
            r5 - round key 3
            r6 - round key 0/3 left branch
            r7 - round key 0/3 right branch
            r8 - round key 2 left branch
            r9 - round key 2 right branch
            r10 - temp
            r11 - halfword mask
            r12 - loop counter
        */


        /* save context */
        "stmdb sp!, {r2-r12}" "\n\t"


        /* set halfword mask */
        "ldr r11, =#0x0000ffff" "\n\t"


        /* load key */
        "ldm r0, {r2-r5}" "\n\t"


        /* store round keys */
        "stm r1!, {r2-r4}" "\n\t"


        /* initialize loop counter */
        "mov r12, #1" "\n\t"
        "step:" "\n\t"


        "and r6, r11, r5" "\n\t"
        "and r7, r11, r5, lsr #16" "\n\t"
        "add r7, r12" "\n\t"
        "and r7, r7, r11" "\n\t"
        "orr r10, r6, r7, lsl #16" "\n\t"


        /* key 3 */
        "mov r5, r4" "\n\t"


        /* speckey */
        "and r6, r11, r2" "\n\t"
        "and r7, r11, r2, lsr #16" "\n\t"

        "lsr r4, r6, #7" "\n\t"
        "orr r6, r4, r6, lsl #9" "\n\t"
        "add r6, r6, r7" "\n\t"

        "lsr r4, r7, #14" "\n\t"
        "orr r7, r4, r7, lsl #2" "\n\t"
        "eor r7, r6, r7" "\n\t"

        "and r6, r6, r11" "\n\t"
        "and r7, r7, r11" "\n\t"


        "and r8, r11, r3" "\n\t"
        "and r9, r11, r3, lsr #16" "\n\t"

        "add r8, r8, r6" "\n\t"
        "and r8, r11, r8" "\n\t"

        "add r9, r9, r7" "\n\t"
        "and r9, r11, r9" "\n\t"

        /* key 2 */
        "orr r4, r8, r9, lsl #16" "\n\t"


        /* key 1 */
        "orr r3, r6, r7, lsl #16" "\n\t"


        /* key 0 */
        "mov r2, r10" "\n\t"


        /* store round keys */
        "stm r1!, {r2-r4}" "\n\t"


        /* loop end */
        "add r12, r12, #1" "\n\t"
        "cmp r12, #16" "\n\t"
        "bne step" "\n\t"


        /* post whitening keys */
        /* speckey */
        "and r6, r11, r2" "\n\t"
        "and r7, r11, r2, lsr #16" "\n\t"

        "lsr r4, r6, #7" "\n\t"
        "orr r6, r4, r6, lsl #9" "\n\t"
        "add r6, r6, r7" "\n\t"

        "lsr r4, r7, #14" "\n\t"
        "orr r7, r4, r7, lsl #2" "\n\t"
        "eor r7, r6, r7" "\n\t"

        "and r6, r6, r11" "\n\t"
        "and r7, r7, r11" "\n\t"

        /* key 1 */
        "orr r3, r6, r7, lsl #16" "\n\t"


        /* key 0 */
        "and r6, r11, r5" "\n\t"
        "and r7, r11, r5, lsr #16" "\n\t"
        "add r7, r12" "\n\t"
        "and r7, r7, r11" "\n\t"
        "orr r2, r6, r7, lsl #16" "\n\t"


        /* store round keys */
        "stm r1!, {r2-r3}" "\n\t"


        /* restore context */
        "ldmia sp!, {r2-r12}" "\n\t"
    );
}

#elif defined(AVR)

void /*__attribute__((naked))*/ RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r25, r24 - *block
            r23, r22 - *roundKeys
        */

        /*
            r2 - round key 0
            r3 - round key 0
            r4 - round key 0
            r5 - round key 0

            r6 - round key 1
            r7 - round key 1
            r8 - round key 1
            r9 - round key 1

            r10 - round key 2
            r11 - round key 2
            r12 - round key 2
            r13 - round key 3

            r14 - round key 3
            r15 - round key 3
            r16 - round key 3
            r17 - round key 3

            r18 - temp
            r19 - temp
            r20 - temp
            r21 - temp

            r28 - loop counter
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
        "push r14" "\n\t"
        "push r15" "\n\t"
        "push r16" "\n\t"
        "push r17" "\n\t"
        "push r18" "\n\t"
        "push r19" "\n\t"
        "push r20" "\n\t"
        "push r21" "\n\t"

        "push r28" "\n\t"

        "push r27" "\n\t"
        "push r26" "\n\t"

        "push r31" "\n\t"
        "push r30" "\n\t"


        /* set key pointer: X (r27, r26) */
        "movw r26, r24" "\n\t"
        /* set round keys pointer: Z (r31, r30) */
        "movw r30, r22" "\n\t"


        /* load key */
        "ld r2, x+" "\n\t"
        "ld r3, x+" "\n\t"
        "ld r4, x+" "\n\t"
        "ld r5, x+" "\n\t"

        "ld r6, x+" "\n\t"
        "ld r7, x+" "\n\t"
        "ld r8, x+" "\n\t"
        "ld r9, x+" "\n\t"

        "ld r10, x+" "\n\t"
        "ld r11, x+" "\n\t"
        "ld r12, x+" "\n\t"
        "ld r13, x+" "\n\t"

        "ld r14, x+" "\n\t"
        "ld r15, x+" "\n\t"
        "ld r16, x+" "\n\t"
        "ld r17, x+" "\n\t"


        /* store round keys */
        "st z+, r2" "\n\t"
        "st z+, r3" "\n\t"
        "st z+, r4" "\n\t"
        "st z+, r5" "\n\t"

        "st z+, r6" "\n\t"
        "st z+, r7" "\n\t"
        "st z+, r8" "\n\t"
        "st z+, r9" "\n\t"

        "st z+, r10" "\n\t"
        "st z+, r11" "\n\t"
        "st z+, r12" "\n\t"
        "st z+, r13" "\n\t"


        /* initialize loop counter */
        "ldi r28, 1" "\n\t"
        "step:" "\n\t"


        "mov r18, r14" "\n\t"
        "mov r19, r15" "\n\t"
        "mov r20, r16" "\n\t"
        "mov r21, r17" "\n\t"
        "add r20, r28" "\n\t"
        "adc r21, __zero_reg__" "\n\t" // r1


        /* key 3 */
        "mov r14, r10" "\n\t"
        "mov r15, r11" "\n\t"
        "mov r16, r12" "\n\t"
        "mov r17, r13" "\n\t"


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

        "add r6, r2" "\n\t"
        "adc r7, r3" "\n\t"
        "add r8, r4" "\n\t"
        "adc r9, r5" "\n\t"


        /* key 2 */
        "mov r10, r6" "\n\t"
        "mov r11, r7" "\n\t"
        "mov r12, r8" "\n\t"
        "mov r13, r9" "\n\t"


        /* key 1 */
        "mov r6, r2" "\n\t"
        "mov r7, r3" "\n\t"
        "mov r8, r4" "\n\t"
        "mov r9, r5" "\n\t"


        /* key 0 */
        "mov r2, r18" "\n\t"
        "mov r3, r19" "\n\t"
        "mov r4, r20" "\n\t"
        "mov r5, r21" "\n\t"


        /* store round keys */
        "st z+, r2" "\n\t"
        "st z+, r3" "\n\t"
        "st z+, r4" "\n\t"
        "st z+, r5" "\n\t"

        "st z+, r6" "\n\t"
        "st z+, r7" "\n\t"
        "st z+, r8" "\n\t"
        "st z+, r9" "\n\t"

        "st z+, r10" "\n\t"
        "st z+, r11" "\n\t"
        "st z+, r12" "\n\t"
        "st z+, r13" "\n\t"


        /* loop end */
        "inc r28" "\n\t"
        "cpi r28, 16" "\n\t"
        "brne step" "\n\t"


        /* post whitening keys */
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


        /* key 0 */
        "add r16, r28" "\n\t"
        "adc r17, __zero_reg__" "\n\t" // r1


        /* store round keys */
        "st z+, r14" "\n\t"
        "st z+, r15" "\n\t"
        "st z+, r16" "\n\t"
        "st z+, r17" "\n\t"

        "st z+, r2" "\n\t"
        "st z+, r3" "\n\t"
        "st z+, r4" "\n\t"
        "st z+, r5" "\n\t"


        /* restore context */
        "pop r30" "\n\t"
        "pop r31" "\n\t"

        "pop r26" "\n\t"
        "pop r27" "\n\t"

        "pop r28" "\n\t"

        "pop r21" "\n\t"
        "pop r20" "\n\t"
        "pop r19" "\n\t"
        "pop r18" "\n\t"
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

#elif defined(MSP)

void /*__attribute__((naked))*/ RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r15 - *key
            r14 - *roundKeys
        */

        /*
            r4 - round key 0
            r5 - round key 0

            r6 - round key 1
            r7 - round key 1

            r8 - round key 2
            r9 - round key 2

            r10 - round key 3
            r11 - round key 3

            r12 - temp
            r13 - temp

            r15 - *key / loop counter
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
        "push r13" "\n\t"
        //"push r15" "\n\t"


        /* load key */
        "mov @r15+, r4" "\n\t"
        "mov @r15+, r5" "\n\t"

        "mov @r15+, r6" "\n\t"
        "mov @r15+, r7" "\n\t"

        "mov @r15+, r8" "\n\t"
        "mov @r15+, r9" "\n\t"

        "mov @r15+, r10" "\n\t"
        "mov @r15+, r11" "\n\t"


        /* store round keys */
        "mov r4, 0(r14)" "\n\t"
        "mov r5, 2(r14)" "\n\t"

        "mov r6, 4(r14)" "\n\t"
        "mov r7, 6(r14)" "\n\t"

        "mov r8, 8(r14)" "\n\t"
        "mov r9, 10(r14)" "\n\t"

        "add #12, r14" "\n\t"


        /* initialize loop counter */
        "mov #1, r15" "\n\t"
        "step:" "\n\t"


        "mov r10, r12" "\n\t"
        "mov r11, r13" "\n\t"
        "add r15, r13" "\n\t"


        /* key 3 */
        "mov r8, r10" "\n\t"
        "mov r9, r11" "\n\t"


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

        "add r4, r6" "\n\t"
        "add r5, r7" "\n\t"


        /* key 2 */
        "mov r6, r8" "\n\t"
        "mov r7, r9" "\n\t"


        /* key 1 */
        "mov r4, r6" "\n\t"
        "mov r5, r7" "\n\t"


        /* key 0 */
        "mov r12, r4" "\n\t"
        "mov r13, r5" "\n\t"


        /* store round keys */
        "mov r4, 0(r14)" "\n\t"
        "mov r5, 2(r14)" "\n\t"

        "mov r6, 4(r14)" "\n\t"
        "mov r7, 6(r14)" "\n\t"

        "mov r8, 8(r14)" "\n\t"
        "mov r9, 10(r14)" "\n\t"

        "add #12, r14" "\n\t"


        /* loop end */
        "inc r15" "\n\t"
        "cmp #16, r15" "\n\t"
        "jne step" "\n\t"


        /* post whitening keys */
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


        /* key 0 */
        "add r15, r11" "\n\t"


        /* store round keys */
        "mov r10, 0(r14)" "\n\t"
        "mov r11, 2(r14)" "\n\t"

        "mov r4, 4(r14)" "\n\t"
        "mov r5, 6(r14)" "\n\t"


        /* restore context */
        //"pop r15" "\n\t"
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
    );
}

#endif
