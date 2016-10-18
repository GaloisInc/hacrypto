/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu>,
 *                    Jason Smith <jksmit3@tycho.ncsc.mil>,
 *                    Bryan Weeks <beweeks@tycho.ncsc.mil>
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
#include "rot32.h"
#include "constants.h"

#if defined(MSP)

#include "msp430_basic_asm_macros.h"

void __attribute__((naked)) Decrypt(uint8_t *block, uint8_t *roundKeys)
{
  asm (

    /* Arguments for MSP should be in r15 and r14 */

    /* Store x in r12-r11, y in r10-r9, and use r8-r4 as tmp */

    /* r11-r4 must be pushed if used */

    "push r11"         "\n\t"
    "push r10"         "\n\t"
    "push r9"          "\n\t"
    "push r8"          "\n\t"
    "push r7"          "\n\t"
    "push r6"          "\n\t"
    "push r5"          "\n\t"
    "push r4"          "\n\t"

    /* Copy ciphertext from memory */

    "mov @r15+, r9"    "\n\t"
    "mov @r15+, r10"   "\n\t"
    "mov @r15+, r11"   "\n\t"
    "mov @r15+, r12"   "\n\t"

    /*
     * Start reading key from the beginning of the last key word since
     * there's no MSP430 autodecrement addressing mode
     */
    "add #43*4, r14"   "\n\t"

    /* Setup loop counter */
    "mov #44, r13"     "\n\t"

    "loop_begin:"      "\n\t"

    SIMON_ENC_ROUND(r10, r9, r12, r11, r14, r8, r7, r6, r5, r4)

    /* Jump back to the beginning of the previous key word */
    "sub #8, r14"      "\n\t"

    "dec r13"          "\n\t"
    "jne loop_begin"   "\n\t"

    /* Copy results to memory */

    /* r15 was advanced by 8 bytes when we read in the plaintext,
       so the offsets used here are offset-8 */

    "mov r9 , -8(r15)" "\n\t"
    "mov r10, -6(r15)" "\n\t"
    "mov r11, -4(r15)" "\n\t"
    "mov r12, -2(r15)" "\n\t"

    "pop r4"           "\n\t"
    "pop r5"           "\n\t"
    "pop r6"           "\n\t"
    "pop r7"           "\n\t"
    "pop r8"           "\n\t"
    "pop r9"           "\n\t"
    "pop r10"          "\n\t"
    "pop r11"          "\n\t"

    "ret"              "\n\t"
  );

}

#elif defined(AVR)

#include "avr_basic_asm_macros.h"

void __attribute__((naked)) Decrypt(uint8_t *block, uint8_t *roundKeys)
{
  asm (

    /*
     * GCC AVR passes arguments from left to right in r25-r8. Pointers
     * are 16-bits, so arguments are in r25:r24 and r23:22
     */

    /* Must save r2-r17, r28-r29 */

    "push r17"                   "\n\t"
    "push r16"                   "\n\t"
    "push r15"                   "\n\t"
    "push r14"                   "\n\t"
    "push r13"                   "\n\t"

    "push r12"                   "\n\t"
    "push r11"                   "\n\t"
    "push r10"                   "\n\t"
    "push r9"                    "\n\t"
    "push r8"                    "\n\t"

    /*
     * Register usage:
     *
     * x and k must start on even registers to use movw.
     *
     * count must be above r15 to use ldi
     *
     * k = r25, r24, r23, r22
     * x = r21, r20, r19, r18
     * y = r16, r15, r14, r13
     *
     * Z register (r31:r30) used for key pointer
     * X register (r27:r26) used for block pointer
     *
     * count = r17
     */

    /* Copy ciphertext from memory */
    "movw r26, r24"                    "\n\t"

    "ld r12, x+"                       "\n\t"
    "ld r13, x+"                       "\n\t"
    "ld r14, x+"                       "\n\t"
    "ld r15, x+"                       "\n\t"
    "ld r18, x+"                       "\n\t"
    "ld r19, x+"                       "\n\t"
    "ld r20, x+"                       "\n\t"
    "ld r21, x"                        "\n\t"

    /*
     * Setup key pointer
     *
     * When reading from flash we start at the beginning of the last key
     * word. With RAM we start at the end.
     *
     * The AVR ADIW instruction can only handle immediate values from
     * 0-63 so this takes three adds.
     */

    "movw r30, r22"                    "\n\t"

    "adiw r30, 63"                     "\n\t"
    "adiw r30, 63"                     "\n\t"

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
    "adiw r30, 46"                     "\n\t"
#else
    "adiw r30, 50"                     "\n\t"
#endif

    "ldi r17, 44"                      "\n\t"

    "loop_begin:"                      "\n\t"

    LOAD_KEY_DEC(r25, r24, r23, r22)                   
    SIMON_ENC_ROUND(r15, r14, r13, r12, r21, r20, r19, r18, r25, r24, r23, r22, r11, r10, r9, r8)

    "dec r17"                          "\n\t"
    "brne loop_begin"                  "\n\t"

    /* Copy back plaintext */

    "st x,  r21"                  "\n\t"
    "st -x, r20"                  "\n\t"
    "st -x, r19"                  "\n\t"
    "st -x, r18"                  "\n\t"
    "st -x, r15"                  "\n\t"
    "st -x, r14"                  "\n\t"
    "st -x, r13"                  "\n\t"
    "st -x, r12"                  "\n\t"

    "pop r8"                     "\n\t"
    "pop r9"                     "\n\t"
    "pop r10"                    "\n\t"
    "pop r11"                    "\n\t"
    "pop r12"                    "\n\t"

    "pop r13"                    "\n\t"
    "pop r14"                    "\n\t"
    "pop r15"                    "\n\t"
    "pop r16"                    "\n\t"
    "pop r17"                    "\n\t"

    "ret"                        "\n\t"
  );

}



#else

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
  uint32_t       *block32  = (uint32_t *)block;
  const uint32_t *rk       = (uint32_t *)roundKeys;

  uint32_t y = block32[0];
  uint32_t x = block32[1];

  int8_t i;
  uint32_t tmp;

  for (i = NUMBER_OF_ROUNDS - 1; i >= 0; i--)
  {
    tmp = y;
    y = x ^ ( rot32l1(y) & rot32l8(y) ) ^ ( rot32l1(rot32l1(y)) ) ^ READ_ROUND_KEY_DOUBLE_WORD(rk[i]);
    x = tmp;
  }

  block32[0] = y;
  block32[1] = x;
}

#endif
