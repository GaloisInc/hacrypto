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
 *                    Jason Smith <jksmit3@tycho.ncsc.mil>
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

void  __attribute__((naked))
RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
  asm (

  /*
   * Register usage:
   *
   * key word 2    : r13-r12
   * key word 1 (x): r11-r10
   * key word 0 (y): r9-r8
   *
   * tmp           : r5
   */

  "push r11"           "\n\t"
  "push r10"           "\n\t"
  "push r9"            "\n\t"
  "push r8"            "\n\t"
  "push r5"            "\n\t"

  /* Copy key from memory */

  "mov @r15+, r8"      "\n\t"
  "mov @r15+, r9"      "\n\t"
  "mov @r15+, r10"     "\n\t"
  "mov @r15+, r11"     "\n\t"
  "mov @r15+, r12"     "\n\t"
  "mov @r15+, r13"     "\n\t"

  /*
   * No longer need r15, so we'll use it as the loop counter. We have to
   * count up for the key schedule
   */

  "clr r15"           "\n\t"

  "ks_loop_begin:"

  /* Copy y to memory */

  "mov r8, 0(r14)"    "\n\t"
  "mov r9, 2(r14)"    "\n\t"

  /* Are we done? */

  "cmp #25, r15"      "\n\t"
  "jeq ks_done"       "\n\t"

  "add #4, r14"       "\n\t"

  SPECK_ENC_KS_ROUND(r11, r10, r9, r8, r15, r5)

  /* Shift the words of key */

  "mov r10, r5"       "\n\t"
  "mov r12, r10"      "\n\t"
  "mov r5,  r12"      "\n\t"

  "mov r11,  r5"      "\n\t"
  "mov r13, r11"      "\n\t"
  "mov r5,  r13"      "\n\t"

  "inc r15"           "\n\t"
  "jmp ks_loop_begin" "\n\t"

  "ks_done:"

  "pop r5"            "\n\t"
  "pop r8"            "\n\t"
  "pop r9"            "\n\t"
  "pop r10"           "\n\t"
  "pop r11"           "\n\t"

  "ret"               "\n\t"
  );
}

#elif defined(AVR)

#include "avr_basic_asm_macros.h"

void  __attribute__((naked))
RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
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

    /*
     * Register usage:
     *
     * key2 = r25, r24, r23, r22
     * x    = r21, r20, r19, r18
     * y    = r17, r16, r15, r14
     * tmp  = r13, r12, r11, r10
     *
     * Z register (r31:r30) used for key pointer
     * X register (r27:r26) used for roundKey pointer
     *
     * count = r30
     */

    "movw r30, r24"                    "\n\t"
    "movw r26, r22"                    "\n\t"

    "ld r14, z+"                       "\n\t"
    "ld r15, z+"                       "\n\t"
    "ld r16, z+"                       "\n\t"
    "ld r17, z+"                       "\n\t"
    "ld r18, z+"                       "\n\t"
    "ld r19, z+"                       "\n\t"
    "ld r20, z+"                       "\n\t"
    "ld r21, z+"                       "\n\t"
    "ld r22, z+"                       "\n\t"
    "ld r23, z+"                       "\n\t"
    "ld r24, z+"                       "\n\t"
    "ld r25, z"                        "\n\t"

    "ldi r30, 0"                       "\n\t"

    "ks_loop_begin:"                   "\n\t"

    /* Store round key */

    "st x+, r14"                       "\n\t"
    "st x+, r15"                       "\n\t"
    "st x+, r16"                       "\n\t"
    "st x+, r17"                       "\n\t"

    /* Are we done? */
    "cpi r30, 25"                      "\n\t"
    "breq ks_done"                     "\n\t"

    /* Copy x to tmp */
    "movw r10, r18"                    "\n\t"
    "movw r12, r20"                    "\n\t"

    /* Perform round with tmp = x */
    SPECK_KS_ROUND(r13, r12, r11, r10, r17, r16, r15, r14, r0, r30)

    /* Shift the key words */
    "movw r18, r22"                    "\n\t"
    "movw r20, r24"                    "\n\t"
    "movw r22, r10"                    "\n\t"
    "movw r24, r12"                    "\n\t"

    "inc r30"                          "\n\t"

    "rjmp ks_loop_begin"               "\n\t"

    "ks_done:"                         "\n\t"

    "pop r10"                          "\n\t"
    "pop r11"                          "\n\t"
    "pop r12"                          "\n\t"
    "pop r13"                          "\n\t"
    "pop r14"                          "\n\t"
    "pop r15"                          "\n\t"
    "pop r16"                          "\n\t"
    "pop r17"                          "\n\t"

    "ret"                              "\n\t"

  );
}

#else

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
  uint32_t *key32       = (uint32_t *)key;
  uint32_t *roundKeys32 = (uint32_t *)roundKeys;

  uint32_t y    = key32[0];
  uint32_t x    = key32[1];
  uint32_t key2 = key32[2];
  uint32_t tmp;

  uint8_t i = 0;

  while(1) {

    roundKeys32[i] = y;

    if (i == NUMBER_OF_ROUNDS-1) break;

    x = (rot32r8(x) + y) ^ i++;
    y = rot32l3(y) ^ x;

    tmp  = x;
    x    = key2;
    key2 = tmp;

  }
}
#endif
