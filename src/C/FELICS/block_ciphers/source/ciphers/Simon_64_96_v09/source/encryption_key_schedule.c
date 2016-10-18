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

#if defined(MSP)

#include "msp430_basic_asm_macros.h"

void  __attribute__((naked))
RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
  asm (

  /*
   * Register usage:
   *
   * key word i+2 : r13-r12
   * key word i+1 : r11-r10
   * key word i   : r9-r8
   * tmp word     : r7-r6
   */

  "push r11"           "\n\t"
  "push r10"           "\n\t"
  "push r9"            "\n\t"
  "push r8"            "\n\t"
  "push r7"            "\n\t"
  "push r6"            "\n\t"

  /* Copy the key to registers */
  "mov @r15+, r8"      "\n\t"
  "mov @r15+, r9"      "\n\t"
  "mov @r15+, r10"     "\n\t"
  "mov @r15+, r11"     "\n\t"
  "mov @r15+, r12"     "\n\t"
  "mov @r15,  r13"     "\n\t"

  /* No longer need r15, so we'll use it to point to z_xor_3 */

  "mov #Z_XOR_3, r15"  "\n\t"

  "ks_loop_begin:"     "\n\t"

  /* Store the round key */
  "mov r8, 0(r14)"    "\n\t"
  "mov r9, 2(r14)"    "\n\t"

  "add #4, r14"       "\n\t"

  /* k_i ^= Z_XOR3 */
  "mov.b @r15+, r6"   "\n\t"
  "xor      r6, r8"   "\n\t"

  /* Save word i+2 */
  "mov r12, r6"       "\n\t"
  "mov r13, r7"       "\n\t"

  /* k_{i+2} = S^{-3}(k_{i+2}) */
  RCS3(r13, r12)

  /* k_i ^= S^{-3}(k_{i+2}) */
  "xor r12, r8"       "\n\t"
  "xor r13, r9"       "\n\t"

  RCS1(r13, r12)

  "xor r8, r12"       "\n\t"
  "xor r9, r13"       "\n\t"

  "inv r12"           "\n\t"
  "inv r13"           "\n\t"

  /* Register motion */
  "mov r10,  r8"      "\n\t"
  "mov r6,  r10"      "\n\t"

  "mov r11,  r9"      "\n\t"
  "mov r7,  r11"      "\n\t"

  "cmp #Z_XOR_3+42, r15"   "\n\t"
  "jne ks_loop_begin"      "\n\t"

  "pop r6"            "\n\t"
  "pop r7"            "\n\t"
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
    "push r28"                   "\n\t"
 
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

    "ldi r28, 42"                       "\n\t"

    /* Setup Z pointer  */ 
    "ldi r30, lo8(Z_XOR_252)"            "\n\t"
    "ldi r31, hi8(Z_XOR_252)"            "\n\t"

    "ks_loop_begin:"                   "\n\t"

    /* Store round key */

    "st x+, r14"                       "\n\t"
    "st x+, r15"                       "\n\t"
    "st x+, r16"                       "\n\t"
    "st x+, r17"                       "\n\t"

    SIMON_KS_ROUND(r25, r24, r23, r22, r21, r20, r19, r18, r17, r16, r15, r14, r13, r12, r11, r10)

    "dec r28"                          "\n\t"

   /* Are we done? */
    "brne ks_loop_begin"               "\n\t"

    "pop r28"                          "\n\t"
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

#include "constants.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
  uint8_t i;
  uint8_t z_xor_3;
  uint32_t tmp;
  uint32_t *mk = (uint32_t *)key;
  uint32_t *rk = (uint32_t *)roundKeys;

  rk[0] = mk[0];
  rk[1] = mk[1];
  rk[2] = mk[2];

  for (i = 3; i < NUMBER_OF_ROUNDS; ++i) {

    tmp  = rot32r3(rk[i - 1]);
    tmp ^= rot32r1(tmp);

    z_xor_3 = READ_Z_BYTE(Z_XOR_3[(i - 3)]);

    rk[i] = ~(rk[i - 3]) ^ tmp ^ (uint32_t)z_xor_3;
  }
}

#endif
