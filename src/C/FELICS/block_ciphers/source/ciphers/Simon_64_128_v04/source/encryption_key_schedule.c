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
   * key word i+3 : r13-r12
   * key word i+2 : r11-r10
   * key word i+1 : r9-r8
   * key word i   : r7-r6
   * tmp word     : r5-r4
   *
   * constant pointer/loop counter : r15
   */

  "push r11"           "\n\t"
  "push r10"           "\n\t"
  "push r9"            "\n\t"
  "push r8"            "\n\t"
  "push r7"            "\n\t"
  "push r6"            "\n\t"
  "push r5"            "\n\t"
  "push r4"            "\n\t"

  /* Copy the key to registers */
  "mov @r15+, r6"      "\n\t"
  "mov @r15+, r7"      "\n\t"
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
  "mov r6, 0(r14)"     "\n\t"
  "mov r7, 2(r14)"     "\n\t"

  "add #4, r14"        "\n\t"

  /* k_i ^= Z_XOR3 */
  "mov.b @r15+, r4"   "\n\t"
  "xor      r4, r6"   "\n\t"

  /* Save word i+3 */
  "mov r12, r4"       "\n\t"
  "mov r13, r5"       "\n\t"

  /* k_{i+3} = S^{-3}(k_{i+3}) */
  RCS3(r13, r12)

  /* k_{i+3} ^= k_{i+1} */
  "xor r8, r12"       "\n\t"
  "xor r9, r13"       "\n\t"  

  /* k_i ^= S^{-3}(k_{i+3}) ^ k_{i+1} */
  "xor r12, r6"       "\n\t"
  "xor r13, r7"       "\n\t"

  RCS1(r13, r12)

  "xor r6, r12"       "\n\t"
  "xor r7, r13"       "\n\t"

  "inv r12"           "\n\t"
  "inv r13"           "\n\t"

  /* Register motion */
  "mov r8,   r6"      "\n\t"
  "mov r10,  r8"      "\n\t"
  "mov r4,  r10"      "\n\t"

  "mov r9,   r7"      "\n\t"
  "mov r11,  r9"      "\n\t"
  "mov r5,  r11"      "\n\t"

  "cmp #Z_XOR_3+44, r15"   "\n\t"
  "jne ks_loop_begin"      "\n\t"

  "pop r4"            "\n\t"
  "pop r5"            "\n\t"
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

    "push r28"                   "\n\t"
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
    "push r7"                    "\n\t"
    "push r6"                    "\n\t"

    /*
     * Register usage:
     *
     * key3     = r25, r24, r23, r22
     * key2     = r21, r20, r19, r18
     * key1     = r17, r16, r15, r14
     * key0     = r13, r12, r11, r10
     * tmp word = r9, r8, r7, r6
     *
     * loop counter = r28
     *
     * Z register (r31:r30) used for key and constant pointer
     * X register (r27:r26) used for roundKey pointer
     *
     */

    "movw r30, r24"                    "\n\t"
    "movw r26, r22"                    "\n\t"

    "ld r10, z+"                       "\n\t"
    "ld r11, z+"                       "\n\t"
    "ld r12, z+"                       "\n\t"
    "ld r13, z+"                       "\n\t"
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

    "ldi r28, 44"                      "\n\t"

    /* Setup Z pointer  */ 
    "ldi r30, lo8(Z_XOR_252)"          "\n\t"
    "ldi r31, hi8(Z_XOR_252)"          "\n\t"

    "ks_loop_begin:"                   "\n\t"

    /* Store round key */

    "st x+, r10"                       "\n\t"
    "st x+, r11"                       "\n\t"
    "st x+, r12"                       "\n\t"
    "st x+, r13"                       "\n\t"

    /* Perform register motion, saving k_i in tmp word */ 
    MOV(r9,   r8,  r7,  r6, r13, r12, r11, r10)
    MOV(r13, r12, r11, r10, r17, r16, r15, r14)
    MOV(r17, r16, r15, r14, r21, r20, r19, r18)
    MOV(r21, r20, r19, r18, r25, r24, r23, r22)
    
    /* Rotate k_{i+3} */
    RCS3(r25, r24, r23, r22)

    /* k_{i+3} ^= k_{i+1}. The k_{i+1} value is now in k_i */
    XOR(r25, r24, r23, r22, r13, r12, r11, r10)

    /* tmp ^= k_{i+3} */
    XOR(r9, r8, r7, r6, r25, r24, r23, r22)

    /* Rotate and xor again */
    RCS1(r25, r24, r23, r22)
    XOR(r9, r8, r7, r6, r25, r24, r23, r22)

    SIMON_ADD_CONST(r9, r8, r7, r6, r22)

    /* k_{i+3} = tmp */
    MOV(r25, r24, r23, r22, r9, r8, r7, r6)

    "dec r28"                          "\n\t"

   /* Are we done? */
    "brne ks_loop_begin"               "\n\t"

    "pop r6"                           "\n\t"
    "pop r7"                           "\n\t"
    "pop r8"                           "\n\t"
    "pop r9"                           "\n\t"
    "pop r10"                          "\n\t"
    "pop r11"                          "\n\t"
    "pop r12"                          "\n\t"
    "pop r13"                          "\n\t"
    "pop r14"                          "\n\t"
    "pop r15"                          "\n\t"
    "pop r16"                          "\n\t"
    "pop r17"                          "\n\t"
    "pop r28"                          "\n\t"

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
  rk[3] = mk[3];

  for (i = 4; i < NUMBER_OF_ROUNDS; ++i) {

    tmp  = rot32r3(rk[i - 1]) ^ rk[i - 3];
    tmp ^= rot32r1(tmp);

    z_xor_3 = READ_Z_BYTE(Z_XOR_3[i - 4]);

    rk[i] = ~(rk[i - 4]) ^ tmp ^ (uint32_t)z_xor_3;
  }
}

#endif
