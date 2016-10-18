/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu> and
 * André Stemper <andre.stemper@uni.lu>
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

#define EQUALIZE_EXECUTION_TIME 1

#ifdef AVR
/*----------------------------------------------------------------------------*/
/* Optimized for AVR                                                          */
/* rc_tab and sbox are assumed to be aligned on a 256 byte boundary.          */
/* __attribute__ ((aligned (256)))                                            */
/*----------------------------------------------------------------------------*/
#include "constants.h"
/*----------------------------------------------------------------------------*/
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile (\
        /*--------------------------------------------------*/
        /* Registers allocation:                            */
        /*     r0-r15  : state                              */
        /*     r16     : loop counter                       */
        /*     r17     : temporary 0                        */
        /*     r18     : temporary 1                        */
        /*     r19     : temporary 2                        */
        /*     r20     : temporary 3                        */
        /*     r21     : temporary 4                        */
        /*     r22     : temporary 5                        */
        /*     r23     : 0x1b                               */
        /*     r24     : unused                             */
        /*     r25     : unused                             */
        /*     r26:r27 : X Plain text                       */
        /*     r28:r29 : Unused                             */
        /*     r30:r31 : Z Key / Sbox                       */
        /*                                                  */
        /* State:                                           */
        /*     r0 r4 r8  r12                                */
        /*     r1 r5 r9  r13                                */
        /*     r2 r6 r10 r14                                */
        /*     r3 r7 r11 r15                                */
        /*--------------------------------------------------*/
        /* Store all modified registers */
        /*--------------------------------------------------*/
        "push  r0;\n"
        "push  r2;\n"
        "push  r3;\n"
        "push  r4;\n"
        "push  r5;\n"
        "push  r6;\n"
        "push  r7;\n"
        "push  r8;\n"
        "push  r9;\n"
        "push r10;\n"
        "push r11;\n"
        "push r12;\n"
        "push r13;\n"
        "push r14;\n"
        "push r15;\n"
        "push r16;\n"
        "push r17;\n"
        /*--------------------------------------------------*/
        /* copy the block state from memory to registers    */
        /*--------------------------------------------------*/
        "ld    r0,    x+;\n"
        "ld    r1,    x+;\n"
        "ld    r2,    x+;\n"
        "ld    r3,    x+;\n"
        "ld    r4,    x+;\n"
        "ld    r5,    x+;\n"
        "ld    r6,    x+;\n"
        "ld    r7,    x+;\n"
        "ld    r8,    x+;\n"
        "ld    r9,    x+;\n"
        "ld   r10,    x+;\n"
        "ld   r11,    x+;\n"
        "ld   r12,    x+;\n"
        "ld   r13,    x+;\n"
        "ld   r14,    x+;\n"
        "ld   r15,    x+;\n"
        /*--------------------------------------------------*/
        "ldi  r23,   0x1b;\n" 
        "ldi  r16,     10;\n"  
        /*--------------------------------------------------*/
"encrypt_round:          \n"
        /*--------------------------------------------------*/
        /* AddRoundKey                                      */
        /*--------------------------------------------------*/
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
      	"lpm  r17,    z+;\n"
        "eor   r0,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r1,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r2,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r3,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r4,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r5,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r6,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r7,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r8,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r9,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r10,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r11,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r12,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r13,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r14,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r15,   r17;\n"
#else
        "ld   r17,    z+;\n"
        "eor   r0,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r1,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r2,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r3,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r4,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r5,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r6,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r7,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r8,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r9,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r10,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r11,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r12,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r13,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r14,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r15,   r17;\n"
#endif
        /*--------------------------------------------------*/
        /* SubBytes                                         */
        /*--------------------------------------------------*/
        "push r30;       \n" /* push z                      */ 
        "push r31;       \n"
        "ldi  r31,   hi8(sbox);\n"
        "mov  r30,    r0;\n"
        "lpm   r0,     z;\n"
        "mov  r30,    r1;\n"
        "lpm   r1,     z;\n"
        "mov  r30,    r2;\n"
        "lpm   r2,     z;\n"
        "mov  r30,    r3;\n"
        "lpm   r3,     z;\n"
        "mov  r30,    r4;\n"
        "lpm   r4,     z;\n"
        "mov  r30,    r5;\n"
        "lpm   r5,     z;\n"
        "mov  r30,    r6;\n"
        "lpm   r6,     z;\n"
        "mov  r30,    r7;\n"
        "lpm   r7,     z;\n"
        "mov  r30,    r8;\n"
        "lpm   r8,     z;\n"
        "mov  r30,    r9;\n"
        "lpm   r9,     z;\n"
        "mov  r30,   r10;\n"
        "lpm  r10,     z;\n"
        "mov  r30,   r11;\n"
        "lpm  r11,     z;\n"
        "mov  r30,   r12;\n"
        "lpm  r12,     z;\n"
        "mov  r30,   r13;\n"
        "lpm  r13,     z;\n"
        "mov  r30,   r14;\n"
        "lpm  r14,     z;\n"
        "mov  r30,   r15;\n"
        "lpm  r15,     z;\n"
        "pop  r31;       \n"
        "pop  r30;       \n"
        /*--------------------------------------------------*/
        /* Shift rows                                       */
        /*--------------------------------------------------*/
        "mov  r17,    r1;\n" /* Row 1                       */
        "mov   r1,    r5;\n"
        "mov   r5,    r9;\n"
        "mov   r9,   r13;\n"
        "mov  r13,   r17;\n"
        "mov  r17,    r2;\n" /* Row 2                       */
        "mov   r2,   r10;\n"
        "mov  r10,   r17;\n"
        "mov  r17,    r6;\n"
        "mov   r6,   r14;\n"
        "mov  r14,   r17;\n"
        "mov  r17,    r3;\n" /* Row 3                       */
        "mov   r3,   r15;\n"
        "mov  r15,   r11;\n"
        "mov  r11,    r7;\n"
        "mov   r7,   r17;\n"
        /*--------------------------------------------------*/
        "dec  r16;       \n"
        "brne encrypt_mix_columns;\n"
        "jmp  encrypt_final_addition;\n"
        /*--------------------------------------------------*/
"encrypt_mix_columns:\n"
        /*--------------------------------------------------*/
        /* MixColumns                                       */
        /*--------------------------------------------------*/
        /*  b0 = r0 * 2 + r4 * 3 + r8 * 1 + r12 * 1 
            b1 = r0 * 1 + r4 * 2 + r8 * 3 + r12 * 1 
            b2 = r0 * 1 + r4 * 1 + r8 * 2 + r12 * 3
            b3 = r0 * 3 + r4 * 1 + r8 * 1 + r12 * 2         */
        /*--------------------------------------------------*/
        /*--------------------------------------------------*/
        /* m(x) = x^8 + x^4 + x^3 + x + 1 -> 0x11b          */
        /* 8bit operation: xor by 0x1b instead of 0x11b     */
        /*-----------1111111--------------------------------*/
        /* Column 1                                         */
        /* t = tmp[4 * i + 0] ^ tmp[4 * i + 1] ^ 
                           tmp[4 * i + 2] ^ tmp[4 * i + 3]; */
        /*--------------------------------------------------*/
        "mov  r22,    r0;\n"
        "eor  r22,    r1;\n"
        "eor  r22,    r2;\n"
        "eor  r22,    r3;\n" 
        "movw r18,    r0;\n"
        "movw r20,    r2;\n"
        "eor  r18,    r1;\n"
        "eor  r19,    r2;\n"
        "eor  r20,    r3;\n"
        "eor  r21,    r0;\n"
        "lsl  r18;       \n" /* Byte 1 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r18,   r23;\n"
        "eor   r0,   r18;\n"
        "eor   r0,   r22;\n"
        "lsl  r19;       \n" /* Byte 2 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r19,   r23;\n"
        "eor   r1,   r19;\n"
        "eor   r1,   r22;\n"
        "lsl  r20;       \n" /* Byte 3 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r20,   r23;\n"
        "eor   r2,   r20;\n"
        "eor   r2,   r22;\n"
        "lsl  r21;       \n" /* Byte 4 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r21,   r23;\n"
        "eor   r3,   r21;\n"
        "eor   r3,   r22;\n"
        /*--------------------------------------------------*/
        /* Column 2                                         */
        /* t = tmp[4 * i + 0] ^ tmp[4 * i + 1] ^ 
                           tmp[4 * i + 2] ^ tmp[4 * i + 3]; */
        /*--------------------------------------------------*/
        "mov  r22,    r4;\n"
        "eor  r22,    r5;\n"
        "eor  r22,    r6;\n"
        "eor  r22,    r7;\n"
        "movw r18,    r4;\n"
        "movw r20,    r6;\n"
        "eor  r18,    r5;\n"
        "eor  r19,    r6;\n"
        "eor  r20,    r7;\n"
        "eor  r21,    r4;\n"
        "lsl  r18;       \n" /* Byte 1 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r18,   r23;\n"
        "eor   r4,   r18;\n"
        "eor   r4,   r22;\n"
        "lsl  r19;       \n" /* Byte 2 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r19,   r23;\n"
        "eor   r5,   r19;\n"
        "eor   r5,   r22;\n"
        "lsl  r20;       \n" /* Byte 3 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r20,   r23;\n"
        "eor   r6,   r20;\n"
        "eor   r6,   r22;\n"
        "lsl  r21;       \n" /* Byte 4 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif        
        "eor  r21,   r23;\n"
        "eor   r7,   r21;\n"
        "eor   r7,   r22;\n"
        /*--------------------------------------------------*/
        /* Column 3 */
        /* t = tmp[4 * i + 0] ^ tmp[4 * i + 1] ^
                           tmp[4 * i + 2] ^ tmp[4 * i + 3]; */
        /*--------------------------------------------------*/
        "mov  r22,    r8;\n"
        "eor  r22,    r9;\n"
        "eor  r22,   r10;\n"
        "eor  r22,   r11;\n"
        "movw r18,    r8;\n"
        "movw r20,   r10;\n"
        "eor  r18,    r9;\n"
        "eor  r19,   r10;\n"
        "eor  r20,   r11;\n"
        "eor  r21,    r8;\n"
        "lsl  r18;       \n" /* Byte 1 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif   
        "eor  r18,   r23;\n"
        "eor   r8,   r18;\n"
        "eor   r8,   r22;\n"
        "lsl  r19;       \n" /* Byte 2 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r19,   r23;\n"
        "eor   r9,   r19;\n"
        "eor   r9,   r22;\n"
        "lsl  r20;       \n" /* Byte 3 */

#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r20,   r23;\n"
        "eor  r10,   r20;\n"
        "eor  r10,   r22;\n"
        "lsl  r21;       \n" /* Byte 4 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r21,   r23;\n"
        "eor  r11,   r21;\n"
        "eor  r11,   r22;\n"
        /*--------------------------------------------------*/
        /* Column 4 */
        /* t = tmp[4 * i + 0] ^ tmp[4 * i + 1] ^
                           tmp[4 * i + 2] ^ tmp[4 * i + 3]; */
        /*--------------------------------------------------*/
        "mov  r22,   r12;\n"
        "eor  r22,   r13;\n"
        "eor  r22,   r14;\n"
        "eor  r22,   r15;\n"
        "movw r18,   r12;\n"
        "movw r20,   r14;\n"
        "eor  r18,   r13;\n"
        "eor  r19,   r14;\n"
        "eor  r20,   r15;\n"
        "eor  r21,   r12;\n"
        "lsl  r18;       \n" /* Byte 1 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r18,   r23;\n"
        "eor  r12,   r18;\n"
        "eor  r12,   r22;\n"
        "lsl  r19;       \n" /* Byte 2 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r19,   r23;\n"
        "eor  r13,   r19;\n"
        "eor  r13,   r22;\n"
        "lsl  r20;       \n" /* Byte 3 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r20,   r23;\n"
        "eor  r14,   r20;\n"
        "eor  r14,   r22;\n"
        "lsl  r21;       \n" /* Byte 4 */
#ifdef EQUALIZE_EXECUTION_TIME
        "brcs .+2;       \n" /* cycles: True?2:1             */
        "brcc .+2;       \n" /* cycles: True?2:1             */
#else
        "brcc .+2;       \n"
#endif
        "eor  r21,   r23;\n"
        "eor  r15,   r21;\n"
        "eor  r15,   r22;\n"
        "jmp encrypt_round;\n"
        /*--------------------------------------------------*/
"encrypt_final_addition:\n"
        /*--------------------------------------------------*/
        /* AddRoundKey                                      */
        /*--------------------------------------------------*/
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
		"lpm  r17,    z+;\n"
        "eor   r0,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r1,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r2,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r3,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r4,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r5,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r6,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r7,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r8,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor   r9,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r10,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r11,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r12,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r13,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r14,   r17;\n"
        "lpm  r17,    z+;\n"
        "eor  r15,   r17;\n"
#else
        "ld   r17,    z+;\n"
        "eor   r0,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r1,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r2,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r3,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r4,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r5,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r6,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r7,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r8,   r17;\n"
        "ld   r17,    z+;\n"
        "eor   r9,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r10,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r11,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r12,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r13,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r14,   r17;\n"
        "ld   r17,    z+;\n"
        "eor  r15,   r17;\n"
#endif
        /*--------------------------------------------------*/
        /* Store back the state                             */
        /*--------------------------------------------------*/
        "st    -x,   r15;\n"
        "st    -x,   r14;\n"
        "st    -x,   r13;\n"
        "st    -x,   r12;\n"
        "st    -x,   r11;\n"
        "st    -x,   r10;\n"
        "st    -x,    r9;\n"
        "st    -x,    r8;\n"
        "st    -x,    r7;\n"
        "st    -x,    r6;\n"
        "st    -x,    r5;\n"
        "st    -x,    r4;\n"
        "st    -x,    r3;\n"
        "st    -x,    r2;\n"
        "st    -x,    r1;\n"
        "st    -x,    r0;\n"
        /*--------------------------------------------------*/
        /* Restore all modified registers                   */
        /*--------------------------------------------------*/
        "pop  r17;\n"
        "pop  r16;\n"
        "pop  r15;\n"
        "pop  r14;\n"
        "pop  r13;\n"
        "pop  r12;\n"
        "pop  r11;\n"
        "pop  r10;\n"
        "pop   r9;\n"
        "pop   r8;\n"
        "pop   r7;\n"
        "pop   r6;\n"
        "pop   r5;\n"
        "pop   r4;\n"
        "pop   r3;\n"
        "pop   r2;\n"
        "clr   r1;\n" 
        "pop   r0;\n"
        /*--------------------------------------------------*/
    :
    : [block] "x" (block), [roundKeys] "z" (roundKeys), [sbox] "" (sbox)
); 
}
#else
/*----------------------------------------------------------------------------*/
/* Optimized for MSP                                                          */
/*----------------------------------------------------------------------------*/
#ifdef MSP

#include <stdint.h>
#include "constants.h"

/*----------------------------------------------------------------------------*/
/* Assembly                                                                   */
/*----------------------------------------------------------------------------*/
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile (\
        /*--------------------------------------------------*/
        /* r4  - Temp pointer to Block                      */
        /* r5  - Working temporary                          */
        /* r6  - Temporary 1                                */
        /* r7  - Temporary 2                                */
        /* r8  - Temporary 3                                */
        /* r9  - Temporary 4                                */
        /* r5  - Temporary 5                                */
        /* r10 - Temporary 6                                */
        /* r12 - Constant 0x1b                              */
        /* r13 - Loop counter                               */
        /* r14 - RoundKeys                                  */
        /* r15 - Block                                      */
        /*--------------------------------------------------*/
        /* Store all modified registers                     */
        /*--------------------------------------------------*/
        "push   r4;                 \n"
        "push   r5;                 \n"
        "push   r6;                 \n"
        "push   r7;                 \n"
        "push   r8;                 \n"
        "push   r9;                 \n"
        "push   r10;                \n"
        "push   r12;                \n"
        "push   r13;                \n"
        "push   r14;                \n"
        "push   r15;                \n"
        /*--------------------------------------------------*/
        "mov    %[block],       r15;\n"
        "mov    %[roundKeys],   r14;\n"
        /*--------------------------------------------------*/
        "mov.b  #0x1b,          r12;\n" /* r12 = 0x1b       */
        /*--------------------------------------------------*/
        "mov    #10,            r13;\n"
"encrypt_round_loop:                \n"
        /*--------------------------------------------------*/
        /* addroundkey, sbox and shiftrows                  */
        /* ordered such that round key pointer can be ++    */
        /*--------------------------------------------------*/
        "mov    r15,             r4;\n" /* temp ptr */
        /*--------------------------------------------------*/
        /* block[0] = sbox[(block[0] ^ roundKeys[i])];      */ 
        "mov.b  @r4+,            r5;\n" /* @block[0]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),    0(r15);\n" /* block[0]=sbox(r5)*/
        /* tmp1 = sbox[(block[1] ^ roundKeys[i + 1])];      */
        "mov.b  @r4+,            r5;\n" /* @block[1]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),        r6;\n" /* tmp1=sbox(r5)    */
        /* tmp3 = sbox[(block[2] ^ roundKeys[i + 2])];      */ 
        "mov.b  @r4+,            r5;\n" /* @block[2]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),        r8;\n" /* tmp3=sbox(r5)    */
        /* tmp4 = sbox[(block[3] ^ roundKeys[i + 3])];      */
        "mov.b  @r4+,            r5;\n" /* @block[3]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),        r9;\n" /* tmp4=sbox(r5)    */
        /* block[4] = sbox[(block[4] ^ roundKeys[i + 4])];  */
        "mov.b  @r4+,            r5;\n" /* @block[4]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),    4(r15);\n" /* block[4]=sbox(r5)*/
        /* block[1] = sbox[(block[5] ^ roundKeys[i + 5])];  */
        "mov.b  @r4+,            r5;\n" /* @block[5]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),    1(r15);\n" /* block[1]=sbox(r5)*/
        /* tmp2 = sbox[(block[6] ^ roundKeys[i + 6])];      */ 
        "mov.b  @r4+,            r5;\n" /* @block[6]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),        r7;\n" /* tmp2=sbox(r5)    */
        /* tmp5 = sbox[(block[7] ^ roundKeys[i + 7])];      */
        "mov.b  @r4+,            r5;\n" /* @block[7]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),       r10;\n" /* tmp2=sbox(r5)    */
        /* block[7] = tmp4;                                 */
        "mov.b  r9,          7(r15);\n" 
        /* block[8] = sbox[(block[ 8] ^ roundKeys[i + 8])]; */
        "mov.b  @r4+,            r5;\n" /* @block[8]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),    8(r15);\n" /* block[8]=sbox(r5)*/
        /* block[5] = sbox[(block[ 9] ^ roundKeys[i + 9])]; */
        "mov.b  @r4+,            r5;\n" /* @block[9]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),    5(r15);\n" /* block[5]=sbox(r5)*/
        /* block[2] = sbox[(block[10] ^ roundKeys[i + 10])];*/
        "mov.b  @r4+,            r5;\n" /* @block[10]       */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),    2(r15);\n" /* block[2]=sbox(r5)*/
        /* block[10] = tmp3;                                */
        "mov.b  r8,         10(r15);\n" 
        /* tmp3 = sbox[(block[11] ^ roundKeys[i + 11])];    */
        "mov.b  @r4+,            r5;\n" /* @block[11]       */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),        r8;\n" /* tmp3=sbox(r5)    */
        /* block[11] = tmp5;                                */
        "mov.b  r10,        11(r15);\n" 
        /*block[12] = sbox[(block[12] ^ roundKeys[i + 12])];*/
        "mov.b  @r4+,            r5;\n" /* @block[12]       */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),   12(r15);\n" /*block[12]=sbox(r5)*/
        /*block[9] = sbox[(block[13] ^ roundKeys[i + 13])]; */
        "mov.b  @r4+,            r5;\n" /* @block[9]        */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),    9(r15);\n" /* block[9]=sbox(r5)*/
        /* block[13] = tmp1;                                */
        "mov.b  r6,         13(r15);\n" 
        /* block[6] = sbox[(block[14] ^ roundKeys[i + 14])];*/
        "mov.b  @r4+,            r5;\n" /* @block[14]       */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),    6(r15);\n" /* block[6]=sbox(r5)*/
        /* block[14] = tmp2;                                */
        "mov.b  r7,         14(r15);\n" 
        /* block[3] = sbox[(block[15] ^ roundKeys[i + 15])];*/
        "mov.b  @r4+,            r5;\n" /* @block[15]       */     
        "xor.b  @r14+,           r5;\n" /* r5^=@rk++        */
        "mov.b  sbox(r5),    3(r15);\n" /* block[3]=sbox(r5)*/
        /* block[15] = tmp3;                                */
        "mov.b  r8,         15(r15);\n" 
        /*--------------------------------------------------*/
        /* leave last round before mixing                   */
        /*--------------------------------------------------*/
        "dec    r13;                \n" /* while(r13 != 0)  */
        "jz     encrypt_add_roundkey;\n"
        /*--------------------------------------------------*/
        /* Mix columns                                      */
        /*--------------------------------------------------*/
        "mov    r15,             r4;\n" /* temp ptr */
        /*--------------------------------------------------*/
        /* Column 1                                         */
        "mov.b  @r4+,            r6;\n" /* tmp1 = block[0]; */
        "mov.b  @r4+,            r7;\n" /* tmp2 = block[1]; */
        "mov.b  @r4+,            r8;\n" /* tmp3 = block[2]; */
        "mov.b  @r4+,            r9;\n" /* tmp4 = block[3]; */
        /*---                                               */
        /* tmp5 = tmp1 ^ tmp2;                              */
        "mov.b  r6,              r5;\n" 
        "xor.b  r7,              r5;\n"  
        /* tmp6 = tmp5 ^ tmp3 ^ tmp4;                       */
        "mov.b  r5,             r10;\n" 
        "xor.b  r8,             r10;\n"  
        "xor.b  r9,             r10;\n"  
        /* tmp5 = galois_multiply_times_2(tmp5);            */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[0] = tmp1 ^ tmp5 ^ tmp6;                   */
        "xor.b  r6,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          0(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp2 ^ tmp3;                              */
        "mov.b  r7,              r5;\n" 
        "xor.b  r8,              r5;\n"  
        /* tmp5     = galois_mul2(tmp5);                    */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[1] = tmp2 ^ tmp5 ^ tmp6;                   */
        "xor.b  r7,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          1(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp3 ^ tmp4;                              */
        "mov.b  r8,              r5;\n" 
        "xor.b  r9,              r5;\n"  
        /* tmp5 = galois_mul2(tmp5);                        */ 
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[2] = tmp3 ^ tmp5 ^ tmp6;                   */
        "xor.b  r8,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          2(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp4 ^ tmp1;                              */
        "mov.b  r6,              r5;\n" 
        "xor.b  r9,              r5;\n"  
        /* tmp5     = galois_mul2(tmp5);                    */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[3] = tmp4 ^ tmp5 ^ tmp6;                   */
        "xor.b  r9,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          3(r15);\n" 
        /*--------------------------------------------------*/
        /* Column 2                                         */
        "mov.b  @r4+,            r6;\n" /* tmp1 = block[4]; */
        "mov.b  @r4+,            r7;\n" /* tmp2 = block[5]; */
        "mov.b  @r4+,            r8;\n" /* tmp3 = block[6]; */
        "mov.b  @r4+,            r9;\n" /* tmp4 = block[7]; */
        /* tmp5 = tmp1 ^ tmp2;                              */ 
        "mov.b  r6,              r5;\n" 
        "xor.b  r7,              r5;\n"  
        /* tmp6 = tmp5 ^ tmp3 ^ tmp4;                       */
        "mov.b  r5,             r10;\n" 
        "xor.b  r8,             r10;\n"  
        "xor.b  r9,             r10;\n"  
        /* tmp5 = galois_multiply_times_2(tmp5);            */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[4] = tmp1 ^ tmp5 ^ tmp6;                   */
        "xor.b  r6,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          4(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp2 ^ tmp3;                              */
        "mov.b  r7,              r5;\n" 
        "xor.b  r8,              r5;\n"  
        /* tmp5     = galois_mul2(tmp5);                    */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[5] = tmp2 ^ tmp5 ^ tmp6;                   */
        "xor.b  r7,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          5(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp3 ^ tmp4;                              */
        "mov.b  r8,              r5;\n" 
        "xor.b  r9,              r5;\n"  
        /* tmp5 = galois_mul2(tmp5);                        */ 
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[6] = tmp3 ^ tmp5 ^ tmp6;                   */
        "xor.b  r8,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          6(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp4 ^ tmp1;                              */
        "mov.b  r6,              r5;\n" 
        "xor.b  r9,              r5;\n"  
        /* tmp5 = galois_mul2(tmp5);                        */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[7] = tmp4 ^ tmp5 ^ tmp6;                   */
        "xor.b  r9,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          7(r15);\n" 
        /*--------------------------------------------------*/
        /* Column 3                                         */
        "mov.b  @r4+,            r6;\n" /* tmp1 = block[8]; */
        "mov.b  @r4+,            r7;\n" /* tmp2 = block[9]; */
        "mov.b  @r4+,            r8;\n" /* tmp3 = block[10];*/
        "mov.b  @r4+,            r9;\n" /* tmp4 = block[11];*/
        /* tmp5 = tmp1 ^ tmp2;                              */ 
        "mov.b  r6,              r5;\n" 
        "xor.b  r7,              r5;\n"  
        /* tmp6 = tmp5 ^ tmp3 ^ tmp4;                       */
        "mov.b  r5,             r10;\n" 
        "xor.b  r8,             r10;\n"  
        "xor.b  r9,             r10;\n"  
        /* tmp5 = galois_multiply_times_2(tmp5);            */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[8] = tmp1 ^ tmp5 ^ tmp6;                   */
        "xor.b  r6,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          8(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp2 ^ tmp3;                              */
        "mov.b  r7,              r5;\n" 
        "xor.b  r8,              r5;\n"  
        /* tmp5     = galois_mul2(tmp5);                    */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[9] = tmp2 ^ tmp5 ^ tmp6;                   */
        "xor.b  r7,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          9(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp3 ^ tmp4;                              */
        "mov.b  r8,              r5;\n" 
        "xor.b  r9,              r5;\n"  
        /* tmp5 = galois_mul2(tmp5);                        */ 
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[10] = tmp3 ^ tmp5 ^ tmp6;                  */
        "xor.b  r8,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,         10(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp4 ^ tmp1;                              */
        "mov.b  r6,              r5;\n" 
        "xor.b  r9,              r5;\n"  
        /* tmp5 = galois_mul2(tmp5);                        */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[11] = tmp4 ^ tmp5 ^ tmp6;                  */
        "xor.b  r9,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,         11(r15);\n" 
        /*--------------------------------------------------*/
        /* Column 4                                         */
        "mov.b  @r4+,            r6;\n" /* tmp1 = block[12];*/
        "mov.b  @r4+,            r7;\n" /* tmp2 = block[13];*/
        "mov.b  @r4+,            r8;\n" /* tmp3 = block[14];*/
        "mov.b  @r4+,            r9;\n" /* tmp4 = block[15];*/
        /* tmp5 = tmp1 ^ tmp2;                              */ 
        "mov.b  r6,              r5;\n" 
        "xor.b  r7,              r5;\n"  
        /* tmp6 = tmp5 ^ tmp3 ^ tmp4;                       */
        "mov.b  r5,             r10;\n" 
        "xor.b  r8,             r10;\n"  
        "xor.b  r9,             r10;\n"  
        /* tmp5 = galois_multiply_times_2(tmp5);            */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[12] = tmp1 ^ tmp5 ^ tmp6;                  */
        "xor.b  r6,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,         12(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp2 ^ tmp3;                              */
        "mov.b  r7,              r5;\n" 
        "xor.b  r8,              r5;\n"  
        /* tmp5     = galois_mul2(tmp5);                    */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[13] = tmp2 ^ tmp5 ^ tmp6;                  */
        "xor.b  r7,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,          13(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp3 ^ tmp4;                              */
        "mov.b  r8,              r5;\n" 
        "xor.b  r9,              r5;\n"  
        /* tmp5 = galois_mul2(tmp5);                        */ 
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[14] = tmp3 ^ tmp5 ^ tmp6;                  */
        "xor.b  r8,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,         14(r15);\n" 
        /*---                                               */
        /* tmp5 = tmp4 ^ tmp1;                              */
        "mov.b  r6,              r5;\n" 
        "xor.b  r9,              r5;\n"  
        /* tmp5 = galois_mul2(tmp5);                        */
        "rla.b  r5;                 \n" /* msb -> carry     */
#ifdef EQUALIZE_EXECUTION_TIME
        "jc     $+4;                \n" 
        "jnc    $+4;                \n" 
#else
        "jnc    $+4;                \n" 
#endif
        "xor.b  r12,             r5;\n" /* xor by 0x1b      */
        /* block[15] = tmp4 ^ tmp5 ^ tmp6;                  */
        "xor.b  r9,              r5;\n"  
        "xor.b  r10,             r5;\n"  
        "mov.b  r5,         15(r15);\n" 
        /*--------------------------------------------------*/
        "jmp    encrypt_round_loop; \n"
        /*--------------------------------------------------*/
"encrypt_add_roundkey:\n"
        /*--------------------------------------------------*/
        /* Add round key                                    */
        /*--------------------------------------------------*/
        "xor    @r14+,       0(r15);\n" /* 0                */ 
        "xor    @r14+,       2(r15);\n" /* 2                */
        "xor    @r14+,       4(r15);\n" /* 4                */
        "xor    @r14+,       6(r15);\n" /* 6                */
        "xor    @r14+,       8(r15);\n" /* 8                */
        "xor    @r14+,      10(r15);\n" /* 10               */
        "xor    @r14+,      12(r15);\n" /* 11               */
        "xor    @r14+,      14(r15);\n" /* 12               */
        /*--------------------------------------------------*/
        /* Restore registers                                */
        /*--------------------------------------------------*/
        "pop    r15;                \n"
        "pop    r14;                \n"
        "pop    r13;                \n"
        "pop    r12;                \n"
        "pop    r10;                \n"
        "pop    r9;                 \n"
        "pop    r8;                 \n"
        "pop    r7;                 \n"
        "pop    r6;                 \n"
        "pop    r5;                 \n"
        "pop    r4;                 \n"
        /*--------------------------------------------------*/
    :
    : [block] "m" (block), [roundKeys] "m" (roundKeys), [sbox] "" (sbox)
); 
}
#else
#ifdef ARM
/*----------------------------------------------------------------------------*/
/* Optimized for ARM                                                          */
/*----------------------------------------------------------------------------*/
#include <stdint.h>
#include "constants.h"

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile (\
        /*--------------------------------------------------------------------*/
        /* r0  - State 0-3                                                    */
        /* r1  - State 4-7                                                    */
        /* r2  - State 8-11                                                   */
        /* r3  - State 12-15                                                  */
        /* r4  - Block  / Temporary 4 / a                                     */
        /* r5  - RoundKeys                                                    */
        /* r6  - Sbox                                                         */
        /* r7  - Temporary 7                                                  */
        /* r8  - Loop counter                                                 */
        /* r9  - Temporary 0                                                  */
        /* r10 - Temporary 1                                                  */
        /* r11 - Temporary 2                                                  */
        /* r12 - Temporary 3                                                  */
        /* lr  - 255 for masking                                              */
        /*--------------------------------------------------------------------*/
        /* Store all modified registers                                       */
        /*--------------------------------------------------------------------*/
        "stmdb        sp!,   {r0-r12,lr};              \n" 
        "mov           r4,      %[block];              \n" 
        "mov           r5,  %[roundKeys];              \n" 
        "ldr           r6,         =sbox;              \n"
        /*--------------------------------------------------------------------*/
        /* Load state                                                         */
        /*--------------------------------------------------------------------*/
        "ldmia         r4,       {r0-r3};              \n"
        "stmdb        sp!,          {r4};              \n"
        /*--------------------------------------------------------------------*/
        "mov           lr,          #255;              \n"
        "mov           r8,           #10;              \n"
"encrypt_round_loop:                                   \n" 
        /*--------------------------------------------------------------------*/
        /* AddRoundKey                                                        */
        /*--------------------------------------------------------------------*/
        "ldmia        r5!,      {r9-r12};              \n" /* ++              */
        "eor           r9,            r0,           r9;\n" /* column 0        */ 
        "eor          r10,            r1,          r10;\n" /* column 1        */
        "eor          r11,            r2,          r11;\n" /* column 2        */
        "eor          r12,            r3,          r12;\n" /* column 3        */
        /*--------------------------------------------------------------------*/
        /* SubBytes + Shift                                                   */
        /*--------------------------------------------------------------------*/
        /* block[ 0] = sbox[x0];                                              */
        "and           r0,            lr,           r9;\n" /* r7=(r9>>0)&ff   */
        "ldrb          r0,      [r6, r0];              \n" /* r7=sbox(r7)     */
        /* block[ 1] = sbox[x5];                                              */
        "and           r7,            lr,    r10,lsr#8;\n" /* r7=(r10>>1)&ff  */
        "ldrb          r7,      [r6, r7];              \n" /* r7=sbox(r7)     */
        "orr           r0,            r0,     r7,lsl#8;\n" /* collect bytes   */
        /* block[ 2] = sbox[x10];                                             */
        "and           r7,            lr,   r11,lsr#16;\n" /* r7=(r11>>2)&ff  */
        "ldrb          r7,                    [r6, r7];\n" /* r7=sbox(r7)     */
        "orr           r0,            r0,   r7, lsl#16;\n" /* collect bytes   */
        /* block[ 3] = sbox[x15];                                             */
        "and           r7,            lr,   r12,lsr#24;\n" /* r7=(r12>>3)&ff  */
        "ldrb          r7,                    [r6, r7];\n" /* r7=sbox(r7)     */
        "orr           r0,            r0,    r7,lsl#24;\n" /* collect bytes   */
        /* block[ 4] = sbox[x4];                                              */
        "and           r1,            lr,          r10;\n" 
        "ldrb          r1,      [r6, r1];              \n" /* r7=sbox(r7)     */
        /* block[ 5] = sbox[x9];                                              */
        "and           r7,            lr,    r11,lsr#8;\n" 
        "ldrb          r7,      [r6, r7];              \n" /* r7=sbox(r7)     */
        "orr           r1,            r1,     r7,lsl#8;\n" /* collect bytes   */
        /* block[ 6] = sbox[x14];                                             */
        "and           r7,            lr,   r12,lsr#16;\n" 
        "ldrb          r7,      [r6, r7];              \n" /* r7=sbox(r7)     */
        "orr           r1,            r1,    r7,lsl#16;\n" /* collect bytes   */
        /* block[ 7] = sbox[x3];                                              */
        "and           r7,            lr,    r9,lsr#24;\n" 
        "ldrb          r7,      [r6, r7];              \n" /* r7=sbox(r7)     */
        "orr           r1,            r1,    r7,lsl#24;\n" /* collect bytes   */
        /* block[ 8] = sbox[x8];                                              */
        "and           r2,            lr,          r11;\n" 
        "ldrb          r2,      [r6, r2];              \n" /* r7=sbox(r7)     */
        /* block[ 9] = sbox[x13];                                             */ 
        "and           r7,            lr,    r12,lsr#8;\n" 
        "ldrb          r7,      [r6, r7];              \n" /* r7=sbox(r7)     */
        "orr           r2,            r2,     r7,lsl#8;\n" /* collect bytes   */
        /* block[10] = sbox[x2];                                              */ 
        "and           r7,            lr,    r9,lsr#16;\n" 
        "ldrb          r7,      [r6, r7];              \n" /* r7=sbox(r7)     */
        "orr           r2,            r2,    r7,lsl#16;\n" /* collect bytes   */
        /* block[11] = sbox[x7];                                              */
        "and           r7,            lr,   r10,lsr#24;\n" 
        "ldrb          r7,      [r6, r7];              \n" /* r7=sbox(r7)     */
        "orr           r2,            r2,    r7,lsl#24;\n" /* collect bytes   */
        /* block[12] = sbox[x12];                                             */
        "and           r3,            lr,          r12;\n" 
        "ldrb          r3,      [r6, r3];              \n" /* r7=sbox(r7)     */
        /* block[13] = sbox[x1];                                              */ 
        "and           r7,            lr,     r9,lsr#8;\n" 
        "ldrb          r7,      [r6, r7];              \n" /* r7=sbox(r7)     */
        "orr           r3,            r3,     r7,lsl#8;\n" /* collect bytes   */
        /* block[14] = sbox[x6];                                              */ 
        "and           r7,            lr,   r10,lsr#16;\n" 
        "ldrb          r7,      [r6, r7];              \n" /* r7=sbox(r7)     */
        "orr           r3,            r3,    r7,lsl#16;\n" /* collect bytes   */
        /* block[15] = sbox[x11];                                             */
        "and           r7,            lr,   r11,lsr#24;\n" 
        "ldrb          r7,      [r6, r7];              \n" /* r7=sbox(r7)     */
        "orr           r3,            r3,    r7,lsl#24;\n" /* collect bytes   */
        /*--------------------------------------------------------------------*/
        /* while (loop_counter >0)                                            */
        /*--------------------------------------------------------------------*/
        "subs          r8,            r8,           #1;\n"
        "beq           encrypt_add_last_round;         \n"
        /*--------------------------------------------------------------------*/
        /* MixColumns                                                         */
        /*--------------------------------------------------------------------*/
        /* Column 1                                                           */
        /*--------------------------------------------------------------------*/
        /* tmp2 = block[0];                                                   */
        "and          r11,            lr,           r0;\n" /* tmp2=C0&0xff    */ 
        /* tmp3 = tmp2 ^ block[1];                                            */
        "and           r7,            lr,     r0,lsr#8;\n" /* r7=(C0>>8)&&0xff*/ 
        "eor          r12,           r11,           r7;\n" /* tmp3 = tmp2^r7  */
        /* tmp0 = block[2] ^ block[3];                                        */
        "and           r9,            lr,    r0,lsr#16;\n" /* tm0=(C0>>16)&&ff*/ 
        "eor           r9,            r9,    r0,lsr#24;\n" /* tmp0=tmp0^blk[3]*/
        /* tmp1 = tmp3 ^ tmp0; <-- block[0] ^ block[1] ^ block[2] ^ block[3]; */
        "eor          r10,            r9,          r12;\n" /* tmp1=tmp3^tmp0; */
        /* tmp3 = galois_mul2(tmp3);                                          */
        "lsls         r12,           r12,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[0] = block[0] ^ tmp3 ^ tmp1; -> tmp2^tmp3^tmp1               */
        "eor           r4,           r12,          r10;\n" /* a=tmp3^tmp1     */
        "eor           r4,            r4,          r11;\n" /* a=a^tmp2        */
        /* tmp3 = block[1]^block[2];                                          */
        "and          r12,            lr,    r0,lsr#16;\n" /* tmp3=block[2]   */ 
        "eor          r12,           r12,           r7;\n" /* tmp3=tmp3^r7    */
        /* tmp3 = galois_mul2(tmp3);                                          */
        "lsls         r12,           r12,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[1] = block[1] ^ tmp3 ^ tmp1;                                 */
        "eor          r12,           r12,           r7;\n" /* tmp3=tmp3^blk[1]*/
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "orr           r4,            r4,    r12,lsl#8;\n" /* a|=(tmp3<<8)    */
        /* tmp0 = galois_mul2(tmp0);                                          */
        "lsls          r9,            r9,          #25;\n" /* << 1: msb -> C  */
        "lsr           r9,            r9,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs         r9,            r9,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc         r9,            r9,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs         r9,            r9,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[2] = block[2] ^ tmp0 ^ tmp1;                                 */
        "and          r12,            lr,    r0,lsr#16;\n" /* tmp3=block[2]   */ 
        "eor          r12,           r12,           r9;\n" /* tmp3=tmp3^tmp0  */
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "orr           r4,            r4,   r12,lsl#16;\n" /* a|=(tmp3<<16)   */
        /* tmp2 = block[3]^tmp2;                                              */
        "eor          r11,           r11,    r0,lsr#24;\n" /* tmp2=tmp2^blk[3]*/
        /* tmp3 = galois_mul2(tmp2);                                          */
        "lsls         r12,           r11,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[3] = block[3] ^ tmp3 ^ tmp1; --> tmp2^tmp3^tmp1;             */
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "eor          r12,           r12,    r0,lsr#24;\n" /* t3=t3^(c0<<24)  */
        "orr           r0,            r4,   r12,lsl#24;\n" /* st0=a|(tmp3<<24)*/
        /*--------------------------------------------------------------------*/
        /* Column 2                                                           */
        /*--------------------------------------------------------------------*/
        /* tmp2 = block[4];                                                   */
        "and          r11,            lr,           r1;\n" /* tmp2=C0&0xff    */ 
        /* tmp3 = tmp2 ^ block[5];                                            */
        "and           r7,            lr,     r1,lsr#8;\n" /* r7=(C0>>8)&&0xff*/ 
        "eor          r12,           r11,           r7;\n" /* tmp3 = tmp2^r7  */
        /* tmp0 = block[6] ^ block[7];                                        */
        "and           r9,            lr,    r1,lsr#16;\n" /* tm0=(C0>>16)&&ff*/ 
        "eor           r9,            r9,    r1,lsr#24;\n" /* tmp0=tmp0^blk[3]*/
        /* tmp1 = tmp3 ^ tmp0; <-- block[4] ^ block[5] ^ block[6] ^ block[7]; */
        "eor          r10,            r9,          r12;\n" /* tmp1=tmp3^tmp0; */
        /* tmp3 = galois_mul2(tmp3);                                          */
        "lsls         r12,           r12,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[4] = block[4] ^ tmp3 ^ tmp1; -> tmp2^tmp3^tmp1               */
        "eor           r4,           r12,          r10;\n" /* a=tmp3^tmp1     */
        "eor           r4,            r4,          r11;\n" /* a=a^tmp2        */
        /* tmp3 = block[5]^block[6];                                          */
        "and          r12,            lr,    r1,lsr#16;\n" /* tmp3=block[6]   */ 
        "eor          r12,           r12,           r7;\n" /* tmp3=tmp3^r7    */
        /* tmp3 = galois_mul2(tmp3);                                          */
        "lsls         r12,           r12,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[5] = block[5] ^ tmp3 ^ tmp1;                                 */
        "eor          r12,           r12,           r7;\n" /* tmp3=tmp3^blk[1]*/
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "orr           r4,            r4,    r12,lsl#8;\n" /* a|=(tmp3<<8)    */
        /* tmp0 = galois_mul2(tmp0);                                          */
        "lsls          r9,            r9,          #25;\n" /* << 1: msb -> C  */
        "lsr           r9,            r9,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs         r9,            r9,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc         r9,            r9,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs         r9,            r9,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[6] = block[6] ^ tmp0 ^ tmp1;                                 */
        "and          r12,            lr,    r1,lsr#16;\n" /* tmp3=block[6]   */ 
        "eor          r12,           r12,           r9;\n" /* tmp3=tmp3^tmp0  */
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "orr           r4,            r4,   r12,lsl#16;\n" /* a|=(tmp3<<16)   */
        /* tmp2 = block[7]^tmp2;                                              */
        "eor          r11,           r11,    r1,lsr#24;\n" /* tmp2=tmp2^blk[3]*/
        /* tmp3 = galois_mul2(tmp2);                                          */
        "lsls         r12,           r11,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[7] = block[7] ^ tmp3 ^ tmp1; --> tmp2^tmp3^tmp1;             */
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "eor          r12,           r12,    r1,lsr#24;\n" /* t3=t3^(c0<<24)  */
        "orr           r1,            r4,   r12,lsl#24;\n" /* st0=a|(tmp3<<24)*/
        /*--------------------------------------------------------------------*/
        /* Column 3                                                           */
        /*--------------------------------------------------------------------*/
        /* tmp2 = block[8];                                                   */
        "and          r11,            lr,           r2;\n" /* tmp2=C0&0xff    */ 
        /* tmp3 = tmp2 ^ block[9];                                            */
        "and           r7,            lr,     r2,lsr#8;\n" /* r7=(C0>>8)&&0xff*/ 
        "eor          r12,           r11,           r7;\n" /* tmp3 = tmp2^r7  */
        /* tmp0 = block[10] ^ block[11];                                      */
        "and           r9,            lr,    r2,lsr#16;\n" /* tm0=(C0>>16)&&ff*/ 
        "eor           r9,            r9,    r2,lsr#24;\n" /* tmp0=tmp0^blk[3]*/
        /* tmp1 = tmp3 ^ tmp0; <- block[8] ^ block[9] ^ block[10] ^ block[11];*/
        "eor          r10,            r9,          r12;\n" /* tmp1=tmp3^tmp0; */
        /* tmp3 = galois_mul2(tmp3);                                          */
        "lsls         r12,           r12,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[8] = block[8] ^ tmp3 ^ tmp1; -> tmp2^tmp3^tmp1               */
        "eor           r4,           r12,          r10;\n" /* a=tmp3^tmp1     */
        "eor           r4,            r4,          r11;\n" /* a=a^tmp2        */
        /* tmp3 = block[9]^block[10];                                         */
        "and          r12,            lr,    r2,lsr#16;\n" /* tmp3=block[10]  */ 
        "eor          r12,           r12,           r7;\n" /* tmp3=tmp3^r7    */
        /* tmp3 = galois_mul2(tmp3);                                          */
        "lsls         r12,           r12,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[9] = block[9] ^ tmp3 ^ tmp1;                                 */
        "eor          r12,           r12,           r7;\n" /* tmp3=tmp3^blk[1]*/
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "orr           r4,            r4,    r12,lsl#8;\n" /* a|=(tmp3<<8)    */
        /* tmp0 = galois_mul2(tmp0);                                          */
        "lsls          r9,            r9,          #25;\n" /* << 1: msb -> C  */
        "lsr           r9,            r9,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs         r9,            r9,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc         r9,            r9,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs         r9,            r9,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[10] = block[10] ^ tmp0 ^ tmp1;                               */
        "and          r12,            lr,    r2,lsr#16;\n" /* tmp3=block[10]  */ 
        "eor          r12,           r12,           r9;\n" /* tmp3=tmp3^tmp0  */
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "orr           r4,            r4,   r12,lsl#16;\n" /* a|=(tmp3<<16)   */
        /* tmp2 = block[11]^tmp2;                                             */
        "eor          r11,           r11,    r2,lsr#24;\n" /* tmp2=tmp2^blk[3]*/
        /* tmp3 = galois_mul2(tmp2);                                          */
        "lsls         r12,           r11,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[11] = block[11] ^ tmp3 ^ tmp1; --> tmp2^tmp3^tmp1;           */
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "eor          r12,           r12,    r2,lsr#24;\n" /* t3=t3^(c0<<24)  */
        "orr           r2,            r4,   r12,lsl#24;\n" /* st0=a|(tmp3<<24)*/
        /*--------------------------------------------------------------------*/
        /* Column 4                                                           */
        /*--------------------------------------------------------------------*/
        /* tmp2 = block[12];                                                  */
        "and          r11,            lr,           r3;\n" /* tmp2=C0&0xff    */
        /* tmp3 = tmp2 ^ block[13];                                           */
        "and           r7,            lr,     r3,lsr#8;\n" /* r7=(C0>>8)&&0xff*/
        "eor          r12,           r11,           r7;\n" /* tmp3 = tmp2^r7  */
        /* tmp0 = block[14] ^ block[15];                                      */
        "and           r9,            lr,    r3,lsr#16;\n" /* tm0=(C0>>16)&&ff*/
        "eor           r9,            r9,    r3,lsr#24;\n" /* tmp0=tmp0^blk[3]*/
        /* tmp1 = tmp3 ^ tmp0; <- block[12]^block[13]^block[14]^block[15];    */
        "eor          r10,            r9,          r12;\n" /* tmp1=tmp3^tmp0; */
        /* tmp3 = galois_mul2(tmp3);                                          */
        "lsls         r12,           r12,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[12] = block[12] ^ tmp3 ^ tmp1; -> tmp2^tmp3^tmp1             */
        "eor           r4,           r12,          r10;\n" /* a=tmp3^tmp1     */
        "eor           r4,            r4,          r11;\n" /* a=a^tmp2        */
        /* tmp3 = block[13]^block[14];                                        */
        "and          r12,            lr,    r3,lsr#16;\n" /* tmp3=block[14]  */
        "eor          r12,           r12,           r7;\n" /* tmp3=tmp3^r7    */
        /* tmp3 = galois_mul2(tmp3);                                          */
        "lsls         r12,           r12,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[13] = block[13] ^ tmp3 ^ tmp1;                               */
        "eor          r12,           r12,           r7;\n" /* tmp3=tmp3^blk[1]*/
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "orr           r4,            r4,    r12,lsl#8;\n" /* a|=(tmp3<<8)    */
        /* tmp0 = galois_mul2(tmp0);                                          */
        "lsls          r9,            r9,          #25;\n" /* << 1: msb -> C  */
        "lsr           r9,            r9,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs         r9,            r9,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc         r9,            r9,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs         r9,            r9,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[14] = block[14] ^ tmp0 ^ tmp1;                               */
        "and          r12,            lr,    r3,lsr#16;\n" /* tmp3=block[14]  */
        "eor          r12,           r12,           r9;\n" /* tmp3=tmp3^tmp0  */
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "orr           r4,            r4,   r12,lsl#16;\n" /* a|=(tmp3<<16)   */
        /* tmp2 = block[15]^tmp2;                                             */
        "eor          r11,           r11,    r3,lsr#24;\n" /* tmp2=tmp2^blk[3]*/
        /* tmp3 = galois_mul2(tmp2);                                          */
        "lsls         r12,           r11,          #25;\n" /* << 1: msb -> C  */
        "lsr          r12,           r12,          #24;\n" /*                 */
#ifdef EQUALIZE_EXECUTION_TIME
        "ite           cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
        "eorcc        r12,           r12,        #0x00;\n" /* C?:nop          */
#else
        "it            cs;                             \n" /*                 */
        "eorcs        r12,           r12,        #0x1b;\n" /* C?:xor 0x1b:nop */
#endif
        /* block[15] = block[15] ^ tmp3 ^ tmp1; --> tmp2^tmp3^tmp1;           */
        "eor          r12,           r12,          r10;\n" /* tmp3=tmp3^tmp1  */
        "eor          r12,           r12,    r3,lsr#24;\n" /* t3=t3^(c0<<24)  */
        "orr           r3,            r4,   r12,lsl#24;\n" /* st0=a|(tmp3<<24)*/
        /*--------------------------------------------------------------------*/
        "b             encrypt_round_loop;             \n"
        /*--------------------------------------------------------------------*/
"encrypt_add_last_round:                               \n"
        /*--------------------------------------------------------------------*/
        /* AddRoundKey                                                        */
        /*--------------------------------------------------------------------*/
        "ldmia        r5!,      {r9-r12};              \n" /* ++              */ 
        "eor           r0,            r0,           r9;\n"  
        "eor           r1,            r1,          r10;\n"
        "eor           r2,            r2,          r11;\n"
        "eor           r3,            r3,          r12;\n"
        /*--------------------------------------------------------------------*/
        /* Store state                                                        */
        /*--------------------------------------------------------------------*/
        "ldmia        sp!,             {r4};           \n"
        "stmia         r4,          {r0-r3};           \n"
        /*--------------------------------------------------------------------*/
        /* Restore registers                                                  */
        /*--------------------------------------------------------------------*/
        "ldmia        sp!,      {r0-r12,lr};           \n" /*                 */
        /*--------------------------------------------------------------------*/
    :
    : [block] "r" (block), [roundKeys] "r" (roundKeys) 
); 
}

#else
/*----------------------------------------------------------------------------*/
/* Default c implementation                                                   */
/*----------------------------------------------------------------------------*/
/*
This file is part of the AVR-Crypto-Lib.
Copyright (C) 2008, 2009  Daniel Otte (daniel.otte@rub.de)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>

#include "cipher.h"
#include "constants.h"
#include "gmul_o.h"


#define GF256MUL_1(a) (a)
#define GF256MUL_2(a) (gmul_o(2, (a)))
#define GF256MUL_3(a) (gmul_o(3, (a)))


void aes_shiftcol(uint8_t *data, uint8_t shift)
{
    uint8_t tmp[4];

    
    tmp[0] = data[0];
    tmp[1] = data[4];
    tmp[2] = data[8];
    tmp[3] = data[12];
    
    data[0]  = tmp[(shift + 0) & 3];
    data[4]  = tmp[(shift + 1) & 3];
    data[8]  = tmp[(shift + 2) & 3];
    data[12] = tmp[(shift + 3) & 3];
}

static void aes_enc_round(uint8_t *block, uint8_t *roundKey)
{
    uint8_t tmp[16], t;
    uint8_t i;

    
    /* subBytes */
    for (i = 0; i < 16; ++i) 
    {
        tmp[i] = READ_SBOX_BYTE(sbox[block[i]]);
    }

    /* shiftRows */
    aes_shiftcol(tmp + 1, 1);
    aes_shiftcol(tmp + 2, 2);
    aes_shiftcol(tmp + 3, 3);
    
    /* mixColums */
    for (i = 0; i < 4; ++i) 
    {
        t = tmp[4 * i + 0] ^ tmp[4 * i + 1] ^ tmp[4 * i + 2] ^ tmp[4 * i + 3];
        
        block[4 * i + 0] =
            GF256MUL_2(tmp[4 * i + 0] ^ tmp[4 * i + 1])
            ^ tmp[4 * i + 0]
            ^ t;

        block[4 * i + 1] =
            GF256MUL_2(tmp[4 * i + 1] ^ tmp[4 * i + 2])
            ^ tmp[4 * i + 1]
            ^ t;

        block[4 * i + 2] =
            GF256MUL_2(tmp[4 * i + 2] ^ tmp[4 * i + 3])
            ^ tmp[4 * i + 2]
            ^ t;
        
        block[4 * i + 3] =
            GF256MUL_2(tmp[4 * i + 3] ^ tmp[4 * i + 0])
            ^ tmp[4 * i + 3]
            ^ t;
    }

    /* addKey */
    for (i = 0; i < 16; ++i) 
    {
        block[i] ^= READ_ROUND_KEY_BYTE(roundKey[i]);
    }
}

void aes_enc_lastround(uint8_t *block, uint8_t *roundKey)
{
    uint8_t i;
    

    /* subBytes */
    for (i = 0; i < 16; ++i) 
    {
        block[i] = READ_SBOX_BYTE(sbox[block[i]]);
    }

    /* shiftRows */
    aes_shiftcol(block + 1, 1);
    aes_shiftcol(block + 2, 2);
    aes_shiftcol(block + 3, 3);
    
    /* keyAdd */
    for (i = 0; i < 16; ++i) 
    {
        block[i] ^= READ_ROUND_KEY_BYTE(roundKey[i]);
    }
}

#include <stdio.h>

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    uint8_t i;

    for (i = 0; i < 16; ++i) 
    {
        block[i] ^= READ_ROUND_KEY_BYTE(roundKeys[i]);
    }

    for (i = 1; i < 10; ++i) 
    {
        aes_enc_round(block, roundKeys + 16 * i);
    }

    aes_enc_lastround(block, roundKeys + 16 * 10);
}
/*----------------------------------------------------------------------------*/
#endif
#endif
#endif
