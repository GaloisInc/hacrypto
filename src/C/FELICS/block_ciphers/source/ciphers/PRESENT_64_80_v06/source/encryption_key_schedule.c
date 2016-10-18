/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu>
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

#define CR "\n\t"

#ifdef AVR
/****************************************************************************** 
 * AVR
 ******************************************************************************/

/* Registers allocation:
    r1 : always 0
    r2:r3 : temp
    r11:r20 : rotated register
	r21     : round counter
    r22:r23 : roundKeys base address
    r24:r25 : key base address
    r26:r27 : X
    r28:r29 : Y
    r30:r31 : Z
*/


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	asm volatile(
		// save context
		"push r2" CR
		"push r3" CR
		"push r11" CR
		"push r12" CR
		"push r13" CR
		"push r14" CR
		"push r15" CR
		"push r16" CR
		"push r17" CR
		"push r28" CR
		"push r29" CR

		// Read key from mem and store it in registers
		"movw r26, %[key]" CR		// X <= key base addr
		"ld r11, X+" CR				// r12 <= k[0]
		"ld r12, X+" CR				// r13 <= k[1]
		"ld r13, X+" CR				// r14 <= k[2]
		"ld r14, X+" CR				// r15 <= k[3]
		"ld r15, X+" CR				// r16 <= k[4]
		"ld r16, X+" CR				// r17 <= k[5]
		"ld r17, X+" CR				// r18 <= k[6]
		"ld r18, X+" CR				// r19 <= k[7]
		"ld r19, X+" CR				// r20 <= k[8]
		"ld r20, X+" CR				// r21 <= k[9]

		// load X with roundKeys base address
		"movw r26, %[roundKeys]" CR	// X <= roundKeys base addr

		// load Z with sBox base address
		"ldi r28, lo8(sBox)" CR
		"ldi r29, hi8(sBox)" CR

		// initialize round counter
		"ldi r21, 1" CR			// 31 rounds

		"loop_%=:" CR

		// store round key from registers
		"st X+, r13" CR
		"st X+, r14" CR
		"st X+, r15" CR
		"st X+, r16" CR
		"st X+, r17" CR
		"st X+, r18" CR
		"st X+, r19" CR
		"st X+, r20" CR

		// shift right by 16 bits (i.e 2 bytes), using r2:r3 as temp reg
		"movw r2, r18" CR
		"mov r18, r20" CR
		"mov r19, r11" CR
		"mov r20, r12" CR
		"mov r11, r13" CR
		"movw r12, r14" CR
		"movw r14, r16" CR
		"movw r16, r2" CR

		// shift right by 2 bits, using r2 as temp reg
		"clr r2" CR
		"lsr r20" CR
		"ror r19" CR
		"ror r18" CR
		"ror r17" CR
		"ror r16" CR
		"ror r15" CR
		"ror r14" CR
		"ror r13" CR
		"ror r12" CR
		"ror r11" CR
		"ror r2" CR
		"or r20, r2" CR

		"clr r2" CR
		"lsr r20" CR
		"ror r19" CR
		"ror r18" CR
		"ror r17" CR
		"ror r16" CR
		"ror r15" CR
		"ror r14" CR
		"ror r13" CR
		"ror r12" CR
		"ror r11" CR
		"ror r2" CR
		"or r20, r2" CR

		// xor counter
		"eor r13, r21" CR

		// shift right by 1 bit, using r2 as temp reg
		"clr r2" CR
		"lsr r20" CR
		"ror r19" CR
		"ror r18" CR
		"ror r17" CR
		"ror r16" CR
		"ror r15" CR
		"ror r14" CR
		"ror r13" CR
		"ror r12" CR
		"ror r11" CR
		"ror r2" CR
		"or r20, r2" CR

		// lookup (input in r20, output in r30)
		"movw r30, r28" CR
		"add r30, r20" CR
		"adc r31, r1" CR
		"lpm r30, Z" CR

		// substitute high nibble of r21
		"andi r20, 0x0f" CR
		"andi r30, 0xf0" CR
		"or r20, r30" CR

		// increment round counter and loop if not done
		"cpi r21, 32" CR
		"breq end_%=" CR
		"inc r21" CR
		"jmp loop_%=" CR

		"end_%=:" CR
		// restore context
		"pop r29" CR
		"pop r28" CR
		"pop r17" CR
		"pop r16" CR
		"pop r15" CR
		"pop r14" CR
		"pop r13" CR
		"pop r12" CR
		"pop r11" CR
		"pop r3" CR
		"pop r2" CR
		:
		: [key] "r" (key), [roundKeys] "r" (roundKeys)
		: "r18", "r19", "r20", "r21", "r26", "r27", "r30", "r31"
	);
}
#endif /* AVR */

#ifdef MSP
/****************************************************************************** 
 * MSP
 ******************************************************************************/

/* Registers allocation:
	r11 : round counter
	r12 : temp register
	r13 : 
	r14 : pointer to roundKeys
	r15 : pointer to key
*/

// Rotate right r8-r4 by 1 bit
#define EKS_ROTATE_RIGHT \
	"clr.w r12" CR \
	"rra.w r8" CR \
	"rrc.w r7" CR \
	"rrc.w r6" CR \
	"rrc.w r5" CR \
	"rrc.w r4" CR \
	"rrc.w r12" CR \
	"and.w #0x7fff, r8" CR \
	"xor.w r12, r8" CR

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	asm volatile(
		"nop" CR
		// save context
		"push r4" CR
		"push r5" CR
		"push r6" CR
		"push r7" CR
		"push r8" CR
		"push r11" CR

		// initialize round counter
		"mov.w #1, r11" CR

		// initialize round key pointer
		"mov.w %[roundKeys], r13" CR

		// load key
		"mov.w 0(%[key]), r4" CR
		"mov.w 2(%[key]), r5" CR
		"mov.w 4(%[key]), r6" CR
		"mov.w 6(%[key]), r7" CR
		"mov.w 8(%[key]), r8" CR

		"loop_%=:" CR

		// save round key
		"mov.w r5, 0(r13)" CR
		"mov.w r6, 2(r13)" CR
		"mov.w r7, 4(r13)" CR
		"mov.w r8, 6(r13)" CR
		"add.w #8, r13" CR

		// shift right by 16 bits
		"mov.w r4, r12" CR
		"mov.w r5, r4" CR
		"mov.w r6, r5" CR
		"mov.w r7, r6" CR
		"mov.w r8, r7" CR
		"mov.w r12, r8" CR

		// shift right by 2 bits
		EKS_ROTATE_RIGHT
		EKS_ROTATE_RIGHT

		// xor with round counter
		"xor r11, r5" CR

		// shift right by 1 bit
		EKS_ROTATE_RIGHT

		// sbox on 4 MSbits
		"mov.w r8, r12" CR
		"swpb r12" CR
		"and.w #0x00f0, r12" CR
		"mov.b sBox(r12), r12" CR
		"swpb r12" CR
		"and.w #0xf000, r12" CR
		"and.w #0x0fff, r8" CR
		"xor.w r12, r8" CR

		// round counter management
		"inc.w r11" CR
		"cmp.w #0x32, r11" CR
		"jne loop_%=" CR

		// restore context
		"pop r11" CR
		"pop r8" CR
		"pop r7" CR
		"pop r6" CR
		"pop r5" CR
		"pop r4" CR
		:
		: [key] "r" (key), [roundKeys] "r" (roundKeys)
		: "r12", "r13"
	);
}

#endif /* MSP */

#ifdef ARM
/****************************************************************************** 
 * ARM
 ******************************************************************************/

/* Registers allocation:
	v3 : bits 79-48 of shift register
	v2 : bits 47-16 of shift register
	v1 : bits 15-0 of shift register
	v4 : temp. register
	v5 : pointer to roundKey
	v6 : pointer to sbox
*/

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	unsigned int roundCounter = 1;

	asm volatile(
		// load master key
		"ldrh v1, [%[key]]" CR
		"ldr v2, [%[key], #2]" CR
		"ldr v3, [%[key], #6]" CR

		// load roundKey pointer
		"mov v5, %[roundKeys]" CR

		"loop_%=:" CR

		// store roundKey
		"stm v5, {v2, v3}" CR

		// adjust roundKey pointer
		"add v5, v5, #8" CR

		// shift right by 19 bits
		"ubfx v4, v3, 0, 19" CR		// v4[18:0] <- v3[18:0]
		"lsr v3, v3, #19" CR		// v3 <- v3 >> 19
		"bfi v3, v1, 13, 16" CR		// v3[28:13] <- v1[15:0]
		"bfi v3, v2, 29, 3" CR		// v3[31:29] <- v2[2:0]
		"ubfx v1, v2, 3, 16" CR		// v1[15:0] <- v2[18:3]
		"lsr v2, v2, #19" CR		// v2 <- v2 >> 19
		"bfi v2, v4, 13, 19" CR		// v2[31:13] <- v4[18:0]

		// add round counter
		"eor v2, v2, %[roundCounter], lsr #1" CR
		"eor v1, v1, %[roundCounter], lsl #15" CR

		// sbox
		"ubfx v4, v3, 28 ,4" CR
		"ldr v6, =sBox" CR
		"ldr v4, [v6, v4] "CR
		"bfi v3, v4, 28, 4" CR

		// increment round counter and loop
		"add %[roundCounter], #1" CR
		"cmp %[roundCounter], #33" CR
		"bne loop_%=" CR

		: [roundCounter] "+r" (roundCounter)
		: [key] "r" (key), [roundKeys] "r" (roundKeys)
		: "v1", "v2", "v3", "v4", "v5", "v6", "cc"
	);
}

#endif /* ARM */

#if !defined(AVR) && !defined(MSP) && !defined(ARM)
#error("Implemention only defined for AVR, MSP, and ARM")
#endif /* !AVR && !MSP && !ARM */
