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
    r0 : temp
    r1 : always 0
    r2 : temp
    r4:r5 : block 4 and 6
    r17     : round counter
    r18-r21 : block value (4 bytes only)
    r22:r23 : roundKeyss address
    r24:r26 : block address, then sbox base address
    r26:r27 : X
    r28:r29 : Y
    r30:r31 : Z
*/

// Xor a plaintext byte and a roundKey byte
// Y: plaintext base addr, X: roundKey base addr
// result in r0. r2 as intermediate reg. X incremented
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
// roundKey is in Flash
#define ENC_ADDKEY(byteIdx) \
    "ldd r2, Y + "#byteIdx CR \
	"movw r30, r26" CR \
    "lpm r0, Z+" CR \
	"movw r26, r30" CR \
    "eor r0, r2" CR
#else
// roundKey is in RAM
#define ENC_ADDKEY(byteIdx) \
    "ldd r2, Y + "#byteIdx CR \
    "ld r0, X+" CR \
    "eor r0, r2" CR
#endif

// Lookup value r0 in table located at r25:r24
// result in r0. r1 must be 0
#define ENC_LOOKUP \
    "movw r30, r24" CR \
    "add r30, r0" CR \
    "adc r31, r1" CR \
    "lpm r0, Z" CR

// Distribute value in r0 in r18-r21
#define ENC_P_LAYER \
    "lsr r0" CR \
    "ror r18" CR \
    "lsr r0" CR \
    "ror r19" CR \
    "lsr r0" CR \
    "ror r20" CR \
    "lsr r0" CR \
    "ror r21" CR \
    "lsr r0" CR \
    "ror r18" CR \
    "lsr r0" CR \
    "ror r19" CR \
    "lsr r0" CR \
    "ror r20" CR \
    "lsr r0" CR \
    "ror r21" CR

#define ENC_STEP(byteIdx) \
    ENC_ADDKEY(byteIdx) \
    ENC_LOOKUP \
    ENC_P_LAYER

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	asm volatile(
		"push r29" CR
		"push r28" CR
		"push r17" CR
		"push r5" CR
		"push r4" CR
		"push r2" CR
		"ldi r17, 31" CR		// r17 <= 31 (31 iterations in loop)
		"movw r28, %[block]" CR		// Y <- block addr
		"movw r26, %[roundKeys]" CR		// X <- rk addr
		"ldi r24, lo8(sBox)" CR // \ r24/r25 <= sBox addr
		"ldi r25, hi8(sBox)" CR // /

		"loop_%=:" CR

		ENC_STEP(0)
		ENC_STEP(1)
		ENC_STEP(2)
		ENC_STEP(3)

        ////////////////////////////////////////////////////////////////////////
		// store even registers
        ////////////////////////////////////////////////////////////////////////
		"std Y + 0, r18" CR
		"std Y + 2, r19" CR
		"movw r4, r20" CR

		ENC_STEP(4)
		ENC_STEP(5)
		ENC_STEP(6)
		ENC_STEP(7)

        ////////////////////////////////////////////////////////////////////////
		// store odd registers
        ////////////////////////////////////////////////////////////////////////
		"std Y + 1, r18" CR
		"std Y + 3, r19" CR
		"std Y + 5, r20" CR
		"std Y + 7, r21" CR
		"std Y + 4, r4" CR
		"std Y + 6, r5" CR

        ////////////////////////////////////////////////////////////////////////
		// round counter management
        ////////////////////////////////////////////////////////////////////////
		"dec r17" CR 			// decrement round counter
		"breq end_%=" CR
		"jmp loop_%=" CR
		"end_%=:" CR

		ENC_ADDKEY(0)
		"std Y + 0, r0" CR
		ENC_ADDKEY(1)
		"std Y + 1, r0" CR
		ENC_ADDKEY(2)
		"std Y + 2, r0" CR
		ENC_ADDKEY(3)
		"std Y + 3, r0" CR
		ENC_ADDKEY(4)
		"std Y + 4, r0" CR
		ENC_ADDKEY(5)
		"std Y + 5, r0" CR
		ENC_ADDKEY(6)
		"std Y + 6, r0" CR
		ENC_ADDKEY(7)
		"std Y + 7, r0" CR

		// restore context
		"pop r2" CR
		"pop r4" CR
		"pop r5" CR
		"pop r17" CR
		"pop r28" CR
		"pop r29" CR
		:
		: [block] "r" (block), [roundKeys] "r" (roundKeys)
		: "r0", "r18", "r19", "r20", "r21", "r24", "r25", "r26", "r27", "r30", "r31"
	);
}
#endif /* AVR */

#ifdef MSP
/****************************************************************************** 
 * MSP
 ******************************************************************************/

/* Registers allocation:
	r4-r7 : block value
	r8-r11: temp block
	r12 : temp register
	r13 : pointer to roundKey bytes
	r14 : pointer to roundKeys arg
	r15 : pointer to block arg
*/

/* Perform xor between block and roundKey.
 * RoundKey pointer is r13. It is automatically incremented
 */
#define ENC_ADDKEY(reg) \
	"xor.w @r13+, "#reg CR

/* Perform sbox substitution.
 * r12 used as temp register
 */
#define ENC_LOOKUP(src, dst) \
	"mov.b "#src", r12" CR \
	"swpb "#src CR \
	"mov.b "#src", "#src CR \
	"mov.b sBox(r12), r12" CR \
	"mov.b sBox("#src"), "#dst CR \
	"swpb "#dst CR \
	"xor.w r12, "#dst CR

/* Performs p laver
 * Output is r4-r7
 */
#define ENC_P_LAYER_STEP(reg) \
	"rra.w "#reg CR \
	"rrc.w r4" CR \
	"rra.w "#reg CR \
	"rrc.w r5" CR \
	"rra.w "#reg CR \
	"rrc.w r6" CR \
	"rra.w "#reg CR \
	"rrc.w r7" CR

#define ENC_P_LAYER(reg) \
	ENC_P_LAYER_STEP(reg) \
	ENC_P_LAYER_STEP(reg) \
	ENC_P_LAYER_STEP(reg) \
	ENC_P_LAYER_STEP(reg)

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	asm volatile(
		// save context
		"push r4" CR
		"push r5" CR
		"push r6" CR
		"push r7" CR
		"push r8" CR
		"push r9" CR
		"push r10" CR
		"push r11" CR
		"decd r1" CR // make some place for round counter

		// load roundKey pointer
		"mov.w %[roundKeys], r13" CR

		// load block
		"mov.w 0(%[block]), r4" CR
		"mov.w 2(%[block]), r5" CR
		"mov.w 4(%[block]), r6" CR
		"mov.w 6(%[block]), r7" CR

		// initialize round counter
		"mov.w #31, @r1" CR

		"loop_%=:" CR

		// round function
		ENC_ADDKEY(r4)
		ENC_LOOKUP(r4, r8)
		ENC_ADDKEY(r5)
		ENC_LOOKUP(r5, r9)
		ENC_ADDKEY(r6)
		ENC_LOOKUP(r6, r10)
		ENC_ADDKEY(r7)
		ENC_LOOKUP(r7, r11)
		ENC_P_LAYER(r8)
		ENC_P_LAYER(r9)
		ENC_P_LAYER(r10)
		ENC_P_LAYER(r11)

		// update loop counter and branch
		"mov.w @r1, r8" CR
		"dec.w r8" CR
		"mov.w r8, @r1" CR
		"jne loop_%=" CR

		// add last round key
		ENC_ADDKEY(r4)
		ENC_ADDKEY(r5)
		ENC_ADDKEY(r6)
		ENC_ADDKEY(r7)

		// save result (for debug)
		"mov.w r4, 0(%[block])" CR
		"mov.w r5, 2(%[block])" CR
		"mov.w r6, 4(%[block])" CR
		"mov.w r7, 6(%[block])" CR

		// restore context
		"incd r1" CR
		"pop r11" CR
		"pop r10" CR
		"pop r9" CR
		"pop r8" CR
		"pop r7" CR
		"pop r6" CR
		"pop r5" CR
		"pop r4" CR
		:
		: [block] "r" (block), [roundKeys] "r" (roundKeys)
		: "r12", "r13"
	);
}

#endif /* MSP */

#ifdef ARM
/****************************************************************************** 
 * ARM (cortex M3)
 ******************************************************************************/

/* Registers allocation:
	v1 : block (low)
	v2 : block (high)
	v3 : sbox base addr
	v4 : temp reg
	v5 : intermediate block (low)
	v6 : intermediate block (high)
	v7 : round counter
	v8 : pointer to roundKey
*/

// Combine sbox and p-layer.
// Use v4 as temp. register. v3 contains the address of sBox
// Result in v5 and v6
#define SBOX_PLAYER_BYTE(src, byteIdx, dstIdx) \
	"ubfx v4, "#src", 8*"#byteIdx", 8" CR \
	"ldr v4, [v3, v4]" CR \
	"bfi v5, v4, 0 + 2*"#dstIdx", 1" CR \
	"lsr v4, v4, #1" CR \
	"bfi v5, v4, 16 + 2*"#dstIdx", 1" CR \
	"lsr v4, v4, #1" CR \
	"bfi v6, v4, 0 + 2*"#dstIdx", 1" CR \
	"lsr v4, v4, #1" CR \
	"bfi v6, v4, 16 + 2*"#dstIdx", 1" CR \
	"lsr v4, v4, #1" CR \
	"bfi v5, v4, 1 + 2*"#dstIdx", 1" CR \
	"lsr v4, v4, #1" CR \
	"bfi v5, v4, 17 + 2*"#dstIdx", 1" CR \
	"lsr v4, v4, #1" CR \
	"bfi v6, v4, 1 + 2*"#dstIdx", 1" CR \
	"lsr v4, v4, #1" CR \
	"bfi v6, v4, 17 + 2*"#dstIdx", 1" CR

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	unsigned int loopCounter = 31;

	asm volatile(
		// load block
		"ldm.w %[block], {v1, v2}" CR

		// load sbox pointer
		"ldr v3, =sBox" CR

		// load roundKey pointer
		"mov v7, %[roundKeys]" CR

		"loop_%=:" CR

		// add roundKey
		"ldr.w v4, [v7, 0]" CR
		"eor v1, v4" CR
		"ldr.w v4, [v7, #4]" CR
		"eor v2, v4" CR

		// update roundKey pointer
		"add v7, #8" CR

		// sbox combined with p-layer
		SBOX_PLAYER_BYTE(v1, 0, 0)	// bits 0-7
		SBOX_PLAYER_BYTE(v1, 1, 1)	// bits 8-15
		SBOX_PLAYER_BYTE(v1, 2, 2)	// bits 16-23
		SBOX_PLAYER_BYTE(v1, 3, 3)	// bits 24-31
		SBOX_PLAYER_BYTE(v2, 0, 4)	// bits 32-39
		SBOX_PLAYER_BYTE(v2, 1, 5)	// bits 40-47
		SBOX_PLAYER_BYTE(v2, 2, 6)	// bits 48-55
		SBOX_PLAYER_BYTE(v2, 3, 7)	// bits 56-63
		"mov.w v1, v5" CR
		"mov.w v2, v6" CR

		// decrement round counter and loop
		"subs %[loopCounter], #1" CR
		"bne.w loop_%=" CR

		// add last roundKey
		"ldr.w v4, [v7, 0]" CR
		"eor v1, v4" CR
		"ldr.w v4, [v7, #4]" CR
		"eor v2, v4" CR

		// save block
		"stm.w %[block], {v1, v2}" CR

		: [loopCounter] "+r" (loopCounter)
		: [block] "r" (block), [roundKeys] "r" (roundKeys)
		: "v1", "v2", "v3", "v4", "v5", "v6", "v7", "cc"
	);
}

#endif /* ARM */

#if !defined(AVR) && !defined(MSP) && !defined(ARM)
#error("Implemention only defined for AVR, MSP, and ARM")
#endif /* !AVR && !MSP && !ARM */
