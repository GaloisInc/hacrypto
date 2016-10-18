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
    r13:r16 : block value (lowest bytes)
    r17     : round counter
    r18-r21 : block value (highest bytes)
    r22:r23 : roundKeyss address
    r24:r26 : block address, then sbox base address
    r26:r27 : X
    r28:r29 : Y
    r30:r31 : Z
*/

// Xor a plaintext byte and a roundKey byte
// Y: plaintext base addr, X: roundKey base addr
// result in (destReg). r2 as intermediate reg. X pre-decremented
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
// roundKey is in Flash
#define DEC_ADDKEY(byteIdx, destReg) \
    "ldd r0, Y + "#byteIdx CR \
	"movw r30, r26" CR \
	"sbiw r30, 1" CR \
    "lpm "#destReg", Z" CR \
	"movw r26, r30" CR \
    "eor "#destReg", r0" CR
#else
// roundKey is in RAM
#define DEC_ADDKEY(byteIdx, destReg) \
    "ldd r0, Y + "#byteIdx CR \
    "ld "#destReg", -X" CR \
    "eor "#destReg", r0" CR
#endif

// Distribute bits in r18:r21 in r0 (half byte)
#define DEC_P_LAYER74 \
    "lsl r21" CR \
    "rol r0" CR \
    "lsl r20" CR \
    "rol r0" CR \
    "lsl r19" CR \
    "rol r0" CR \
    "lsl r18" CR \
    "rol r0" CR \

// Distribute bits in r13:r16 in r0 (half byte)
#define DEC_P_LAYER30 \
    "lsl r16" CR \
    "rol r0" CR \
    "lsl r15" CR \
    "rol r0" CR \
    "lsl r14" CR \
    "rol r0" CR \
    "lsl r13" CR \
    "rol r0" CR \

// Perform look-up table. Base address of the table is in
// r25:r24 and the index in the table is in r0. The output
// is returned in r0
#define DEC_LOOKUP \
    "movw r30, r24" CR \
    "add r30, r0" CR \
    "adc r31, r1" CR \
    "lpm r0, Z" CR

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	asm volatile(
		"push r29" CR
		"push r28" CR
		"push r17" CR
		"push r16" CR
		"push r15" CR
		"push r14" CR
		"push r13" CR

		"movw r26, %[roundKeys]" CR	// X <- rk addr
		"ldi r17, 1" CR
		"add r27, r17" CR			// X <- rk addr + 256
		"movw r28, %[block]" CR		// Y <- block addr
		"ldi r24, lo8(invsBox)" CR	// \ r24/r25 <= invsBox addr
		"ldi r25, hi8(invsBox)" CR	// /
		"ldi r17, 31" CR			// r17 <- 31 (31 iterations in loop)

		"loop_%=:" CR

		DEC_ADDKEY(7, r21)
		DEC_ADDKEY(6, r16)
		DEC_ADDKEY(5, r20)
		DEC_ADDKEY(4, r15)
		DEC_ADDKEY(3, r19)
		DEC_ADDKEY(2, r14)
		DEC_ADDKEY(1, r18)
		DEC_ADDKEY(0, r13)

		DEC_P_LAYER74
		DEC_P_LAYER74
		DEC_LOOKUP
		"std Y + 7, r0" CR
		DEC_P_LAYER74
		DEC_P_LAYER74
		DEC_LOOKUP
		"std Y + 6, r0" CR
		DEC_P_LAYER74
		DEC_P_LAYER74
		DEC_LOOKUP
		"std Y + 5, r0" CR
		DEC_P_LAYER74
		DEC_P_LAYER74
		DEC_LOOKUP
		"std Y + 4, r0" CR

		DEC_P_LAYER30
		DEC_P_LAYER30
		DEC_LOOKUP
		"std Y + 3, r0" CR
		DEC_P_LAYER30
		DEC_P_LAYER30
		DEC_LOOKUP
		"std Y + 2, r0" CR
		DEC_P_LAYER30
		DEC_P_LAYER30
		DEC_LOOKUP
		"std Y + 1, r0" CR
		DEC_P_LAYER30
		DEC_P_LAYER30
		DEC_LOOKUP
		"std Y + 0, r0" CR

        ////////////////////////////////////////////////////////////////////////
        // round counter management
        ////////////////////////////////////////////////////////////////////////
        "dec r17" CR            // decrement round counter
        "breq end_%=" CR
        "jmp loop_%=" CR
        "end_%=:" CR

		DEC_ADDKEY(7, r18)
		"std Y + 7, r18" CR
		DEC_ADDKEY(6, r18)
		"std Y + 6, r18" CR
		DEC_ADDKEY(5, r18)
		"std Y + 5, r18" CR
		DEC_ADDKEY(4, r18)
		"std Y + 4, r18" CR
		DEC_ADDKEY(3, r18)
		"std Y + 3, r18" CR
		DEC_ADDKEY(2, r18)
		"std Y + 2, r18" CR
		DEC_ADDKEY(1, r18)
		"std Y + 1, r18" CR
		DEC_ADDKEY(0, r18)
		"std Y + 0, r18" CR

		// restore context
		"pop r13" CR
		"pop r14" CR
		"pop r15" CR
		"pop r16" CR
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

/* Perform sbox substitution.
 * r12 used as temp register
 */
#define DEC_LOOKUP(src, dst) \
    "mov.b "#src", r12" CR \
    "swpb "#src CR \
    "mov.b "#src", "#src CR \
    "mov.b invsBox(r12), r12" CR \
    "mov.b invsBox("#src"), "#dst CR \
    "swpb "#dst CR \
    "xor.w r12, "#dst CR

/* Performs p laver
 * Input is r4-r7
 */
#define DEC_P_LAYER_STEP(reg) \
	"rla.w r7" CR \
	"rlc.w "#reg CR \
	"rla.w r6" CR \
	"rlc.w "#reg CR \
	"rla.w r5" CR \
	"rlc.w "#reg CR \
	"rla.w r4" CR \
	"rlc.w "#reg CR

#define DEC_P_LAYER(reg) \
    DEC_P_LAYER_STEP(reg) \
    DEC_P_LAYER_STEP(reg) \
    DEC_P_LAYER_STEP(reg) \
    DEC_P_LAYER_STEP(reg)


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	asm volatile(
		// save context
		"push r11" CR
		"push r10" CR
		"push r9" CR
		"push r8" CR
		"push r7" CR
		"push r6" CR
		"push r5" CR
		"push r4" CR
		"decd r1" CR

		// load block
		"mov.w 0(%[block]), r4" CR
		"mov.w 2(%[block]), r5" CR
		"mov.w 4(%[block]), r6" CR
		"mov.w 6(%[block]), r7" CR

		// load roundKey pointer
		"mov.w %[roundKeys], r13" CR
		"add.w #248, r13" CR

		// initialize round counter
		"mov.w #31, @r1" CR

		"loop_%=:" CR

		// round function
		"xor.w 6(r13), r7" CR
		"xor.w 4(r13), r6" CR
		"xor.w 2(r13), r5" CR
		"xor.w 0(r13), r4" CR
		DEC_P_LAYER(r11)
		DEC_P_LAYER(r10)
		DEC_P_LAYER(r9)
		DEC_P_LAYER(r8)
		DEC_LOOKUP(r8, r4)
		DEC_LOOKUP(r9, r5)
		DEC_LOOKUP(r10, r6)
		DEC_LOOKUP(r11, r7)

		// ajust roundKey pointer
		"sub.w #0x8, r13" CR

		// update round counter
		"mov.w @r1, r8" CR
		"dec.w r8" CR
		"mov.w r8, @r1" CR
		"jne loop_%=" CR

		// add last round key
		"xor.w 6(r13), r7" CR
		"xor.w 4(r13), r6" CR
		"xor.w 2(r13), r5" CR
		"xor.w 0(r13), r4" CR

		// save result
		"mov.w r4, 0(%[block])" CR
		"mov.w r5, 2(%[block])" CR
		"mov.w r6, 4(%[block])" CR
		"mov.w r7, 6(%[block])" CR

		// restore context
		"incd r1" CR
		"pop r4" CR
		"pop r5" CR
		"pop r6" CR
		"pop r7" CR
		"pop r8" CR
		"pop r9" CR
		"pop r10" CR
		"pop r11" CR
		:
		: [block] "r" (block), [roundKeys] "r" (roundKeys)
		: "r12", "r13"
	);
}

#endif /* MSP */

#ifdef ARM
/****************************************************************************** 
 * AVR
 ******************************************************************************/

/* Registers allocation:
	v1 : block (low)
	v2 : block (high)
	v3 : invSbox base address
	v4 : temp register
	v5 : intermediate block (low)
	v6 : intermediate block (high)
	v7 : pointer to roundKey
*/

// inverse p-layer for 1 byte
//  Input is in #src and output is #dst
#define DEC_P_LAYER(dst, src, idx) \
	"bfi "#dst", "#src", 0 + "#idx", 1" CR \
	"lsr "#src", "#src", #1" CR \
	"bfi "#dst", "#src", 4 + "#idx", 1" CR \
	"lsr "#src", "#src", #1" CR \
	"bfi "#dst", "#src", 8 + "#idx", 1" CR \
	"lsr "#src", "#src", #1" CR \
	"bfi "#dst", "#src", 12 + "#idx", 1" CR \
	"lsr "#src", "#src", #1" CR \
	"bfi "#dst", "#src", 16 + "#idx", 1" CR \
	"lsr "#src", "#src", #1" CR \
	"bfi "#dst", "#src", 20 + "#idx", 1" CR \
	"lsr "#src", "#src", #1" CR \
	"bfi "#dst", "#src", 24 + "#idx", 1" CR \
	"lsr "#src", "#src", #1" CR \
	"bfi "#dst", "#src", 28 + "#idx", 1" CR

// substitute byte #byteIdx from #src with invSbox
// and put result in byte #byteIdx in #dst
// Use v4 as temp. register. v3 contains the base
// address of invSbox
#define INV_SBOX(dst, src, byteIdx) \
	"ubfx v4, "#src", 8*"#byteIdx", 8" CR \
	"ldr v4, [v3, v4]" CR \
	"bfi "#dst", v4, 8*"#byteIdx", 8" CR

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	unsigned int roundCounter = 31;
	asm volatile(

		// load invSbox base address
		"ldr v3, =invsBox" CR

		// load block
		"ldm.w %[block], {v1, v2}" CR

		// load and adjust roundKey pointer
		"mov v7, %[roundKeys]" CR
		"add v7, #248" CR

		"loop_%=:"

		// add roundKey
		"ldr.w v4, [v7, #0]" CR
		"eor v1, v4" CR
		"ldr.w v4, [v7, #4]" CR
		"eor v2, v4" CR

		// adjust roundKey pointer
		"sub v7, #8" CR

		// inv p-layer
		DEC_P_LAYER(v5, v1, 0)
		"lsr v1, v1, #1" CR
		DEC_P_LAYER(v6, v1, 0)
		"lsr v1, v1, #1" CR
		DEC_P_LAYER(v5, v1, 1)
		"lsr v1, v1, #1" CR
		DEC_P_LAYER(v6, v1, 1)

		DEC_P_LAYER(v5, v2, 2)
		"lsr v2, v2, #1" CR
		DEC_P_LAYER(v6, v2, 2)
		"lsr v2, v2, #1" CR
		DEC_P_LAYER(v5, v2, 3)
		"lsr v2, v2, #1" CR
		DEC_P_LAYER(v6, v2, 3)

		// inv sbox
		INV_SBOX(v1, v5, 0)
		INV_SBOX(v1, v5, 1)
		INV_SBOX(v1, v5, 2)
		INV_SBOX(v1, v5, 3)
		INV_SBOX(v2, v6, 0)
		INV_SBOX(v2, v6, 1)
		INV_SBOX(v2, v6, 2)
		INV_SBOX(v2, v6, 3)

		// decrement counter and loop
		"subs %[roundCounter], #1" CR
		"bne loop_%=" CR

		// add last roundKey
		"ldr.w v4, [v7, #0]" CR
		"eor v1, v4" CR
		"ldr.w v4, [v7, #4]" CR
		"eor v2, v4" CR

		// save result
		"stm.w %[block], {v1, v2}" CR
	: [roundCounter] "+r" (roundCounter)
	: [block] "r" (block), [roundKeys] "r" (roundKeys)
	: "v1", "v2", "v3", "v4", "v5", "v6", "v7", "cc"
	);
}
#endif /* ARM */

#if !defined(AVR) && !defined(MSP) && !defined(ARM)
#error("Implemention only defined for AVR, MSP, and ARM")
#endif /* !AVR && !MSP && !ARM */
