/*
 *
 * National Security Research Institute
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 National Security Research Institute
 *
 * Written in 2015 by Ilwoong Jeong <iw98jeong@nsr.re.kr> and
 * Dongsoo Lee <letrhee@nsr.re.kr>
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

#if defined(AVR)
void Encrypt(uint8_t *block, uint8_t *roundKeys) {
	asm volatile (\
		/*--------------------------------------------------------------------
		 * Macro - Round function
		 *--------------------------------------------------------------------*/
		".MACRO LEA_EncBlk_1Rnd V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15;\n"

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
		"	LPM R16, Z+;\n"
		"	LPM R17, Z+;\n"
		"	LPM R18, Z+;\n"
		"	LPM R19, Z+;\n"
#else
		"	LD R16, Z+;\n"
		"	LD R17, Z+;\n"
		"	LD R18, Z+;\n"
		"	LD R19, Z+;\n"
#endif

		"	EOR \\V12, R16;\n"
		"	EOR \\V13, R17;\n"
		"	EOR \\V14, R18;\n"
		"	EOR \\V15, R19;\n"

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
		"	LPM R20, Z+;\n"
		"	LPM R21, Z+;\n"
		"	LPM R22, Z+;\n"
		"	LPM R23, Z+;\n"
#else
		"	LD R20, Z+;\n"
		"	LD R21, Z+;\n"
		"	LD R22, Z+;\n"
		"	LD R23, Z+;\n"
#endif

		"	EOR R20, \\V8;\n"
		"	EOR R21, \\V9;\n"
		"	EOR R22, \\V10;\n"
		"	EOR R23, \\V11;\n"

		"	ADD \\V12, R20;\n"
		"	ADC \\V13, R21;\n"
		"	ADC \\V14, R22;\n"
		"	ADC \\V15, R23;\n"

		"	CLR R20;\n"
		"	LSR \\V15;\n"
		"	ROR \\V14;\n"
		"	ROR \\V13;\n"
		"	ROR \\V12;\n"
		"	ROR R20;\n"

		"	LSR \\V15;\n"
		"	ROR \\V14;\n"
		"	ROR \\V13;\n"
		"	ROR \\V12;\n"
		"	ROR R20;\n"

		"	LSR \\V15;\n"
		"	ROR \\V14;\n"
		"	ROR \\V13;\n"
		"	ROR \\V12;\n"
		"	ROR R20;\n"

		"	EOR \\V15, R20;\n"

		"	EOR \\V8 , R16;\n"
		"	EOR \\V9 , R17;\n"
		"	EOR \\V10, R18;\n"
		"	EOR \\V11, R19;\n"

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
		"	LPM R20, Z+;\n"
		"	LPM R21, Z+;\n"
		"	LPM R22, Z+;\n"
		"	LPM R23, Z+;\n"
#else
		"	LD R20, Z+;\n"
		"	LD R21, Z+;\n"
		"	LD R22, Z+;\n"
		"	LD R23, Z+;\n"
#endif

		"	EOR R20, \\V4;\n"
		"	EOR R21, \\V5;\n"
		"	EOR R22, \\V6;\n"
		"	EOR R23, \\V7;\n"

		"	ADD \\V8 , R20;\n"
		"	ADC \\V9 , R21;\n"
		"	ADC \\V10, R22;\n"
		"	ADC \\V11, R23;\n"

		"	LSL \\V8;\n"
		"	ROL \\V9;\n"
		"	ROL \\V10;\n"
		"	ROL \\V11;\n"
		"	ADC \\V8, R28;\n"

		"	LSL \\V8;\n"
		"	ROL \\V9;\n"
		"	ROL \\V10;\n"
		"	ROL \\V11;\n"
		"	ADC \\V8, R28;\n"

		"	LSL \\V8;\n"
		"	ROL \\V9;\n"
		"	ROL \\V10;\n"
		"	ROL \\V11;\n"
		"	ADC \\V8, R28;\n"

		"	EOR \\V4 , R16;\n"
		"	EOR \\V5 , R17;\n"
		"	EOR \\V6 , R18;\n"
		"	EOR \\V7 , R19;\n"

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
		"	LPM R20, Z+;\n"
		"	LPM R21, Z+;\n"
		"	LPM R22, Z+;\n"
		"	LPM R23, Z+;\n"
#else
		"	LD R20, Z+;\n"
		"	LD R21, Z+;\n"
		"	LD R22, Z+;\n"
		"	LD R23, Z+;\n"
#endif

		"	EOR R20, \\V0;\n"
		"	EOR R21, \\V1;\n"
		"	EOR R22, \\V2;\n"
		"	EOR R23, \\V3;\n"

		"	ADD \\V4 , R20;\n"
		"	ADC \\V5 , R21;\n"
		"	ADC \\V6 , R22;\n"
		"	ADC \\V7 , R23;\n"

		"	LSL \\V4;\n"
		"	ROL \\V5;\n"
		"	ROL \\V6;\n"
		"	ROL \\V7;\n"
		"	ADC \\V4, R28;\n"
		".ENDM;\n"
		
		/*--------------------------------------------------------------------
		 * Macro - Reorder
		 *--------------------------------------------------------------------*/
		".MACRO LEA_EncReOrder;\n"
		"	MOV R29, R0;\n"
		"	MOV R0, R7;\n"
		"	MOV R7, R8;\n"
		"	MOV R8, R12;\n"
		"	MOV R12, R29;\n"

		"	MOV R29, R1;\n"
		"	MOV R1, R4;\n"
		"	MOV R4, R9;\n"
		"	MOV R9, R13;\n"
		"	MOV R13, R29;\n"

		"	MOV R29, R2;\n"
		"	MOV R2, R5;\n"
		"	MOV R5, R10;\n"
		"	MOV R10, R14;\n"
		"	MOV R14, R29;\n"

		"	MOV R29, R3;\n"
		"	MOV R3, R6;\n"
		"	MOV R6, R11;\n"
		"	MOV R11, R15;\n"
		"	MOV R15, R29;\n"
		".ENDM;\n"

		/*--------------------------------------------------------------------
		 * Save state
		 *--------------------------------------------------------------------*/
		"	PUSH R2 ;\n"
		"	PUSH R3 ;\n"
		"	PUSH R4 ;\n"
		"	PUSH R5 ;\n"
		"	PUSH R6 ;\n"
		"	PUSH R7 ;\n"
		"	PUSH R8 ;\n"
		"	PUSH R9 ;\n"
		"	PUSH R10;\n"
		"	PUSH R11;\n"
		"	PUSH R12;\n"
		"	PUSH R13;\n"
		"	PUSH R14;\n"
		"	PUSH R15;\n"
		"	PUSH R16;\n"
		"	PUSH R17;\n"
		"	PUSH R28;\n"
		"	PUSH R29;\n"

		/*--------------------------------------------------------------------
		 * Load block
		 *--------------------------------------------------------------------*/
		"	LD R0, Y+;\n"
		"	LD R1, Y+;\n"
		"	LD R2, Y+;\n"
		"	LD R3, Y+;\n"
		"	LD R4, Y+;\n"
		"	LD R5, Y+;\n"
		"	LD R6, Y+;\n"
		"	LD R7, Y+;\n"
		"	LD R8, Y+;\n"
		"	LD R9, Y+;\n"
		"	LD R10,Y+;\n"
		"	LD R11,Y+;\n"
		"	LD R12,Y+;\n"
		"	LD R13,Y+;\n"
		"	LD R14,Y+;\n"
		"	LD R15,Y+;\n"
		"	CLR R28;\n"

		/*--------------------------------------------------------------------
		 * Loop
		 *--------------------------------------------------------------------*/
		"LDI R25, 24;\n"
		"LEA_EncryptBlk_SubRound:\n"
		"	LEA_EncBlk_1Rnd R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15;\n"
		"   LEA_EncReOrder;\n"

		"	DEC R25;\n"
		"	BREQ LEA_EncryptBlk_Finish;\n"
		"	RJMP LEA_EncryptBlk_SubRound;\n"
		
		/*--------------------------------------------------------------------
		 * Final
		 *--------------------------------------------------------------------*/
		"LEA_EncryptBlk_Finish:\n"

		/*--------------------------------------------------------------------
		 * Store result
		 *--------------------------------------------------------------------*/
		"	ST X+,R0;\n"
		"	ST X+,R1;\n"
		"	ST X+,R2;\n"
		"	ST X+,R3;\n"
		"	ST X+,R4;\n"
		"	ST X+,R5;\n"
		"	ST X+,R6;\n"
		"	ST X+,R7;\n"
		"	ST X+,R8;\n"
		"	ST X+,R9;\n"
		"	ST X+,R10;\n"
		"	ST X+,R11;\n"
		"	ST X+,R12;\n"
		"	ST X+,R13;\n"
		"	ST X+,R14;\n"
		"	ST X+,R15;\n"

		/*--------------------------------------------------------------------
		 * Restore state
		 *--------------------------------------------------------------------*/
		"	CLR R1;\n"
		"	POP R29;\n"
		"	POP R28;\n"
		"	POP R17;\n"
		"	POP R16;\n"
		"	POP R15;\n"
		"	POP R14;\n"
		"	POP R13;\n"
		"	POP R12;\n"
		"	POP R11;\n"
		"	POP R10;\n"
		"	POP R9 ;\n"
		"	POP R8 ;\n"
		"	POP R7 ;\n"
		"	POP R6 ;\n"
		"	POP R5 ;\n"
		"	POP R4 ;\n"
		"	POP R3 ;\n"
		"	POP R2 ;\n"
		:
		: "x" (block), "y" (block), "z" (roundKeys)
	);
}

#elif defined(ARM)
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	asm volatile (\
		/*--------------------------------------------------------------------
		 * r0 - roundkey pointer
		 * r1 - roundkey 0
		 * r2 - roundkey 1, 3, 5
		 * r3 - roundkey 2
		 * r4 - roundkey 4
		 * r5 - block 0-3
		 * r6 - block 4-7
		 * r7 - block 8-11
		 * r8 - block 12-15
		 * r9 - block pointer
		 * r10 - loop counter
		 * r11 - temporary variable
		 *--------------------------------------------------------------------*/
		
		/*--------------------------------------------------------------------
		 * Init
		 *--------------------------------------------------------------------*/
		"STMDB           sp!,     {r0-r11};                          \n"
		"MOV              r9,     %[block];                          \n"
		"MOV              r0, %[roundKeys];                          \n"
		"LDM              r9,      {r5-r8};                          \n"

		/*--------------------------------------------------------------------
		 * START_LOOP
		 *--------------------------------------------------------------------*/
		"MOV             r10,          #24;                          \n"
		"enc_loop:                                                    \n"

		/*--------------------------------------------------------------------
		 * Round 1
		 *--------------------------------------------------------------------*/
		"LDMIA           r0!,      {r1-r4};                          \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r4,           r4,           r7;            \n"
		"ADD              r8,           r8,           r4;            \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r3,           r3,           r6;            \n"
		"ADD              r7,           r7,           r3;            \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r1,           r1,           r5;            \n"
		"ADD              r6,           r6,           r1;            \n"

		/*--------------------------------------------------------------------
		 * Reorder
		 *--------------------------------------------------------------------*/
		"MOV             r11,           r5;                          \n"
		"MOV              r5,           r6, ROR #23;                 \n"
		"MOV              r6,           r7, ROR #5;                  \n"
		"MOV              r7,           r8, ROR #3;                  \n"
		"MOV              r8,          r11;                          \n"

		/*--------------------------------------------------------------------
		 * END_LOOP
		 *--------------------------------------------------------------------*/
		"SUBS            r10,          r10,           #1;            \n"
		"BNE enc_loop;                                                \n"

		/*--------------------------------------------------------------------
		 * Final
		 *--------------------------------------------------------------------*/
		"STM              r9,      {r5-r8};                          \n"
		"LDMIA           sp!,     {r0-r11};                          \n"
		: 
		: [block] "r" (block), [roundKeys] "r" (roundKeys)
	);
}

#else
#include "primitives.h"

#define RK(x, y) READ_ROUND_KEY_DOUBLE_WORD(x[y])

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t* blk = (uint32_t*) block;
	uint32_t* rk = (uint32_t*) roundKeys;
	uint32_t tmp;
	int8_t i;
	
	uint32_t b0 = blk[0];
	uint32_t b1 = blk[1];
	uint32_t b2 = blk[2];
	uint32_t b3 = blk[3];
	
	for (i = 0; i < NUMBER_OF_ROUNDS; ++i, rk += 4) {
		b3 = rotr((b2 ^ RK(rk, RV4)) + (b3 ^ RK(rk, RVC)), 3);
		b2 = rotr((b1 ^ RK(rk, RV2)) + (b2 ^ RK(rk, RVC)), 5);
		b1 = rotl((b0 ^ RK(rk, RV0)) + (b1 ^ RK(rk, RVC)), 9);
		
		tmp = b0;
		b0 = b1;
		b1 = b2;
		b2 = b3;
		b3 = tmp;
	}
	
	blk[0] = b0;
	blk[1] = b1;
	blk[2] = b2;
	blk[3] = b3;
}

#endif
