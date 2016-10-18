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
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	asm volatile (\
		/*--------------------------------------------------------------------
		 * Macro - Round function
		 *--------------------------------------------------------------------*/
		".MACRO LEA_DecBlk_1Rnd V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15;\n"

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


#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
		"	SUBI R30, 0xF8;\n"
		"	SBCI R31, 0xFF;\n"
#else
		"	SUBI R30, 0xF4;\n"
		"	SBCI R31, 0xFF;\n"
#endif

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
		"	LPM R16, Z+;\n"
		"	LPM R17, Z+;\n"
		"	LPM R18, Z+;\n"
		"	LPM R19, Z+;\n"
		"	SBIW R30, 8;\n"
#else
		"	LD R19, -Z;\n"
		"	LD R18, -Z;\n"
		"	LD R17, -Z;\n"
		"	LD R16, -Z;\n"
#endif

		"	EOR R16, \\V12;\n"
		"	EOR R17, \\V13;\n"
		"	EOR R18, \\V14;\n"
		"	EOR R19, \\V15;\n"

		"	BST \\V0, 0;\n"
		"	LSR \\V3;\n"
		"	BLD \\V3, 7;\n"
		"	ROR \\V2;\n"
		"	ROR \\V1;\n"
		"	ROR \\V0;\n"

		"	SUB \\V1, R16;\n"
		"	SBC \\V2, R17;\n"
		"	SBC \\V3, R18;\n"
		"	SBC \\V0, R19;\n"

		"	EOR \\V1, R20;\n"
		"	EOR \\V2, R21;\n"
		"	EOR \\V3, R22;\n"
		"	EOR \\V0, R23;\n"

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
		"	LPM R16, Z+;\n"
		"	LPM R17, Z+;\n"
		"	LPM R18, Z+;\n"
		"	LPM R19, Z+;\n"
		"	SBIW R30, 8;\n"
#else
		"	LD R19, -Z;\n"
		"	LD R18, -Z;\n"
		"	LD R17, -Z;\n"
		"	LD R16, -Z;\n"
#endif

		"	EOR R16, \\V1;\n"
		"	EOR R17, \\V2;\n"
		"	EOR R18, \\V3;\n"
		"	EOR R19, \\V0;\n"

		"	CLR R24;\n"
		"	LSR \\V7;\n"
		"	ROR \\V6;\n"
		"	ROR \\V5;\n"
		"	ROR \\V4 ;\n"
		"	ROR R24 ;\n"

		"	LSR \\V7;\n"
		"	ROR \\V6;\n"
		"	ROR \\V5;\n"
		"	ROR \\V4 ;\n"
		"	ROR R24 ;\n"

		"	LSR \\V7;\n"
		"	ROR \\V6;\n"
		"	ROR \\V5;\n"
		"	ROR \\V4 ;\n"
		"	ROR R24 ;\n"

		"	EOR \\V7, R24;\n"

		"	SUB \\V7, R16;\n"
		"	SBC \\V4, R17;\n"
		"	SBC \\V5, R18;\n"
		"	SBC \\V6, R19;\n"

		"	EOR \\V7, R20;\n"
		"	EOR \\V4, R21;\n"
		"	EOR \\V5, R22;\n"
		"	EOR \\V6, R23;\n"

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
		"	LPM R16, Z+;\n"
		"	LPM R17, Z+;\n"
		"	LPM R18, Z+;\n"
		"	LPM R19, Z+;\n"
#else
		"	LD R19, -Z;\n"
		"	LD R18, -Z;\n"
		"	LD R17, -Z;\n"
		"	LD R16, -Z;\n"
#endif

		"	EOR R16, \\V7;\n"
		"	EOR R17, \\V4;\n"
		"	EOR R18, \\V5;\n"
		"	EOR R19, \\V6;\n"

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

		"	SUB \\V8, R16;\n"
		"	SBC \\V9, R17;\n"
		"	SBC \\V10, R18;\n"
		"	SBC \\V11, R19;\n"


		"	EOR \\V8, R20;\n"
		"	EOR \\V9, R21;\n"
		"	EOR \\V10, R22;\n"
		"	EOR \\V11, R23;\n"
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
		"	SUBI R30, 24 ;\n"
		"	SBCI R31, 0x0 ;\n"
#else
		"	SUBI R30, 20 ;\n"
		"	SBCI R31, 0x0 ;\n"
#endif
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
		"	SUBI R30, 0x90 ;\n"
		"	SBCI R31, 0xFE ;\n"
		"	LDI R25, 6 ;\n"

		/*--------------------------------------------------------------------
		 * Loop
		 *--------------------------------------------------------------------*/		
		"	LEA_DecBlk_1Rnd R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15;\n"
		"	LEA_DecBlk_1Rnd R12, R13, R14, R15, R1, R2, R3, R0, R7, R4, R5, R6, R8, R9, R10, R11;\n"
		"	LEA_DecBlk_1Rnd R8, R9, R10, R11, R13, R14, R15, R12, R0, R1, R2, R3, R7, R4, R5, R6;\n"
		"	LEA_DecBlk_1Rnd R7, R4, R5, R6, R9, R10, R11, R8, R12, R13, R14, R15, R0, R1, R2, R3;\n"
		
		"	LEA_DecBlk_1Rnd R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15;\n"
		"	LEA_DecBlk_1Rnd R12, R13, R14, R15, R1, R2, R3, R0, R7, R4, R5, R6, R8, R9, R10, R11;\n"
		"	LEA_DecBlk_1Rnd R8, R9, R10, R11, R13, R14, R15, R12, R0, R1, R2, R3, R7, R4, R5, R6;\n"
		"	LEA_DecBlk_1Rnd R7, R4, R5, R6, R9, R10, R11, R8, R12, R13, R14, R15, R0, R1, R2, R3;\n"
		
		"	LEA_DecBlk_1Rnd R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15;\n"
		"	LEA_DecBlk_1Rnd R12, R13, R14, R15, R1, R2, R3, R0, R7, R4, R5, R6, R8, R9, R10, R11;\n"
		"	LEA_DecBlk_1Rnd R8, R9, R10, R11, R13, R14, R15, R12, R0, R1, R2, R3, R7, R4, R5, R6;\n"
		"	LEA_DecBlk_1Rnd R7, R4, R5, R6, R9, R10, R11, R8, R12, R13, R14, R15, R0, R1, R2, R3;\n"
		
		"	LEA_DecBlk_1Rnd R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15;\n"
		"	LEA_DecBlk_1Rnd R12, R13, R14, R15, R1, R2, R3, R0, R7, R4, R5, R6, R8, R9, R10, R11;\n"
		"	LEA_DecBlk_1Rnd R8, R9, R10, R11, R13, R14, R15, R12, R0, R1, R2, R3, R7, R4, R5, R6;\n"
		"	LEA_DecBlk_1Rnd R7, R4, R5, R6, R9, R10, R11, R8, R12, R13, R14, R15, R0, R1, R2, R3;\n"
		
		"	LEA_DecBlk_1Rnd R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15;\n"
		"	LEA_DecBlk_1Rnd R12, R13, R14, R15, R1, R2, R3, R0, R7, R4, R5, R6, R8, R9, R10, R11;\n"
		"	LEA_DecBlk_1Rnd R8, R9, R10, R11, R13, R14, R15, R12, R0, R1, R2, R3, R7, R4, R5, R6;\n"
		"	LEA_DecBlk_1Rnd R7, R4, R5, R6, R9, R10, R11, R8, R12, R13, R14, R15, R0, R1, R2, R3;\n"

		"	LEA_DecBlk_1Rnd R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15;\n"
		"	LEA_DecBlk_1Rnd R12, R13, R14, R15, R1, R2, R3, R0, R7, R4, R5, R6, R8, R9, R10, R11;\n"
		"	LEA_DecBlk_1Rnd R8, R9, R10, R11, R13, R14, R15, R12, R0, R1, R2, R3, R7, R4, R5, R6;\n"
		"	LEA_DecBlk_1Rnd R7, R4, R5, R6, R9, R10, R11, R8, R12, R13, R14, R15, R0, R1, R2, R3;\n"

		/*--------------------------------------------------------------------
		 * Save result
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
		: [out] "x" (block), [in] "y" (block), [roundKeys] "z" (roundKeys)
	);
}

#elif defined(ARM)
void Decrypt(uint8_t *block, uint8_t *roundKeys)
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
		 *--------------------------------------------------------------------*/

		/*--------------------------------------------------------------------
		 * Init
		 *--------------------------------------------------------------------*/
		"STMDB           sp!,      {r0-r9};                          \n"
		"MOV              r9,     %[block];                          \n"
		"MOV              r0, %[roundKeys];                          \n"
		"LDM              r9,      {r5-r8};                          \n"

		"ADD              r0,         #384;                          \n"
		/*--------------------------------------------------------------------
		 * Round 1
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r8;            \n"
		"RSB              r5,           r1,           r5, ROR #9;    \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r3,           r3,           r5;            \n"
		"RSB              r6,           r3,           r6, ROR #27;   \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r4,           r4,           r6;            \n"
		"RSB              r7,           r4,           r7, ROR #29;   \n"
		"EOR              r7,           r2,           r7;            \n"

		/*--------------------------------------------------------------------
		 * Round 2
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r7;            \n"
		"RSB              r8,           r1,           r8, ROR #9;    \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r3,           r3,           r8;            \n"
		"RSB              r5,           r3,           r5, ROR #27;   \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r4,           r4,           r5;            \n"
		"RSB              r6,           r4,           r6, ROR #29;   \n"
		"EOR              r6,           r2,           r6;            \n"

		/*--------------------------------------------------------------------
		 * Round 3
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r6;            \n"
		"RSB              r7,           r1,           r7, ROR #9;    \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r3,           r3,           r7;            \n"
		"RSB              r8,           r3,           r8, ROR #27;   \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r4,           r4,           r8;            \n"
		"RSB              r5,           r4,           r5, ROR #29;   \n"
		"EOR              r5,           r2,           r5;            \n"

		/*--------------------------------------------------------------------
		 * Round 4
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r5;            \n"
		"RSB              r6,           r1,           r6, ROR #9;    \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r3,           r3,           r6;            \n"
		"RSB              r7,           r3,           r7, ROR #27;   \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r4,           r4,           r7;            \n"
		"RSB              r8,           r4,           r8, ROR #29;   \n"
		"EOR              r8,           r2,           r8;            \n"

		/*--------------------------------------------------------------------
		 * Round 5
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r8;            \n"
		"RSB              r5,           r1,           r5, ROR #9;    \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r3,           r3,           r5;            \n"
		"RSB              r6,           r3,           r6, ROR #27;   \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r4,           r4,           r6;            \n"
		"RSB              r7,           r4,           r7, ROR #29;   \n"
		"EOR              r7,           r2,           r7;            \n"

		/*--------------------------------------------------------------------
		 * Round 6
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r7;            \n"
		"RSB              r8,           r1,           r8, ROR #9;    \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r3,           r3,           r8;            \n"
		"RSB              r5,           r3,           r5, ROR #27;   \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r4,           r4,           r5;            \n"
		"RSB              r6,           r4,           r6, ROR #29;   \n"
		"EOR              r6,           r2,           r6;            \n"

		/*--------------------------------------------------------------------
		 * Round 7
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r6;            \n"
		"RSB              r7,           r1,           r7, ROR #9;    \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r3,           r3,           r7;            \n"
		"RSB              r8,           r3,           r8, ROR #27;   \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r4,           r4,           r8;            \n"
		"RSB              r5,           r4,           r5, ROR #29;   \n"
		"EOR              r5,           r2,           r5;            \n"

		/*--------------------------------------------------------------------
		 * Round 8
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r5;            \n"
		"RSB              r6,           r1,           r6, ROR #9;    \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r3,           r3,           r6;            \n"
		"RSB              r7,           r3,           r7, ROR #27;   \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r4,           r4,           r7;            \n"
		"RSB              r8,           r4,           r8, ROR #29;   \n"
		"EOR              r8,           r2,           r8;            \n"

		/*--------------------------------------------------------------------
		 * Round 9
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r8;            \n"
		"RSB              r5,           r1,           r5, ROR #9;    \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r3,           r3,           r5;            \n"
		"RSB              r6,           r3,           r6, ROR #27;   \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r4,           r4,           r6;            \n"
		"RSB              r7,           r4,           r7, ROR #29;   \n"
		"EOR              r7,           r2,           r7;            \n"

		/*--------------------------------------------------------------------
		 * Round 10
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r7;            \n"
		"RSB              r8,           r1,           r8, ROR #9;    \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r3,           r3,           r8;            \n"
		"RSB              r5,           r3,           r5, ROR #27;   \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r4,           r4,           r5;            \n"
		"RSB              r6,           r4,           r6, ROR #29;   \n"
		"EOR              r6,           r2,           r6;            \n"

		/*--------------------------------------------------------------------
		 * Round 11
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r6;            \n"
		"RSB              r7,           r1,           r7, ROR #9;    \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r3,           r3,           r7;            \n"
		"RSB              r8,           r3,           r8, ROR #27;   \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r4,           r4,           r8;            \n"
		"RSB              r5,           r4,           r5, ROR #29;   \n"
		"EOR              r5,           r2,           r5;            \n"

		/*--------------------------------------------------------------------
		 * Round 12
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r5;            \n"
		"RSB              r6,           r1,           r6, ROR #9;    \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r3,           r3,           r6;            \n"
		"RSB              r7,           r3,           r7, ROR #27;   \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r4,           r4,           r7;            \n"
		"RSB              r8,           r4,           r8, ROR #29;   \n"
		"EOR              r8,           r2,           r8;            \n"

		/*--------------------------------------------------------------------
		 * Round 13
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r8;            \n"
		"RSB              r5,           r1,           r5, ROR #9;    \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r3,           r3,           r5;            \n"
		"RSB              r6,           r3,           r6, ROR #27;   \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r4,           r4,           r6;            \n"
		"RSB              r7,           r4,           r7, ROR #29;   \n"
		"EOR              r7,           r2,           r7;            \n"

		/*--------------------------------------------------------------------
		 * Round 14
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r7;            \n"
		"RSB              r8,           r1,           r8, ROR #9;    \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r3,           r3,           r8;            \n"
		"RSB              r5,           r3,           r5, ROR #27;   \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r4,           r4,           r5;            \n"
		"RSB              r6,           r4,           r6, ROR #29;   \n"
		"EOR              r6,           r2,           r6;            \n"

		/*--------------------------------------------------------------------
		 * Round 15
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r6;            \n"
		"RSB              r7,           r1,           r7, ROR #9;    \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r3,           r3,           r7;            \n"
		"RSB              r8,           r3,           r8, ROR #27;   \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r4,           r4,           r8;            \n"
		"RSB              r5,           r4,           r5, ROR #29;   \n"
		"EOR              r5,           r2,           r5;            \n"

		/*--------------------------------------------------------------------
		 * Round 16
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r5;            \n"
		"RSB              r6,           r1,           r6, ROR #9;    \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r3,           r3,           r6;            \n"
		"RSB              r7,           r3,           r7, ROR #27;   \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r4,           r4,           r7;            \n"
		"RSB              r8,           r4,           r8, ROR #29;   \n"
		"EOR              r8,           r2,           r8;            \n"

		/*--------------------------------------------------------------------
		 * Round 17
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r8;            \n"
		"RSB              r5,           r1,           r5, ROR #9;    \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r3,           r3,           r5;            \n"
		"RSB              r6,           r3,           r6, ROR #27;   \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r4,           r4,           r6;            \n"
		"RSB              r7,           r4,           r7, ROR #29;   \n"
		"EOR              r7,           r2,           r7;            \n"

		/*--------------------------------------------------------------------
		 * Round 18
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r7;            \n"
		"RSB              r8,           r1,           r8, ROR #9;    \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r3,           r3,           r8;            \n"
		"RSB              r5,           r3,           r5, ROR #27;   \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r4,           r4,           r5;            \n"
		"RSB              r6,           r4,           r6, ROR #29;   \n"
		"EOR              r6,           r2,           r6;            \n"

		/*--------------------------------------------------------------------
		 * Round 19
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r6;            \n"
		"RSB              r7,           r1,           r7, ROR #9;    \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r3,           r3,           r7;            \n"
		"RSB              r8,           r3,           r8, ROR #27;   \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r4,           r4,           r8;            \n"
		"RSB              r5,           r4,           r5, ROR #29;   \n"
		"EOR              r5,           r2,           r5;            \n"

		/*--------------------------------------------------------------------
		 * Round 20
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r5;            \n"
		"RSB              r6,           r1,           r6, ROR #9;    \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r3,           r3,           r6;            \n"
		"RSB              r7,           r3,           r7, ROR #27;   \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r4,           r4,           r7;            \n"
		"RSB              r8,           r4,           r8, ROR #29;   \n"
		"EOR              r8,           r2,           r8;            \n"

		/*--------------------------------------------------------------------
		 * Round 21
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r8;            \n"
		"RSB              r5,           r1,           r5, ROR #9;    \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r3,           r3,           r5;            \n"
		"RSB              r6,           r3,           r6, ROR #27;   \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r4,           r4,           r6;            \n"
		"RSB              r7,           r4,           r7, ROR #29;   \n"
		"EOR              r7,           r2,           r7;            \n"

		/*--------------------------------------------------------------------
		 * Round 22
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r7;            \n"
		"RSB              r8,           r1,           r8, ROR #9;    \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r3,           r3,           r8;            \n"
		"RSB              r5,           r3,           r5, ROR #27;   \n"
		"EOR              r5,           r2,           r5;            \n"
		"EOR              r4,           r4,           r5;            \n"
		"RSB              r6,           r4,           r6, ROR #29;   \n"
		"EOR              r6,           r2,           r6;            \n"

		/*--------------------------------------------------------------------
		 * Round 23
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r6;            \n"
		"RSB              r7,           r1,           r7, ROR #9;    \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r3,           r3,           r7;            \n"
		"RSB              r8,           r3,           r8, ROR #27;   \n"
		"EOR              r8,           r2,           r8;            \n"
		"EOR              r4,           r4,           r8;            \n"
		"RSB              r5,           r4,           r5, ROR #29;   \n"
		"EOR              r5,           r2,           r5;            \n"

		/*--------------------------------------------------------------------
		 * Round 24
		 *--------------------------------------------------------------------*/
		"LDMDB           r0!,      {r1-r4};                          \n"
		"EOR              r1,           r1,           r5;            \n"
		"RSB              r6,           r1,           r6, ROR #9;    \n"
		"EOR              r6,           r2,           r6;            \n"
		"EOR              r3,           r3,           r6;            \n"
		"RSB              r7,           r3,           r7, ROR #27;   \n"
		"EOR              r7,           r2,           r7;            \n"
		"EOR              r4,           r4,           r7;            \n"
		"RSB              r8,           r4,           r8, ROR #29;   \n"
		"EOR              r8,           r2,           r8;            \n"

		/*--------------------------------------------------------------------
		 * Final
		 *--------------------------------------------------------------------*/
		"STM              r9,      {r5-r8};                          \n"
		"LDMIA           sp!,      {r0-r9};                          \n"

		: 
		: [block] "r" (block), [roundKeys] "r" (roundKeys)
	);
}

#else
#include "primitives.h"

#define RK(x, y) READ_ROUND_KEY_DOUBLE_WORD(x[y])

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t* blk = (uint32_t*) block;
	uint32_t* rk = (uint32_t*) roundKeys;
	
	uint32_t b0 = blk[0];
	uint32_t b1 = blk[1];
	uint32_t b2 = blk[2];
	uint32_t b3 = blk[3];
	
	// Round 1
	rk += 92;	
	b0 = (rotr(b0, 9) - (b3 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 5) - (b0 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 3) - (b1 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 2
	rk -= 4;
	b3 = (rotr(b3, 9) - (b2 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 5) - (b3 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 3) - (b0 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 3
	rk -= 4;
	b2 = (rotr(b2, 9) - (b1 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 5) - (b2 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 3) - (b3 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 4
	rk -= 4;
	b1 = (rotr(b1, 9) - (b0 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 5) - (b1 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 3) - (b2 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 5
	rk -= 4;	
	b0 = (rotr(b0, 9) - (b3 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 5) - (b0 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 3) - (b1 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 6
	rk -= 4;
	b3 = (rotr(b3, 9) - (b2 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 5) - (b3 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 3) - (b0 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 7
	rk -= 4;
	b2 = (rotr(b2, 9) - (b1 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 5) - (b2 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 3) - (b3 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 8
	rk -= 4;
	b1 = (rotr(b1, 9) - (b0 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 5) - (b1 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 3) - (b2 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 9
	rk -= 4;	
	b0 = (rotr(b0, 9) - (b3 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 5) - (b0 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 3) - (b1 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 10
	rk -= 4;
	b3 = (rotr(b3, 9) - (b2 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 5) - (b3 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 3) - (b0 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 11
	rk -= 4;
	b2 = (rotr(b2, 9) - (b1 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 5) - (b2 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 3) - (b3 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 12
	rk -= 4;
	b1 = (rotr(b1, 9) - (b0 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 5) - (b1 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 3) - (b2 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 13
	rk -= 4;	
	b0 = (rotr(b0, 9) - (b3 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 5) - (b0 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 3) - (b1 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 14
	rk -= 4;
	b3 = (rotr(b3, 9) - (b2 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 5) - (b3 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 3) - (b0 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 15
	rk -= 4;
	b2 = (rotr(b2, 9) - (b1 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 5) - (b2 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 3) - (b3 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 16
	rk -= 4;
	b1 = (rotr(b1, 9) - (b0 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 5) - (b1 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 3) - (b2 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 17
	rk -= 4;	
	b0 = (rotr(b0, 9) - (b3 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 5) - (b0 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 3) - (b1 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 18
	rk -= 4;
	b3 = (rotr(b3, 9) - (b2 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 5) - (b3 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 3) - (b0 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 19
	rk -= 4;
	b2 = (rotr(b2, 9) - (b1 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 5) - (b2 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 3) - (b3 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 20
	rk -= 4;
	b1 = (rotr(b1, 9) - (b0 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 5) - (b1 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 3) - (b2 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 21
	rk -= 4;	
	b0 = (rotr(b0, 9) - (b3 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 5) - (b0 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 3) - (b1 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 22
	rk -= 4;
	b3 = (rotr(b3, 9) - (b2 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 5) - (b3 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b1 = (rotl(b1, 3) - (b0 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 23
	rk -= 4;
	b2 = (rotr(b2, 9) - (b1 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 5) - (b2 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b0 = (rotl(b0, 3) - (b3 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	// Round 24
	rk -= 4;
	b1 = (rotr(b1, 9) - (b0 ^ RK(rk, RV0))) ^ RK(rk, RVC);
	b2 = (rotl(b2, 5) - (b1 ^ RK(rk, RV2))) ^ RK(rk, RVC);
	b3 = (rotl(b3, 3) - (b2 ^ RK(rk, RV4))) ^ RK(rk, RVC);
	
	blk[0] = b0;
	blk[1] = b1;
	blk[2] = b2;
	blk[3] = b3;
}

#endif
