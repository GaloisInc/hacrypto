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
#include <string.h>

#include "cipher.h"
#include "constants.h"

#if defined(AVR)

void RunEKS(uint8_t *key, uint8_t *roundKeys, uint32_t *delta) {
	asm volatile (\
		/*--------------------------------------------------------------------
		 * Macro
		 *--------------------------------------------------------------------*/
		".MACRO KeyU32_Body T1, T2, T3, T4;\n"
		"	ADD \\T1, R22;\n"
		"	ADC \\T2, R23;\n"
		"	ADC \\T3, R24;\n"
		"	ADC \\T4, R25;\n"
		"	LSL R22;\n"
		"	ROL R23;\n"
		"	ROL R24;\n"
		"	ROL R25;\n"
		"	ADC R22, R1;\n"
		".ENDM;\n"

		/*--------------------------------------------------------------------
		 * Macro - ROL1
		 *--------------------------------------------------------------------*/
		".MACRO KeyU32_ROL1 T1, T2, T3, T4;\n"
		"	LSL \\T1;\n"
		"	ROL \\T2;\n"
		"	ROL \\T3;\n"
		"	ROL \\T4;\n"
		"	ADC \\T1, R1;\n"
		".ENDM;\n"

		/*--------------------------------------------------------------------
		 * Macro - ROL8
		 *--------------------------------------------------------------------*/
		".MACRO KeyU32_ROL8 T1, T2, T3, T4;\n"
		"	MOV R0, \\T4;\n"
		"	MOV \\T4, \\T3;\n"
		"	MOV \\T3, \\T2;\n"
		"	MOV \\T2, \\T1;\n"
		"	MOV \\T1, R0;\n"
		".ENDM;\n"

		/*--------------------------------------------------------------------
		 * Macro - ROL3
		 *--------------------------------------------------------------------*/
		".MACRO KeyU32_ROL3 T1, T2, T3, T4;\n"
		"	KeyU32_ROL1 \\T1, \\T2, \\T3, \\T4;\n"
		"	KeyU32_ROL1 \\T1, \\T2, \\T3, \\T4;\n"
		"	KeyU32_ROL1 \\T1, \\T2, \\T3, \\T4;\n"
		".ENDM;\n"

		/*--------------------------------------------------------------------
		 * Macro - ROL6
		 *--------------------------------------------------------------------*/
		".MACRO KeyU32_ROL6 T1, T2, T3, T4;\n"
		"	KeyU32_ROL8 \\T1, \\T2, \\T3, \\T4;\n"
		"	CLR R0;\n"
		"	LSR \\T4;\n"
		"	ROR \\T3;\n"
		"	ROR \\T2;\n"
		"	ROR \\T1;\n"
		"	ROR R0;\n"
		"	LSR \\T4;\n"
		"	ROR \\T3;\n"
		"	ROR \\T2;\n"
		"	ROR \\T1;\n"
		"	ROR R0;\n"
		"	EOR \\T4, R0;\n"
		".ENDM;\n"

		/*--------------------------------------------------------------------
		 * Macro - ROL11
		 *--------------------------------------------------------------------*/
		".MACRO KeyU32_ROL11 T1, T2, T3, T4;\n"
		"	KeyU32_ROL8 \\T1, \\T2, \\T3, \\T4;\n"
		"	KeyU32_ROL3 \\T1, \\T2, \\T3, \\T4;\n"
		".ENDM;\n"

		/*--------------------------------------------------------------------
		 * Save state
		 *--------------------------------------------------------------------*/
		"	PUSH R2;\n"
		"	PUSH R3;\n"
		"	PUSH R4;\n"
		"	PUSH R5;\n"
		"	PUSH R6;\n"
		"	PUSH R7;\n"
		"	PUSH R8;\n"
		"	PUSH R9;\n"
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

		"	LDI R19, 4;\n"
		"	LDI R20, 24;\n"
		
		/*--------------------------------------------------------------------
		 * Load key
		 *--------------------------------------------------------------------*/
		"	LD R2, X+;\n"
		"	LD R3, X+;\n"
		"	LD R4, X+;\n"
		"	LD R5, X+;\n"
		"	LD R6, X+;\n"
		"	LD R7, X+;\n"
		"	LD R8, X+;\n"
		"	LD R9, X+;\n"
		"	LD R10, X+;\n"
		"	LD R11, X+;\n"
		"	LD R12, X+;\n"
		"	LD R13, X+;\n"
		"	LD R14, X+;\n"
		"	LD R15, X+;\n"
		"	LD R16, X+;\n"
		"	LD R17, X+;\n"

		/*--------------------------------------------------------------------
		 * Loop
		 *--------------------------------------------------------------------*/
		"KeyLoop:\n"

		"	LD R22, Z;\n"
		"	LDD R23, Z+1;\n"
		"	LDD R24, Z+2;\n"
		"	LDD R25, Z+3;\n"

		"	KeyU32_Body R2, R3, R4, R5;\n"
		"	KeyU32_ROL1 R2, R3, R4, R5;\n"
		"	STD Y+12, R2;\n"
		"	STD Y+13, R3;\n"
		"	STD Y+14, R4;\n"
		"	STD Y+15, R5;\n"

		"	KeyU32_Body R6, R7, R8, R9;\n"
		"	KeyU32_ROL3 R6, R7, R8, R9;\n"
		"	STD Y+0, R6;\n"
		"	STD Y+1, R7;\n"
		"	STD Y+2, R8;\n"
		"	STD Y+3, R9;\n"

		"	KeyU32_Body R10, R11, R12, R13;\n"
		"	KeyU32_ROL6 R10, R11, R12, R13;\n"
		"	STD Y+8, R10;\n"
		"	STD Y+9, R11;\n"
		"	STD Y+10, R12;\n"
		"	STD Y+11, R13;\n"

		"	KeyU32_Body R14, R15, R16, R17;\n"
		"	KeyU32_ROL11 R14, R15, R16, R17;\n"
		"	STD Y+4, R14;\n"
		"	STD Y+5, R15;\n"
		"	STD Y+6, R16;\n"
		"	STD Y+7, R17;\n"

		"	DEC R20;\n"
		"	BREQ KeyEnd;\n"

		"	ADIW R28, 16;\n"

		"	ST Z+, R22;\n"
		"	ST Z+, R23;\n"
		"	ST Z+, R24;\n"
		"	ST Z+, R25;\n"

		"	DEC R19;\n"
		"	BREQ Delta_Reset;\n"
		"	RJMP KeyLoop;\n"

		"Delta_Reset:\n"
		"	LDI R19, 4;\n"
		"	SUBI R30, 16;\n"
		"	SBCI R31, 0;\n"
		"	RJMP KeyLoop;\n"

		/*--------------------------------------------------------------------
		 * Restore state
		 *--------------------------------------------------------------------*/
		"KeyEnd:\n"
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
		"	POP R9;\n"
		"	POP R8;\n"
		"	POP R7;\n"
		"	POP R6;\n"
		"	POP R5;\n"
		"	POP R4;\n"
		"	POP R3;\n"
		"	POP R2;\n"
		:
		: "x" (key), "y" (roundKeys), "z" (delta)
	);
}

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint32_t td[4];
	
	td[0] = READ_RAM_DATA_DOUBLE_WORD(DELTA[0]);
	td[1] = READ_RAM_DATA_DOUBLE_WORD(DELTA[1]);
	td[2] = READ_RAM_DATA_DOUBLE_WORD(DELTA[2]);
	td[3] = READ_RAM_DATA_DOUBLE_WORD(DELTA[3]);
	
	RunEKS(key, roundKeys, td);
}

#elif defined(ARM)
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	asm volatile (\
		/*--------------------------------------------------------------------
		 * r0 - roundkey pointer
		 * r1 - roundkey 0
		 * r2 - roundkey 1, 3, 5
		 * r3 - roundkey 2
		 * r4 - roundkey 4
		 * r5 - delta 0-3
		 * r6 - delta 4-7
		 * r7 - delta 8-11
		 * r8 - delta 12-15
		 * r9 - temp
		 * r10 - temp
		 *--------------------------------------------------------------------*/
		 
		/*--------------------------------------------------------------------
		 * Init
		 *--------------------------------------------------------------------*/
		"STMDB           sp!,     {r0-r10};                          \n"
		"MOV              r9,       %[key];                          \n"
		"MOV             r10,     %[delta];                          \n"
		"MOV              r0, %[roundKeys];                          \n"
		"LDM              r9,      {r1-r4};                          \n"
		"LDM             r10,      {r5-r8};                          \n"

		/*--------------------------------------------------------------------
		 * Round1
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r5;            \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r5, ROR #31;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r5, ROR #30;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r5, ROR #29;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round2
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r6, ROR #31;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r6, ROR #30;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r6, ROR #29;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r6, ROR #28;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round3
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r7, ROR #30;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r7, ROR #29;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r7, ROR #28;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r7, ROR #27;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round4
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r8, ROR #29;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r8, ROR #28;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r8, ROR #27;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r8, ROR #26;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round5
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r5, ROR #28;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r5, ROR #27;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r5, ROR #26;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r5, ROR #25;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round6
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r6, ROR #27;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r6, ROR #26;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r6, ROR #25;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r6, ROR #24;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round7
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r7, ROR #26;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r7, ROR #25;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r7, ROR #24;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r7, ROR #23;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round8
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r8, ROR #25;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r8, ROR #24;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r8, ROR #23;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r8, ROR #22;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round9
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r5, ROR #24;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r5, ROR #23;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r5, ROR #22;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r5, ROR #21;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round10
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r6, ROR #23;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r6, ROR #22;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r6, ROR #21;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r6, ROR #20;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round11
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r7, ROR #22;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r7, ROR #21;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r7, ROR #20;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r7, ROR #19;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round12
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r8, ROR #21;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r8, ROR #20;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r8, ROR #19;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r8, ROR #18;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round13
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r5, ROR #20;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r5, ROR #19;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r5, ROR #18;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r5, ROR #17;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round14
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r6, ROR #19;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r6, ROR #18;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r6, ROR #17;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r6, ROR #16;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round15
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r7, ROR #18;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r7, ROR #17;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r7, ROR #16;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r7, ROR #15;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round16
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r8, ROR #17;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r8, ROR #16;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r8, ROR #15;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r8, ROR #14;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round17
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r5, ROR #16;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r5, ROR #15;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r5, ROR #14;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r5, ROR #13;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round18
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r6, ROR #15;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r6, ROR #14;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r6, ROR #13;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r6, ROR #12;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round19
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r7, ROR #14;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r7, ROR #13;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r7, ROR #12;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r7, ROR #11;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round20
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r8, ROR #13;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r8, ROR #12;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r8, ROR #11;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r8, ROR #10;   \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round21
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r5, ROR #12;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r5, ROR #11;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r5, ROR #10;   \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r5, ROR #9;    \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round22
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r6, ROR #11;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r6, ROR #10;   \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r6, ROR #9;    \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r6, ROR #8;    \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round23
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r7, ROR #10;   \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r7, ROR #9;    \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r7, ROR #8;    \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r7, ROR #7;    \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Round24
		 *--------------------------------------------------------------------*/
		"ADD              r1,           r1,           r8, ROR #9;    \n"
		"MOV              r1,           r1, ROR #31;                 \n"
		"ADD              r2,           r2,           r8, ROR #8;    \n"
		"MOV              r2,           r2, ROR #29;                 \n"
		"ADD              r3,           r3,           r8, ROR #7;    \n"
		"MOV              r3,           r3, ROR #26;                 \n"
		"ADD              r4,           r4,           r8, ROR #6;    \n"
		"MOV              r4,           r4, ROR #21;                 \n"
		"STMIA           r0!,      {r1-r4};                          \n"

		/*--------------------------------------------------------------------
		 * Final
		 *--------------------------------------------------------------------*/
		"LDMIA           sp!,     {r0-r10};                          \n"

		: 
		: [key] "r" (key), [roundKeys] "r" (roundKeys), [delta] "r" (DELTA)
	);
}

#else
#include "primitives.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint32_t* rk = (uint32_t*) roundKeys;
	uint32_t* t = (uint32_t*) key;
	uint32_t t0 = t[0];
	uint32_t t1 = t[1];
	uint32_t t2 = t[2];
	uint32_t t3 = t[3];	
	uint32_t ri = 0;
	int32_t i;

	for(i = 0; i < NUMBER_OF_ROUNDS; ++i) {
		uint32_t tmp = rotl(READ_RAM_DATA_DOUBLE_WORD(DELTA[i & 3]), i);
		
		t0 = rotl(t0 + tmp, 1);
		t1 = rotl(t1 + rotl(tmp, 1), 3);
		t2 = rotl(t2 + rotl(tmp, 2), 6);
		t3 = rotl(t3 + rotl(tmp, 3), 11);

#ifdef ARM_RK_MODE
		rk[ri++] = t0; // rk0
		rk[ri++] = t1; // rk1, rk3, rk5
		rk[ri++] = t2; // rk2
		rk[ri++] = t3; // rk4
#else
		rk[ri++] = t1; // rk1, rk3, rk5
		rk[ri++] = t3; // rk4
		rk[ri++] = t2; // rk2
		rk[ri++] = t0; // rk0
#endif
	}
}

#endif
