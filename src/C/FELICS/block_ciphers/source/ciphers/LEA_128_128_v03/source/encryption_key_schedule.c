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

void RunEKS(uint8_t *key, uint8_t *roundKeys, uint32_t *delta) {
	asm volatile (\
		/*--------------------------------------------------------------------
		 * Macro
		 *--------------------------------------------------------------------*/
		"	PUSH R12;\n"
		"	PUSH R13;\n"
		"	PUSH R14;\n"
		"	PUSH R15;\n"
		"	PUSH R28;\n"
		"	PUSH R29;\n"

		"	LDI R19, 4;\n"
		"	LDI R20, 24;\n"

		/*--------------------------------------------------------------------
		 * Loop
		 *--------------------------------------------------------------------*/
		"KeyLoop:\n"

		"	LD R12, Z;\n"
		"	LDD R13, Z+1;\n"
		"	LDD R14, Z+2;\n"
		"	LDD R15, Z+3;\n"

		"	ADIW R26, 12;\n"

		"	LDI R18, 1;\n"
		"	RCALL LEA_KeySchdU32;\n"

		"	SUBI R26, 16;\n"
		"	SBCI R27, 0;\n"

		"	LDI R18, 3;\n"
		"	RCALL LEA_KeySchdU32;\n"

		"	ADIW R26, 4;\n"

		"	LDI R18, 6;\n"
		"	RCALL LEA_KeySchdU32;\n"

		"	SUBI R26, 8;\n"
		"	SBCI R27, 0;\n"

		"	LDI R18, 11;\n"
		"	RCALL LEA_KeySchdU32;\n"

		"	ADIW R26, 8;\n"

		"	SUBI R28, 16;\n"
		"	SBCI R29, 0;\n"

		"	ST Z+, R12;\n"
		"	ST Z+, R13;\n"
		"	ST Z+, R14;\n"
		"	ST Z+, R15;\n"

		"	DEC R19;\n"
		"	BRNE NO_DELTA_RESET;\n"
		"	LDI R19, 4;\n"
		"	SUBI R30, 16;\n"
		"	SBCI R31, 0;\n"
		
		/*--------------------------------------------------------------------
		 * NO_DELTA_RESET
		 *--------------------------------------------------------------------*/
		"NO_DELTA_RESET:\n"
		"	DEC R20;\n"
		"	BRNE KeyLoop;\n"

		"	POP R29;\n"
		"	POP R28;\n"
		"	POP R15;\n"
		"	POP R14;\n"
		"	POP R13;\n"
		"	POP R12;\n"		
		"   JMP KeyLoopEnd;\n"

		/*--------------------------------------------------------------------
		 * LEA_KeySchdU32
		 *--------------------------------------------------------------------*/
		"LEA_KeySchdU32:\n"		
		"	LD R22, Y;\n"
		"	LDD R23, Y+1;\n"
		"	LDD R24, Y+2;\n"
		"	LDD R25, Y+3;\n"

		"	ADD R22, R12;\n"
		"	ADC R23, R13;\n"
		"	ADC R24, R14;\n"
		"	ADC R25, R15;\n"

		"	LSL R12;\n"
		"	ROL R13;\n"
		"	ROL R14;\n"
		"	ROL R15;\n"
		"	ADC R12, R1;\n"		
		
		/*--------------------------------------------------------------------
		 * ROL
		 *--------------------------------------------------------------------*/
		"ROL_Big:\n"
		"	CPI R18, 5;\n"
		"	BRLT ROL_BigEnd;\n"

		"	MOV R0, R25;\n"
		"	MOV R25, R24;\n"
		"	MOV R24, R23;\n"
		"	MOV R23, R22;\n"
		"	MOV R22, R0;\n"

		"	SUBI R18, 8;\n"		

		"ROL_BigEnd:\n"
		"	CPI R18, 0;\n"
		"	BRLT ROL_SmallRevBegin;\n"

		"ROL_Small:\n"
		"	LSL R22;\n"
		"	ROL R23;\n"
		"	ROL R24;\n"
		"	ROL R25;\n"
		"	ADC R22, R1;\n"

		"	DEC R18;\n"
		"	BRNE ROL_Small;\n"
		"	RJMP ROL_End;\n"

		"ROL_SmallRevBegin:\n"
		"	CLR R0;\n"
		
		"ROL_SmallRev:\n"
		"	LSR R25;\n"
		"	ROR R24;\n"
		"	ROR R23;\n"
		"	ROR R22;\n"
		"	ROR R0;\n"

		"	INC R18;\n"
		"	BRNE ROL_SmallRev;\n"
		"	EOR R25, R0;\n"

		"ROL_End:\n"		
		"	ST Y+, R22;\n"
		"	ST Y+, R23;\n"
		"	ST Y+, R24;\n"
		"	ST Y+, R25;\n"

		"	ST X+, R22;\n"
		"	ST X+, R23;\n"
		"	ST X+, R24;\n"
		"	ST X+, R25;\n"
		"   RET;\n"
		
		/*--------------------------------------------------------------------
		 * Loop end
		 *--------------------------------------------------------------------*/
		"KeyLoopEnd:\n"
		:
		: "x" (roundKeys), "y" (key), "z" (delta)
	);
}

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint32_t td[4];
	uint8_t ckey[16];
	
	td[0] = READ_RAM_DATA_DOUBLE_WORD(DELTA[0]);
	td[1] = READ_RAM_DATA_DOUBLE_WORD(DELTA[1]);
	td[2] = READ_RAM_DATA_DOUBLE_WORD(DELTA[2]);
	td[3] = READ_RAM_DATA_DOUBLE_WORD(DELTA[3]);
	
	ckey[0] = key[0];
	ckey[1] = key[1];
	ckey[2] = key[2];
	ckey[3] = key[3];
	ckey[4] = key[4];
	ckey[5] = key[5];
	ckey[6] = key[6];
	ckey[7] = key[7];
	ckey[8] = key[8];
	ckey[9] = key[9];
	ckey[10] = key[10];
	ckey[11] = key[11];
	ckey[12] = key[12];
	ckey[13] = key[13];
	ckey[14] = key[14];
	ckey[15] = key[15];
	
	RunEKS(ckey, roundKeys, td);	
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
		 * r9 - temp, loop variable
		 * r10 - temp
		 *--------------------------------------------------------------------*/
		 
		/*--------------------------------------------------------------------
		 * Init
		 *--------------------------------------------------------------------*/
		"STMDB           sp!,     {r0-r11};                          \n"
		"MOV              r9,       %[key];                          \n"
		"MOV             r10,     %[delta];                          \n"
		"MOV              r0, %[roundKeys];                          \n"
		"LDM              r9,      {r1-r4};                          \n"
		"LDM             r10,      {r5-r8};                          \n"
		
		/*--------------------------------------------------------------------
		 * Initial Rotation
		 *--------------------------------------------------------------------*/
		"MOV              r6,           r6,  ROR #31;                \n"
		"MOV              r7,           r7,  ROR #30;                \n"
		"MOV              r8,           r8,  ROR #29;                \n"

		/*--------------------------------------------------------------------
		 * START_LOOP
		 *--------------------------------------------------------------------*/
		"MOV             r10,          #24;                          \n"
		"ks_loop:                                                    \n"

		/*--------------------------------------------------------------------
		 * Round
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
		 * Reorder
		 *--------------------------------------------------------------------*/
		"MOV             r11,           r5, ROR #28;                 \n"
		"MOV              r5,           r6;                          \n"
		"MOV              r6,           r7;                          \n"
		"MOV              r7,           r8;                          \n"
		"MOV              r8,          r11;                          \n"

		/*--------------------------------------------------------------------
		 * END_LOOP
		 *--------------------------------------------------------------------*/
		"SUBS            r10,          r10,           #1;            \n"
		"BNE ks_loop;                                                \n"

		/*--------------------------------------------------------------------
		 * Final
		 *--------------------------------------------------------------------*/
		"LDMIA           sp!,     {r0-r11};                          \n"

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
