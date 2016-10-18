/*
 *
 * National Security Research Institute
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 National Security Research Institute
 *
 * Written in 2015 by Ilwoong Jeong <iw98jeong@nsr.re.kr>
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
#include "macros_avr.h"

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	__asm__ __volatile__(\
		/*--------------------------------------------------------------------
		 * Backup registers & load ciphertext
		 *--------------------------------------------------------------------*/
		 STRFY(ENC_PUSH)
		"movw r26, r24                                                    \n\t"
		"movw r30, r22                                                    \n\t"
		 STRFY(LDX_BLOCK)
		 
		/*--------------------------------------------------------------------
		 * Final transformation
		 *--------------------------------------------------------------------*/
		"adiw r30, 4                                                      \n\t"
		 STRFY(LDZ_RKS)
		 STRFY(DEC_FINAL)

#if defined(SCENARIO) & (SCENARIO_2 == SCENARIO)
		"subi r30, 0x84 \n\t"
#else
		"subi r30, 0x80 \n\t"
#endif
		"sbci r31, 0xff \n\t"
		/*--------------------------------------------------------------------
		 * Decryption rounds
		 *--------------------------------------------------------------------*/
		"ldi  r17, 32                                                     \n\t"
		"1:"
		    STRFY(DEC_LDZ_RKS)
		    STRFY(DEC_ROUND)
		"   dec  r17                                                      \n\t"
		"   breq  2f                                                      \n\t"
		"   rjmp  1b                                                      \n\t"
		
		"2:"
		/*--------------------------------------------------------------------
		 * Initial transformation
		 *--------------------------------------------------------------------*/
		"   sbiw r30, 4                                                   \n\t"
		    STRFY(DEC_LDZ_RKS)
			STRFY(DEC_INIT)
			
		/*--------------------------------------------------------------------
		 * Store plaintext & restore registers
		 *--------------------------------------------------------------------*/
		    STRFY(STX_BLOCK)
		    STRFY(ENC_POP)
        "   ret                                                           \n\t"
	);
}

#elif defined(MSP)
#include "macros_msp.h"

void NAKED Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	__asm__ __volatile__(\
		/*--------------------------------------------------------------------
		 * Backup registers & load ciphertext
		 *--------------------------------------------------------------------*/
		 STRFY(PUSH_ALL)
		 STRFY(LD_BLOCK)
		 
		/*--------------------------------------------------------------------
		 * Final transformation
		 *--------------------------------------------------------------------*/
		"add   #4, r14                                                    \n\t"
		 STRFY(DEC_FINAL)		
		"add #128, r14                                                    \n\t"
		
		/*--------------------------------------------------------------------
		 * Decryption rounds
		 *--------------------------------------------------------------------*/
		"mov #32, r13                                                     \n\t"
		"1:"
		    STRFY(DEC_ROUND)
		"   sub #4, r14                                                   \n\t"
		"   dec r13                                                       \n\t"
		"   jnz 1b                                                        \n\t"
		
		/*--------------------------------------------------------------------
		 * Initial transformation
		 *--------------------------------------------------------------------*/
		"sub #4, r14                                                      \n\t"
		 STRFY(DEC_INIT)
		 
		/*--------------------------------------------------------------------
		 * Store plaintext & restore registers
		 *--------------------------------------------------------------------*/
		 STRFY(ST_BLOCK)
		 STRFY(POP_ALL)
		"ret                                                              \n\t"
	);
}

#elif defined(ARM)
#include "macros_arm.h"

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	// r0 - key
	// r1 - roundKeys
	__asm__ __volatile__(\
	    /*--------------------------------------------------------------------
		 * Backup registers & load ciphertext
		 *--------------------------------------------------------------------*/
		"stmdb sp!, {r0-r12}                                              \n\t"
		"ldm    r0, {r4-r5}                                               \n\t"
		 
		/*--------------------------------------------------------------------
		 * Final transformation
		 *--------------------------------------------------------------------*/
		 STRFY(LD_SWAPMASK)
		"add    r1, #4                                                    \n\t"
		 STRFY(DEC_FINAL)
		
		/*--------------------------------------------------------------------
		 * Decryption rounds
		 *--------------------------------------------------------------------*/
		"add  r1, #132                                                    \n\t"
		"mov r12, #32                                                     \n\t"
		"1:                                                               \n\t"
		    STRFY(DEC_ROUND)
		"   subs r12, #1                                                  \n\t"
		"   bne   1b                                                      \n\t"
		
		/*--------------------------------------------------------------------
		 * Initial transformation
		 *--------------------------------------------------------------------*/
		"sub    r1, #8                                                    \n\t"
		 STRFY(DEC_INIT)
		 
		/*--------------------------------------------------------------------
		 * Store plaintext & restore registers
		 *--------------------------------------------------------------------*/
		"stm    r0, {r4-r5}                                               \n\t"
		"ldmia sp!, {r0-r12}                                              \n\t"
	);
}

#else
#include "round_function.h"

void DecryptInitialTransfomation(uint8_t *x, const uint8_t *wk)
{
	x[0] = x[0] - READ_ROUND_KEY_BYTE(wk[0]);
	x[2] = x[2] ^ READ_ROUND_KEY_BYTE(wk[1]);
	x[4] = x[4] - READ_ROUND_KEY_BYTE(wk[2]);
	x[6] = x[6] ^ READ_ROUND_KEY_BYTE(wk[3]);
}

void DecryptRoundFunction(uint8_t *x, const uint8_t *sk)
{
	uint8_t temp0 = x[0];	

	x[0] = x[1];
	x[1] = x[2] - (F1(x[0]) ^ READ_ROUND_KEY_BYTE(sk[0]));
	x[2] = x[3];
	x[3] = x[4] ^ (F0(x[2]) + READ_ROUND_KEY_BYTE(sk[1]));	
	x[4] = x[5];
	x[5] = x[6] - (F1(x[4]) ^ READ_ROUND_KEY_BYTE(sk[2]));
	x[6] = x[7];	
	x[7] = temp0 ^ (F0(x[6]) + READ_ROUND_KEY_BYTE(sk[3]));
}

void DecryptFinalTransfomation(uint8_t *x, const uint8_t *wk)
{
	uint8_t temp = x[7];

	x[7] = x[6] ^ READ_ROUND_KEY_BYTE(wk[7]); 
	x[6] = x[5]; 
	x[5] = x[4] - READ_ROUND_KEY_BYTE(wk[6]);
	x[4] = x[3]; 
	x[3] = x[2] ^ READ_ROUND_KEY_BYTE(wk[5]);
	x[2] = x[1]; 
	x[1] = x[0] - READ_ROUND_KEY_BYTE(wk[4]);
	x[0] = temp;
}

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	int8_t i;
	int8_t* prk = roundKeys + 132;

	DecryptFinalTransfomation(block, roundKeys);

	for(i = 0; i < NUMBER_OF_ROUNDS; ++i) {
		DecryptRoundFunction(block, prk);
		prk -= 4; 
	}

	DecryptInitialTransfomation(block, roundKeys);
}

#endif
