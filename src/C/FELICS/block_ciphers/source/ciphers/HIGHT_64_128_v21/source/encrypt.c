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
/*
 * GCC AVR passes arguments from left to right in r25-r8.
 * Pointers are 16-bits, so arguments are in r25:r24 and r23:22
 */
void NAKED Encrypt(uint8_t *block, uint8_t *roundKeys) 
{	
	__asm__ __volatile__(\
	    /*--------------------------------------------------------------------
		 * Backup registers & load plaintext
		 *--------------------------------------------------------------------*/
	     STRFY(ENC_PUSH)		
		"movw r26, r24                                                    \n\t"
		"movw r30, r22                                                    \n\t"
		 STRFY(LDX_BLOCK)
		
		/*--------------------------------------------------------------------
		 * Initial transformation
		 *--------------------------------------------------------------------*/
		 STRFY(LDZ_RKS)
		 STRFY(ENC_INIT)
		
		/*--------------------------------------------------------------------
		 * Encryption rounds
		 *--------------------------------------------------------------------*/
		"adiw r30, 4                                                      \n\t"
		"ldi  r17, 32                                                     \n\t"
		"1:"
		    STRFY(LDZ_RKS)
		    STRFY(ENC_ROUND)
		"   dec  r17                                                      \n\t"
		"   breq  2f                                                      \n\t"
		"   rjmp  1b                                                      \n\t"
		
		"2:"
		/*--------------------------------------------------------------------
		 * Final transformation
		 *--------------------------------------------------------------------*/
		"   sbiw r30, 63                                                  \n\t"
		"   sbiw r30, 63                                                  \n\t"
		"   sbiw r30, 6                                                   \n\t"
		    STRFY(LDZ_RKS)
		    STRFY(ENC_FINAL)
			
		/*--------------------------------------------------------------------
		 * Store ciphertext & restore registers
		 *--------------------------------------------------------------------*/
		    STRFY(STX_BLOCK)			
		    STRFY(ENC_POP)			
		"   ret                                                           \n\t"
	);
}

#elif defined(MSP)
#include "macros_msp.h"

void NAKED Encrypt(uint8_t *block, uint8_t *roundKeys) 
{
	__asm__ __volatile__(\
		/*--------------------------------------------------------------------
		 * Backup registers & load plaintext
		 *--------------------------------------------------------------------*/
		 STRFY(PUSH_ALL)
		 STRFY(LD_BLOCK)
		 
		/*--------------------------------------------------------------------
		 * Initial transformation
		 *--------------------------------------------------------------------*/
		 STRFY(ENC_INIT)
		
		/*--------------------------------------------------------------------
		 * Encryption rounds
		 *--------------------------------------------------------------------*/
		"add  #8, r14                                                     \n\t"
		"mov #32, r13                                                     \n\t"
		"1:"
		    STRFY(ENC_ROUND)
		"   add #4, r14                                                   \n\t"
		"   dec r13                                                       \n\t"
		"   jnz 1b                                                        \n\t"
		
		/*--------------------------------------------------------------------
		 * Final transformation
		 *--------------------------------------------------------------------*/
		"sub #132, r14                                                    \n\t"
		 STRFY(ENC_FINAL)
		
		/*--------------------------------------------------------------------
		 * Store ciphertext & restore registers
		 *--------------------------------------------------------------------*/
		 STRFY(ST_BLOCK)
		 STRFY(POP_ALL)
		"ret                                                              \n\t"
	);
}

#elif defined(ARM)
#include "macros_arm.h"

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	// r0 - key
	// r1 - roundKeys
	__asm__ __volatile__(\
		/*--------------------------------------------------------------------
		 * Backup registers & load plaintext
		 *--------------------------------------------------------------------*/
		"stmdb sp!, {r0-r12}                                              \n\t"
		"ldm    r0, {r4-r5}                                               \n\t"
		
		/*--------------------------------------------------------------------
		 * Initial transformation
		 *--------------------------------------------------------------------*/
		 STRFY(LD_SWAPMASK)
		 STRFY(ENC_INIT)
		
		/*--------------------------------------------------------------------
		 * Encryption rounds
		 *--------------------------------------------------------------------*/
		"add  r1, #8                                                      \n\t"
		"mov r12, #32                                                     \n\t"
		"1:                                                               \n\t"
		    STRFY(ENC_ROUND)
		"   subs r12, #1                                                  \n\t"
		"   bne   1b                                                      \n\t"
		 
		/*--------------------------------------------------------------------
		 * Final transformation
		 *--------------------------------------------------------------------*/
        "sub r1, #132                                                     \n\t"
		 STRFY(ENC_FINAL)
		 
		/*--------------------------------------------------------------------
		 * Store ciphertext & restore registers
		 *--------------------------------------------------------------------*/ 
		"stm    r0, {r4-r5}                                               \n\t"
		"ldmia sp!, {r0-r12}                                              \n\t"
	);
}

#else
#include "round_function.h"

void EncryptInitialTransfomation(uint8_t *x, const uint8_t *wk)
{
	x[0] = x[0] + READ_ROUND_KEY_BYTE(wk[0]);
	x[2] = x[2] ^ READ_ROUND_KEY_BYTE(wk[1]);
	x[4] = x[4] + READ_ROUND_KEY_BYTE(wk[2]);
	x[6] = x[6] ^ READ_ROUND_KEY_BYTE(wk[3]);
}
	
void EncryptRoundFunction(uint8_t *x, const uint8_t *sk)
{
	uint8_t temp6 = x[6];
	uint8_t temp7 = x[7];
	
	x[7] = x[6];
	x[6] = x[5] + (F1(x[4]) ^ READ_ROUND_KEY_BYTE(sk[2]));
	x[5] = x[4]; 
	x[4] = x[3] ^ (F0(x[2]) + READ_ROUND_KEY_BYTE(sk[1]));
	x[3] = x[2]; 
	x[2] = x[1] + (F1(x[0]) ^ READ_ROUND_KEY_BYTE(sk[0]));
	x[1] = x[0]; 
	x[0] = temp7 ^ (F0(temp6) + READ_ROUND_KEY_BYTE(sk[3]));
}

void EncryptFinalTransfomation(uint8_t *x, const uint8_t *wk)
{
	uint8_t temp = x[0];

	x[0] = x[1] + READ_ROUND_KEY_BYTE(wk[4]); 
	x[1] = x[2]; 
	x[2] = x[3] ^ READ_ROUND_KEY_BYTE(wk[5]); 
	x[3] = x[4];
	x[4] = x[5] + READ_ROUND_KEY_BYTE(wk[6]); 
	x[5] = x[6]; 
	x[6] = x[7] ^ READ_ROUND_KEY_BYTE(wk[7]); 
	x[7] = temp;
}

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i;
    uint8_t* prk = roundKeys + 8;
	
	EncryptInitialTransfomation(block, roundKeys);

	for(i = 0; i < NUMBER_OF_ROUNDS; ++i) {
		EncryptRoundFunction(block, prk);
		prk += 4;
	}

	EncryptFinalTransfomation(block, roundKeys);
}

#endif
