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
 * the Free Software Foundation; either version 3 of the License,or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,see <http://www.gnu.org/licenses/>.
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

void NAKED RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	__asm__ __volatile__(\
		/*--------------------------------------------------------------------
		 * Backup registers
		 *--------------------------------------------------------------------*/
		 STRFY(EKS_PUSH)		 
		 
		/*--------------------------------------------------------------------
		 * Setup parameters
		 *--------------------------------------------------------------------*/
		"movw r26, r24                                                    \n\t"
		"movw r28, r22                                                    \n\t"
		"ldi  r30, lo8(delta)                                             \n\t"
		"ldi  r31, hi8(delta)                                             \n\t"
		 
		/*--------------------------------------------------------------------
		 * Load master keys & store whitening keys
		 *--------------------------------------------------------------------*/
		 STRFY(LDX_MK)
		 STRFY(STY_WKEY)
	
		/*--------------------------------------------------------------------
		 * EKS rounds
		 *--------------------------------------------------------------------*/
		"ldi r17, 8                                                       \n\t"
		"1:"
		    STRFY(EKS_ROUND)
			STRFY(EKS_REORDER)
		"   dec  r17                                                      \n\t"
		"   breq  2f                                                      \n\t"
		"   rjmp  1b                                                      \n\t"
		
		/*--------------------------------------------------------------------
		 * restore registers
		 *--------------------------------------------------------------------*/
		"2:"
		    STRFY(EKS_POP)
		"   ret                                                           \n\t"
	);
}

#elif defined(MSP)
#include "macros_msp.h"

void NAKED RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	__asm__ __volatile__(\
		/*--------------------------------------------------------------------
		 * Backup registers
		 *--------------------------------------------------------------------*/
	     STRFY(PUSH_EKS)
		
		/*--------------------------------------------------------------------
		 * Whitening key generation
		 *--------------------------------------------------------------------*/
		 STRFY(ST_WKEY)
		 
		/*--------------------------------------------------------------------
		 * EKS rounds
		 *--------------------------------------------------------------------*/
		"mov #delta, r10                                                  \n\t"
		"mov     #8, r13                                                  \n\t"
		"1:"
		"    mov  #8, r12                                                 \n\t"
		"    2:"
		"        and  #7, r11                                             \n\t"
		"        add r15, r11                                             \n\t"
				 STRFY(EKS_SUBROUND1)
				 STRFY(EKS_SUBROUND2)
		"        inc r10                                                  \n\t"
		"        inc r14                                                  \n\t"
		"        inc r11                                                  \n\t"
		"        dec r12                                                  \n\t"
		"        jnz  2b                                                  \n\t"
		"   add #8, r10                                                   \n\t"
		"   add #8, r14                                                   \n\t"
		"   dec r11                                                       \n\t"
		
		"   dec r13  \n\t"
		"   jnz  1b  \n\t"
		 
		/*--------------------------------------------------------------------
		 * Restore registers
		 *--------------------------------------------------------------------*/
		 STRFY(POP_EKS)
		 "ret                                                             \n\t"
	);
}

#elif defined(ARM)
#include "macros_arm.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	// r0 - key
	// r1 - roundKeys
	__asm__ __volatile__(\
	    /*--------------------------------------------------------------------
		 * Backup registers
		 *--------------------------------------------------------------------*/
		"stmdb sp!, {r0-r12}                                              \n\t"
		"ldmia r0!, {r4-r7}                                               \n\t"				
		"mov    r0, %[delta]                                              \n\t"
		
		/*--------------------------------------------------------------------
		 * Whitening key generation
		 *--------------------------------------------------------------------*/		
		"stmia  r1!, {r7}                                                 \n\t"
		"stmia  r1!, {r4}                                                 \n\t"
		
		/*--------------------------------------------------------------------
		 * EKS rounds
		 *--------------------------------------------------------------------*/		
		"mov r12, #8                                                      \n\t"
		"1:                                                               \n\t"
		"   ldmia r0!, {r8-r9}                                            \n\t"
		    STRFY(ADDU8(r2, r4, r8))
		    STRFY(ADDU8(r3, r5, r9))
		"   stmia r1!, {r2-r3}                                            \n\t"
		   
		"   ldmia r0!, {r8-r9}                                            \n\t"
		    STRFY(ADDU8(r2, r6, r8))
		    STRFY(ADDU8(r3, r7, r9))
		"   stmia r1!, {r2-r3}                                            \n\t"
		   
		    STRFY(ROR64_8(r4, r5))
			STRFY(ROR64_8(r6, r7))
		"   subs r12, #1                                                  \n\t"
		"   bne   1b                                                      \n\t"
		
		/*--------------------------------------------------------------------
		 * Restore registers
		 *--------------------------------------------------------------------*/
		"ldmia sp!, {r0-r12}                                              \n\t"
		:
		: [mk] "r" (key), [roundKeys] "r" (roundKeys), [delta] "r" (delta)
	);
}

#else

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t i, j, index;
	
	roundKeys[0] = key[12];
	roundKeys[1] = key[13];
	roundKeys[2] = key[14];
	roundKeys[3] = key[15];

	roundKeys[4] = key[0];
	roundKeys[5] = key[1];
	roundKeys[6] = key[2];
	roundKeys[7] = key[3];
	
	for(i = 0; i < 8; ++i) {
		for(j = 0; j < 8; ++j) {
			index = (j - i + 8) & 0x07;
			roundKeys[16 * i + j + 8] = key[index] + READ_DELTA_BYTE(delta[16 * i + j]);
			roundKeys[16 * i + j + 16] = key[index + 8] + READ_DELTA_BYTE(delta[16 * i + j + 8]);
		}
	}
}

#endif
