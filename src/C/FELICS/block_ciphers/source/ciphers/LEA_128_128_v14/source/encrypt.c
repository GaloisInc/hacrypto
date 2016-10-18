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
#include "macros_avr.h"

void NAKED Encrypt(uint8_t *block, uint8_t *roundKeys) 
{
	/*
	 * Register usage
	 * r25:r24 -> block
	 * r23:r22 -> roundkeys
	 */
	__asm__ __volatile__ (\
		/*--------------------------------------------------------------------
		 * Backup registers
		 *--------------------------------------------------------------------*/		
		 STRFY(PUSH_ALL)
		
		/*--------------------------------------------------------------------
		 * Move parameters to X, Y, Z registers
		 *--------------------------------------------------------------------*/
		"movw r26, r24                                                    \n\t"
		"movw r28, r24                                                    \n\t"
		"movw r30, r22                                                    \n\t"

		/*--------------------------------------------------------------------
		 * Load plaintext
		 *--------------------------------------------------------------------*/
		 STRFY(LDY_BLOCK)

		/*--------------------------------------------------------------------
		 * Encryption rounds
		 *--------------------------------------------------------------------*/
		"ldi r29, 24;                                                     \n\t"
		"1:"
		    STRFY(ENC_ROUND)
		    STRFY(ENC_REORDER(R28))
		"	dec r29                                                       \n\t"
		"	breq 2f                                                       \n\t"
		"	rjmp 1b                                                       \n\t"
		
		/*--------------------------------------------------------------------
		 * Store ciphertext & restore registers
		 *--------------------------------------------------------------------*/
		"2:"
		    STRFY(STX_BLOCK)
			STRFY(POP_ALL)
		"ret                                                              \n\t"
	);
}

#elif defined(MSP)
#include "macros_msp.h"

void NAKED Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	/*
	 * Register usage
	 *
	 *       r15 : block, loop counter
	 *       r14 : roundKeys
	 *  r4 ~ r11 : block
	 * r12 ~ r13 : temp
	 */
    __asm__ __volatile__(\
		/*--------------------------------------------------------------------
		 * Backup registers
		 *--------------------------------------------------------------------*/
         STRFY(PUSH_ALL)
		
        /*--------------------------------------------------------------------
		 * Load plaintext
		 *--------------------------------------------------------------------*/
         STRFY(LD_BLOCK(r15))

        /*--------------------------------------------------------------------
		 * Encryption rounds
		 *--------------------------------------------------------------------*/
		"mov #24, r15                                                     \n\t"
        "1:"
		    STRFY(ENC_ROUND)
		    STRFY(ROR128_32)
		"   add #16, r14                                                  \n\t"
		"   dec r15                                                       \n\t"
        "   jnz 1b                                                        \n\t"

		/*--------------------------------------------------------------------
		 * Store ciphertext & restore registers
		 *--------------------------------------------------------------------*/
		"pop r15                                                          \n\t"
		 STRFY(ST_BLOCK(r15))
		 STRFY(POP_ALL)
		"ret                                                              \n\t"
	); 
}

#elif defined(ARM)
#include "macros_arm.h"

void Encrypt(uint8_t *block, uint8_t *roundKeys) 
{
	/*--------------------------------------------------------------------
	 * Register usage
	 *
	 *     r0 : block ptr
	 *     r1 : roundKeys ptr
	 *     r3 : tmp
	 *  r4~r7 : block
	 * r8~r11 : roundKeys
	 *    r12 : loop ctr
	 *--------------------------------------------------------------------*/
	__asm__ __volatile__ (\
		/*--------------------------------------------------------------------
		 * Init
		 *--------------------------------------------------------------------*/
		"stmdb sp!, {r0-r11}                                              \n\t"
		"ldm    r0, {r4-r7};                                              \n\t"

		/*--------------------------------------------------------------------
		 * START_LOOP
		 *--------------------------------------------------------------------*/
		"mov r12, #24 \n"		
		"1:"
		    STRFY(ENC_ROUND(r4, r5, r6, r7))
			STRFY(ENC_REORDER(r4, r5, r6, r7))
		"   subs r12, r12, #1;                                            \n\t"
		"   bne 1b                                                        \n\t"
		
		"stm    r0, {r4-r7};                                              \n\t"
		"ldmia sp!, {r0-r11}                                              \n\t"
	);
}

#else
#include "rot32.h"
#define RK(x, y) READ_ROUND_KEY_DOUBLE_WORD(x[y])

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t* blk = (uint32_t*) block;
	uint32_t* rk = (uint32_t*) roundKeys;
	uint8_t i;
	
	uint32_t b0 = blk[0];
	uint32_t b1 = blk[1];
	uint32_t b2 = blk[2];
	uint32_t b3 = blk[3];
	
	for (i = 0; i < NUMBER_OF_ROUNDS; i += 4, rk += 4) {
		b3 = rot32r3((b2 ^ RK(rk, 1)) + (b3 ^ RK(rk, 0)));
		b2 = rot32r5((b1 ^ RK(rk, 2)) + (b2 ^ RK(rk, 0)));
		b1 = rot32l9((b0 ^ RK(rk, 3)) + (b1 ^ RK(rk, 0)));
		
		rk +=4;
		b0 = rot32r3((b3 ^ RK(rk, 1)) + (b0 ^ RK(rk, 0)));
		b3 = rot32r5((b2 ^ RK(rk, 2)) + (b3 ^ RK(rk, 0)));
		b2 = rot32l9((b1 ^ RK(rk, 3)) + (b2 ^ RK(rk, 0)));
		
		rk +=4;
		b1 = rot32r3((b0 ^ RK(rk, 1)) + (b1 ^ RK(rk, 0)));
		b0 = rot32r5((b3 ^ RK(rk, 2)) + (b0 ^ RK(rk, 0)));
		b3 = rot32l9((b2 ^ RK(rk, 3)) + (b3 ^ RK(rk, 0)));
		
		rk +=4;
		b2 = rot32r3((b1 ^ RK(rk, 1)) + (b2 ^ RK(rk, 0)));
		b1 = rot32r5((b0 ^ RK(rk, 2)) + (b1 ^ RK(rk, 0)));
		b0 = rot32l9((b3 ^ RK(rk, 3)) + (b0 ^ RK(rk, 0)));
	}
	
	blk[0] = b0;
	blk[1] = b1;
	blk[2] = b2;
	blk[3] = b3;
}

#endif
