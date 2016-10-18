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

void NAKED RunEKS(uint8_t *key, uint8_t *roundKeys, uint32_t *delta) 
{
	/*
	 * Register usage
	 * r25:r24 -> key
	 * r23:r22 -> roundKeys
	 * r21:r20 -> delta
	 */
	__asm__ __volatile__(\
		/*--------------------------------------------------------------------
		 * Save register states
		 *--------------------------------------------------------------------*/
		 STRFY(EKS_PUSH)
		
		/*--------------------------------------------------------------------
		 * Move parameters to X, Y, Z registers
		 *--------------------------------------------------------------------*/
		"movw r26, r22                                                    \n\t"
		"movw r28, r24                                                    \n\t"
		"movw r30, r20                                                    \n\t"
		
		/*--------------------------------------------------------------------
		 * Load master key
		 *--------------------------------------------------------------------*/
		 STRFY(LDY_KEY)
		 
		/*--------------------------------------------------------------------
		 * Loop
		 *--------------------------------------------------------------------*/
		"ldi r28, 24                                                      \n\t"
		"ldi r29, 4                                                       \n\t"
		"1:"
		    STRFY(EKS_ROUND)
		"   dec  r28                                                      \n\t"
		"   breq  3f                                                      \n\t"
		"   dec  r29                                                      \n\t"
		"   brne  2f                                                      \n\t"
		"   ldi  r29,  4                                                  \n\t"
		"   sbiw r30, 16                                                  \n\t" //@ Z-=16
		"2:"
		"   rjmp 1b                                                       \n\t"
		
		/*--------------------------------------------------------------------
		 * Restore register states
		 *--------------------------------------------------------------------*/
		"3:"
		    STRFY(EKS_POP)
		"ret                                                              \n\t"
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

#elif defined(MSP)
#include "macros_msp.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint32_t td[4];
	uint32_t* ptd = td;
	uint16_t iter = 0;	
	td[0] = READ_RAM_DATA_DOUBLE_WORD(DELTA[0]);
	td[1] = READ_RAM_DATA_DOUBLE_WORD(DELTA[1]);
	td[2] = READ_RAM_DATA_DOUBLE_WORD(DELTA[2]);
	td[3] = READ_RAM_DATA_DOUBLE_WORD(DELTA[3]);
	
	__asm__ __volatile__(\
		/*--------------------------------------------------------------------
		 * Init
		 *--------------------------------------------------------------------*/
		"mov       %[key], r15                                            \n\t"
		"mov %[roundKeys], r14                                            \n\t"
		 
		/*--------------------------------------------------------------------
		 * Load master key
		 *--------------------------------------------------------------------*/
		STRFY(LD_KEY(r15))

		/*--------------------------------------------------------------------
		 * Loop rounds
		 *--------------------------------------------------------------------*/
		 "1:"
		 "   mov  %[iter], r13                                            \n\t"
		 "   and     #0xc, r13                                            \n\t"
		 "   jnz       2f                                                 \n\t"
		 "   mov %[delta], r15                                            \n\t"
		 
		 "2:"
		     STRFY(EKS_ROUND)
		     STRFY(ST_KEY(r14))
		 "   add      #16, r14                                            \n\t"
		 "   mov  %[iter], r13                                            \n\t"
		 "   add      @r2, r13                                            \n\t"
		 "   mov      r13, %[iter]                                        \n\t"
		 "   cmp      #96, r13                                            \n\t"
		 "   jnz       1b                                                 \n\t"
		:
		: [key] "m" (key), [roundKeys] "m" (roundKeys), [delta] "m" (ptd), [iter] "m" (iter)
	);
}

#elif defined(ARM)
#include "macros_arm.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	/*--------------------------------------------------------------------
	 * Register usage
	 *
	 *     r0 : key
	 *     r1 : roundKeys
	 *     r2 : delta
	 *     r3 : tmp
	 *  r4~r7 : key
	 * r8~r11 : delta
	 *    r12 : loop ctr
	 *--------------------------------------------------------------------*/
	__asm__ __volatile__ (\
		/*--------------------------------------------------------------------
		 * Init
		 *--------------------------------------------------------------------*/
		"stmdb sp!, {r0-r11}                                              \n\t"
		"mov r0, %[key]                                                   \n\t"
		"mov r1, %[roundKeys]                                             \n\t"
		"mov r2, %[delta]                                                 \n\t"
		
		"ldm r0, {r4-r7};                                                 \n\t" // keys
		"ldm r2, {r8-r11};                                                \n\t" // delta
		
		 STRFY(KEY_REORDER(r4, r5, r6, r7))
		/*--------------------------------------------------------------------
		 * START_LOOP
		 *--------------------------------------------------------------------*/
		"mov r12, #24 \n"
		"1:"
		    STRFY(EKS_ROUND(r4, r5, r6, r7, r8))
		    STRFY(EKS_REORDER(r8, r9, r10, r11))
		"   subs r12, r12, #1;                                            \n\t"
		"   bne 1b                                                        \n\t"
		"ldmia sp!, {r0-r11}                                              \n\t"
		:
		: [key] "r" (key), [roundKeys] "r" (roundKeys), [delta] "r" (DELTA)
	);
}

#else
#include "rot32.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint32_t* rk = (uint32_t*) roundKeys;
	uint32_t* t = (uint32_t*) key;
	uint32_t delta[4] = { READ_RAM_DATA_DOUBLE_WORD(DELTA[0]), READ_RAM_DATA_DOUBLE_WORD(DELTA[1]), READ_RAM_DATA_DOUBLE_WORD(DELTA[2]), READ_RAM_DATA_DOUBLE_WORD(DELTA[3]) };
	uint32_t ri = 0;
	int32_t i;
	
	uint32_t t0 = t[0];
	uint32_t t1 = t[1];
	uint32_t t2 = t[2];
	uint32_t t3 = t[3];

	for(i = 0; i < NUMBER_OF_ROUNDS; ++i, ++ri) {
		uint32_t tmp = delta[i & 3];
		
		t0 = rot32l1(t0 + tmp);
		t1 = rot32l3(t1 + rot32l1(tmp));
		t2 = rot32l6(t2 + rot32l2(tmp));
		t3 = rot32l11(t3 + rot32l3(tmp));
		delta[i & 3] = rot32l4(tmp);

		rk[ri] = t1; // rk1, rk3, rk5
		rk[++ri] = t3; // rk4
		rk[++ri] = t2; // rk2
		rk[++ri] = t0; // rk0
	}
}

#endif
