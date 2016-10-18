/*
 *
 * National Security Research Institute
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 National Security Research Institute
 *
 * Written in 2015 by Youngjoo Shin <yjshin@nsr.re.kr>
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

#if defined MSP
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint32_t td[4];
	
	td[0] = READ_RAM_DATA_DOUBLE_WORD(DELTA[0]);
	td[1] = READ_RAM_DATA_DOUBLE_WORD(DELTA[1]);
	td[2] = READ_RAM_DATA_DOUBLE_WORD(DELTA[2]);
	td[3] = READ_RAM_DATA_DOUBLE_WORD(DELTA[3]);
	
	asm volatile (\
		".include \"./../source/msp_rotate.s\"            \n"

		".macro ROUND                                     \n"
		/* load delta */
		" mov  @r14+, r13                                 \n"   /* low */
		" mov  @r14+, r12                                 \n"   /* high */
		/* rotate delta */
		" ROL1 r12, r13                                   \n"   
		/* addition to T0 */
		" add  r13, r5                                    \n"   
		" addc r12, r4                                    \n"
		/* rotate T0 */
		" ROL1 r4, r5                                     \n"   
		/* rotate delta */
		" ROL1 r12, r13                                   \n"   
		/* addition to T1 */
		" add  r13, r7                                    \n"   
		" addc r12, r6                                    \n"
		/* rotate T1 */
		" ROL3 r6, r7                                     \n" 
		/* rotate delta */
		" ROL1 r12, r13                                   \n"
		/* addition to T2 */
		" add  r13, r9                                    \n" 
		" addc r12, r8                                    \n"
		/* rotate T2 */
		" ROL6 r8, r9                                     \n"
		/* rotate delta */
		" ROL1 r12, r13                                   \n" 
		/* addition to T3 */
		" add  r13, r11                                   \n" 
		" addc r12, r10                                   \n"
		/* rotate T3 */
		" ROL11 r10, r11                                \n" 

		/* store round keys */
		" mov  r7, 0(r15)                                 \n"   // T1
		" mov  r6, 2(r15)                                 \n"   // T1
		" mov  r11, 4(r15)                                \n"   // T3
		" mov  r10, 6(r15)                                \n"   // T3
		" mov  r7, 8(r15)                                 \n"   // T1
		" mov  r6, 10(r15)                                \n"   // T1
		" mov  r9, 12(r15)                                \n"   // T2
		" mov  r8, 14(r15)                                \n"   // T2
		" mov  r7, 16(r15)                                \n"   // T1
		" mov  r6, 18(r15)                                \n"   // T1
		" mov  r5, 20(r15)                                \n"   // T0
		" mov  r4, 22(r15)                                \n"   // T0

		" add  #24, r15                                   \n"
		/* store delta */
		" mov  r12, -2(r14)                               \n"
		" mov  r13, -4(r14)                               \n"
		".endm                                            \n"

		" mov  %[key], r14                                \n"
		" mov  %[roundKeys], r15                          \n"

		" mov  @r14+, r5                                  \n"
		" mov  @r14+, r4                                  \n"
		" mov  @r14+, r7                                  \n"
		" mov  @r14+, r6                                  \n"
		" mov  @r14+, r9                                  \n"
		" mov  @r14+, r8                                  \n"
		" mov  @r14+, r11                                 \n"
		" mov  @r14+, r10                                 \n"

		" mov  %[delta], r14                              \n"

		/* begin the rounds */
		" .rept 6                                         \n"
		" ROUND                                           \n"
		" ROUND                                           \n"
		" ROUND                                           \n"
		" ROUND                                           \n"
		" sub  #16, r14                                   \n"
		" .endr                                           \n"
		:
		: [key] "m" (key), [roundKeys] "m" (roundKeys), [delta] "" (td)
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

		rk[ri++] = t0; // rk0
		rk[ri++] = t1; // rk1, rk3, rk5
		rk[ri++] = t2; // rk2
		rk[ri++] = t3; // rk4
	}
}

#endif