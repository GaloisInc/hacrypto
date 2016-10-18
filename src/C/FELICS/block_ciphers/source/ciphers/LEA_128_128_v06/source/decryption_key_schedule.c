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

#if defined(MSP)
void RunDecryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint32_t  td[4];
	uint32_t* ptd = td;
	uint16_t  count = 0;

	td[0] = READ_RAM_DATA_DOUBLE_WORD(DELTA[0]);
	td[1] = READ_RAM_DATA_DOUBLE_WORD(DELTA[1]);
	td[2] = READ_RAM_DATA_DOUBLE_WORD(DELTA[2]);
	td[3] = READ_RAM_DATA_DOUBLE_WORD(DELTA[3]);

	asm volatile (\
		".include \"./../source/msp_rotate.s\"            \n"

		".macro ROUND                                     \n"
		/* load delta */
		"  mov  @r14+, r13                                \n"   /* low */
		"  mov  @r14+, r12                                \n"   /* high */
		/* rotate delta */
		"  ROL1 r12, r13                                  \n"   
		/* addition to T0 */
		"  add  r13, r5                                   \n"   
		"  addc r12, r4                                   \n"
		/* rotate T0 */
		"  ROL1 r4, r5                                    \n"   
		/* rotate delta */
		"  ROL1 r12, r13                                  \n"   
		/* addition to T1 */
		"  add  r13, r7                                   \n"   
		"  addc r12, r6                                   \n"
		/* rotate T1 */
		"  push r12                                       \n"
		"  mov.b #3, r12                                  \n"
		"rot_loop1:                                       \n"
		"  ROL1 r6, r7                                    \n" 
		"  dec r12                                        \n"		
		"  jnz rot_loop1                                  \n"
		"  pop r12                                        \n"
		/* rotate delta */
		"  ROL1 r12, r13                                  \n"
		/* addition to T2 */
		"  add  r13, r9                                   \n" 
		"  addc r12, r8                                   \n"
		/* rotate T2 */
		"  push r12                                       \n"
		"  mov.b #6, r12                                  \n"
		"rot_loop2:                                       \n"
		"  ROL1 r8, r9                                    \n"
		"  dec r12                                        \n"		
		"  jnz rot_loop2                                  \n"
		"  pop r12                                        \n"
		/* rotate delta */
		"  ROL1 r12, r13                                  \n" 
		/* addition to T3 */
		"  add  r13, r11                                  \n" 
		"  addc r12, r10                                  \n"
		/* rotate T3 */
		"  push r12                                       \n"
		"  mov.b #11, r12                                 \n"
		"rot_loop3:                                       \n"
		"  ROL1 r10, r11                                  \n" 
		"  dec r12                                        \n"		
		"  jnz rot_loop3                                  \n"
		"  pop r12                                        \n"
		/* store round keys */
		"  mov  r7, 0(r15)                                \n"   // T1
		"  mov  r6, 2(r15)                                \n"   // T1
		"  mov  r5, 4(r15)                                \n"   // T0
		"  mov  r4, 6(r15)                                \n"   // T0
		"  mov  r9, 8(r15)                                \n"   // T2
		"  mov  r8, 10(r15)                               \n"   // T2
		"  mov  r11, 12(r15)                              \n"   // T3
		"  mov  r10, 14(r15)                              \n"   // T3
		"  sub  #16, r15                                  \n"
		/* store delta */
		"  mov  r12, -2(r14)                              \n"
		"  mov  r13, -4(r14)                              \n"
		".endm                                            \n"

		" mov  %[key], r14                                \n"
		" mov  %[roundKeys], r15                          \n"

		/* load key */
		" mov  @r14+, r5                                  \n"
		" mov  @r14+, r4                                  \n"
		" mov  @r14+, r7                                  \n"
		" mov  @r14+, r6                                  \n"
		" mov  @r14+, r9                                  \n"
		" mov  @r14+, r8                                  \n"
		" mov  @r14+, r11                                 \n"
		" mov  @r14+, r10                                 \n"

		/* point to %[roundKeys]+368 */
		" add #368, r15                                   \n"

		/* begin the rounds */
		" loop:                                           \n"
		" mov  %[count], r13                              \n"
		" and #0xc,r13                                    \n"
		" mov  %[delta], r14                              \n"
		" add  r13, r14                                   \n"
		" ROUND                                           \n"
		" mov  %[count], r14                              \n"
		" incd r14                                        \n"
		" incd r14                                        \n"
		" mov  r14,%[count]                               \n"
		" cmp #96,r14                                     \n"
		" jnz loop                                        \n"
		:
		: [key] "m" (key), [roundKeys] "m" (roundKeys), [delta] "m" (ptd), [count] "m" (count)
	);
}

#else
void RunDecryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
}

#endif
