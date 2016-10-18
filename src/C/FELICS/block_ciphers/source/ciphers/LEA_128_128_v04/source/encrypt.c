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
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile (\
        ".include \"./../source/msp_rotate.s\"        \n"

        ".macro SUBR1 X1h,X1l,X0h,X0l,K0,K1           \n"
        "   xor @r15+, \\X1l                          \n"
        "   xor @r15+, \\X1h                          \n"
        "   mov @r15+,\\K0                            \n" /* low of RK4(T3) */
        "   mov @r15+,\\K1                            \n" /* high of RK4(T3) */
        "   xor \\X0l, \\K0                           \n"
        "   xor \\X0h, \\K1                           \n"
        "   add \\K0, \\X1l                           \n"
        "   addc \\K1, \\X1h                          \n"
        "   ROR3 \\X1h,\\X1l,\\K0                     \n"
        ".endm                                        \n"

        ".macro SUBR2 X1h,X1l,X0h,X0l,K0,K1           \n"
        "   xor @r15+, \\X1l                          \n"
        "   xor @r15+, \\X1h                          \n"
        "   mov @r15+,\\K0                            \n" /* low of RK2(T2) */
        "   mov @r15+,\\K1                            \n" /* high of RK2(T2) */
        "   xor \\X0l, \\K0                           \n"
        "   xor \\X0h, \\K1                           \n"
        "   add \\K0, \\X1l                           \n"
        "   addc \\K1, \\X1h                          \n"
        "   ROR5 \\X1h,\\X1l,\\K0                     \n"
        ".endm                                        \n"

        ".macro SUBR3 X1h,X1l,X0h,X0l,K0,K1           \n"
        "   xor @r15+, \\X1l                          \n"
        "   xor @r15+, \\X1h                          \n"
        "   mov @r15+,\\K0                            \n" /* low of RK0(T0) */
        "   mov @r15+,\\K1                            \n" /* low of RK0(T0) */
        "   xor \\X0l, \\K0                           \n"
        "   xor \\X0h, \\K1                           \n"
        "   add \\K0, \\X1l                           \n"
        "   addc \\K1, \\X1h                          \n"
        "   ROL9 \\X1h,\\X1l,\\K0,\\K1                \n"
        ".endm                                        \n"

        ".macro ROUND X3h,X3l,X2h,X2l,X1h,X1l,X0h,X0l \n"
        "   SUBR1 \\X3h,\\X3l,\\X2h,\\X2l, r12, r13   \n"
        "   SUBR2 \\X2h,\\X2l,\\X1h,\\X1l, r12, r13   \n"
        "   SUBR3 \\X1h,\\X1l,\\X0h,\\X0l, r12, r13   \n"
        ".endm                                        \n"
        "                                             \n"

        " mov %[block], r14                           \n"   
        " mov %[roundKeys], r15                       \n"

        " push r4\n"
        " push r5\n"
        " push r6\n"
        " push r7\n"
        " push r8\n"
        " push r9\n"
        " push r10\n"
        " push r11\n"
        " push r12\n"
        " push r13\n"


        /* load plaintext */
        " mov @r14+,r4                                \n"
        " mov @r14+,r5                                \n"
        " mov @r14+,r6                                \n"
        " mov @r14+,r7                                \n"
        " mov @r14+,r8                                \n"
        " mov @r14+,r9                                \n"
        " mov @r14+,r10                               \n"
        " mov @r14+,r11                               \n"

        /* begin rounds  */
        " .rept 6                                     \n" 
        " ROUND r11,r10,r9,r8,r7,r6,r5,r4             \n"
        " ROUND r5,r4,r11,r10,r9,r8,r7,r6             \n"
        " ROUND r7,r6,r5,r4,r11,r10,r9,r8             \n"
        " ROUND r9,r8,r7,r6,r5,r4,r11,r10             \n"
        " .endr                                       \n"

        /* store ciphertext */
        " mov r4, -16(r14)                            \n"
        " mov r5, -14(r14)                            \n"
        " mov r6, -12(r14)                            \n"
        " mov r7, -10(r14)                            \n"
        " mov r8, -8(r14)                             \n" 
        " mov r9, -6(r14)                             \n"
        " mov r10, -4(r14)                            \n"
        " mov r11, -2(r14)                            \n" 

        " pop r13\n"
        " pop r12\n"
        " pop r11\n"
        " pop r10\n"
        " pop r9\n"
        " pop r8\n"
        " pop r7\n"
        " pop r6\n"
        " pop r5\n"
        " pop r4\n"
		:
		: [block] "m" (block), [roundKeys] "m" (roundKeys)
	); 
}

#else
#include "primitives.h"

#define RK(x, y) READ_ROUND_KEY_DOUBLE_WORD(x[y])

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t* blk = (uint32_t*) block;
	uint32_t* rk = (uint32_t*) roundKeys;
	
	uint32_t b0 = blk[0];
	uint32_t b1 = blk[1];
	uint32_t b2 = blk[2];
	uint32_t b3 = blk[3];	
	
	// Round 1
	b3 = rotr((b2 ^ RK(rk, 3)) + (b3 ^ RK(rk, 1)), 3);
	b2 = rotr((b1 ^ RK(rk, 2)) + (b2 ^ RK(rk, 1)), 5);
	b1 = rotl((b0 ^ RK(rk, 0)) + (b1 ^ RK(rk, 1)), 9);
	
	// Round 2
	rk += 4;
	b0 = rotr((b3 ^ RK(rk, 3)) + (b0 ^ RK(rk, 1)), 3);
	b3 = rotr((b2 ^ RK(rk, 2)) + (b3 ^ RK(rk, 1)), 5);
	b2 = rotl((b1 ^ RK(rk, 0)) + (b2 ^ RK(rk, 1)), 9);
	
	// Round 3
	rk += 4;
	b1 = rotr((b0 ^ RK(rk, 3)) + (b1 ^ RK(rk, 1)), 3);
	b0 = rotr((b3 ^ RK(rk, 2)) + (b0 ^ RK(rk, 1)), 5);
	b3 = rotl((b2 ^ RK(rk, 0)) + (b3 ^ RK(rk, 1)), 9);
	
	// Round 4
	rk += 4;
	b2 = rotr((b1 ^ RK(rk, 3)) + (b2 ^ RK(rk, 1)), 3);
	b1 = rotr((b0 ^ RK(rk, 2)) + (b1 ^ RK(rk, 1)), 5);
	b0 = rotl((b3 ^ RK(rk, 0)) + (b0 ^ RK(rk, 1)), 9);
	
	// Round 5
	rk += 4;
	b3 = rotr((b2 ^ RK(rk, 3)) + (b3 ^ RK(rk, 1)), 3);
	b2 = rotr((b1 ^ RK(rk, 2)) + (b2 ^ RK(rk, 1)), 5);
	b1 = rotl((b0 ^ RK(rk, 0)) + (b1 ^ RK(rk, 1)), 9);
	
	// Round 6
	rk += 4;
	b0 = rotr((b3 ^ RK(rk, 3)) + (b0 ^ RK(rk, 1)), 3);
	b3 = rotr((b2 ^ RK(rk, 2)) + (b3 ^ RK(rk, 1)), 5);
	b2 = rotl((b1 ^ RK(rk, 0)) + (b2 ^ RK(rk, 1)), 9);
	
	// Round 7
	rk += 4;
	b1 = rotr((b0 ^ RK(rk, 3)) + (b1 ^ RK(rk, 1)), 3);
	b0 = rotr((b3 ^ RK(rk, 2)) + (b0 ^ RK(rk, 1)), 5);
	b3 = rotl((b2 ^ RK(rk, 0)) + (b3 ^ RK(rk, 1)), 9);
	
	// Round 8
	rk += 4;
	b2 = rotr((b1 ^ RK(rk, 3)) + (b2 ^ RK(rk, 1)), 3);
	b1 = rotr((b0 ^ RK(rk, 2)) + (b1 ^ RK(rk, 1)), 5);
	b0 = rotl((b3 ^ RK(rk, 0)) + (b0 ^ RK(rk, 1)), 9);
	
	// Round 9
	rk += 4;
	b3 = rotr((b2 ^ RK(rk, 3)) + (b3 ^ RK(rk, 1)), 3);
	b2 = rotr((b1 ^ RK(rk, 2)) + (b2 ^ RK(rk, 1)), 5);
	b1 = rotl((b0 ^ RK(rk, 0)) + (b1 ^ RK(rk, 1)), 9);
	
	// Round 10
	rk += 4;
	b0 = rotr((b3 ^ RK(rk, 3)) + (b0 ^ RK(rk, 1)), 3);
	b3 = rotr((b2 ^ RK(rk, 2)) + (b3 ^ RK(rk, 1)), 5);
	b2 = rotl((b1 ^ RK(rk, 0)) + (b2 ^ RK(rk, 1)), 9);
	
	// Round 11
	rk += 4;
	b1 = rotr((b0 ^ RK(rk, 3)) + (b1 ^ RK(rk, 1)), 3);
	b0 = rotr((b3 ^ RK(rk, 2)) + (b0 ^ RK(rk, 1)), 5);
	b3 = rotl((b2 ^ RK(rk, 0)) + (b3 ^ RK(rk, 1)), 9);
	
	// Round 12
	rk += 4;
	b2 = rotr((b1 ^ RK(rk, 3)) + (b2 ^ RK(rk, 1)), 3);
	b1 = rotr((b0 ^ RK(rk, 2)) + (b1 ^ RK(rk, 1)), 5);
	b0 = rotl((b3 ^ RK(rk, 0)) + (b0 ^ RK(rk, 1)), 9);
	
	// Round 13
	rk += 4;
	b3 = rotr((b2 ^ RK(rk, 3)) + (b3 ^ RK(rk, 1)), 3);
	b2 = rotr((b1 ^ RK(rk, 2)) + (b2 ^ RK(rk, 1)), 5);
	b1 = rotl((b0 ^ RK(rk, 0)) + (b1 ^ RK(rk, 1)), 9);
	
	// Round 14
	rk += 4;
	b0 = rotr((b3 ^ RK(rk, 3)) + (b0 ^ RK(rk, 1)), 3);
	b3 = rotr((b2 ^ RK(rk, 2)) + (b3 ^ RK(rk, 1)), 5);
	b2 = rotl((b1 ^ RK(rk, 0)) + (b2 ^ RK(rk, 1)), 9);
	
	// Round 15
	rk += 4;
	b1 = rotr((b0 ^ RK(rk, 3)) + (b1 ^ RK(rk, 1)), 3);
	b0 = rotr((b3 ^ RK(rk, 2)) + (b0 ^ RK(rk, 1)), 5);
	b3 = rotl((b2 ^ RK(rk, 0)) + (b3 ^ RK(rk, 1)), 9);
	
	// Round 16
	rk += 4;
	b2 = rotr((b1 ^ RK(rk, 3)) + (b2 ^ RK(rk, 1)), 3);
	b1 = rotr((b0 ^ RK(rk, 2)) + (b1 ^ RK(rk, 1)), 5);
	b0 = rotl((b3 ^ RK(rk, 0)) + (b0 ^ RK(rk, 1)), 9);
	
	// Round 17
	rk += 4;
	b3 = rotr((b2 ^ RK(rk, 3)) + (b3 ^ RK(rk, 1)), 3);
	b2 = rotr((b1 ^ RK(rk, 2)) + (b2 ^ RK(rk, 1)), 5);
	b1 = rotl((b0 ^ RK(rk, 0)) + (b1 ^ RK(rk, 1)), 9);
	
	// Round 18
	rk += 4;
	b0 = rotr((b3 ^ RK(rk, 3)) + (b0 ^ RK(rk, 1)), 3);
	b3 = rotr((b2 ^ RK(rk, 2)) + (b3 ^ RK(rk, 1)), 5);
	b2 = rotl((b1 ^ RK(rk, 0)) + (b2 ^ RK(rk, 1)), 9);
	
	// Round 19
	rk += 4;
	b1 = rotr((b0 ^ RK(rk, 3)) + (b1 ^ RK(rk, 1)), 3);
	b0 = rotr((b3 ^ RK(rk, 2)) + (b0 ^ RK(rk, 1)), 5);
	b3 = rotl((b2 ^ RK(rk, 0)) + (b3 ^ RK(rk, 1)), 9);
	
	// Round 20
	rk += 4;
	b2 = rotr((b1 ^ RK(rk, 3)) + (b2 ^ RK(rk, 1)), 3);
	b1 = rotr((b0 ^ RK(rk, 2)) + (b1 ^ RK(rk, 1)), 5);
	b0 = rotl((b3 ^ RK(rk, 0)) + (b0 ^ RK(rk, 1)), 9);
	
	// Round 21
	rk += 4;
	b3 = rotr((b2 ^ RK(rk, 3)) + (b3 ^ RK(rk, 1)), 3);
	b2 = rotr((b1 ^ RK(rk, 2)) + (b2 ^ RK(rk, 1)), 5);
	b1 = rotl((b0 ^ RK(rk, 0)) + (b1 ^ RK(rk, 1)), 9);
	
	// Round 22
	rk += 4;
	b0 = rotr((b3 ^ RK(rk, 3)) + (b0 ^ RK(rk, 1)), 3);
	b3 = rotr((b2 ^ RK(rk, 2)) + (b3 ^ RK(rk, 1)), 5);
	b2 = rotl((b1 ^ RK(rk, 0)) + (b2 ^ RK(rk, 1)), 9);
	
	// Round 23
	rk += 4;
	b1 = rotr((b0 ^ RK(rk, 3)) + (b1 ^ RK(rk, 1)), 3);
	b0 = rotr((b3 ^ RK(rk, 2)) + (b0 ^ RK(rk, 1)), 5);
	b3 = rotl((b2 ^ RK(rk, 0)) + (b3 ^ RK(rk, 1)), 9);
	
	// Round 24
	rk += 4;
	b2 = rotr((b1 ^ RK(rk, 3)) + (b2 ^ RK(rk, 1)), 3);
	b1 = rotr((b0 ^ RK(rk, 2)) + (b1 ^ RK(rk, 1)), 5);
	b0 = rotl((b3 ^ RK(rk, 0)) + (b0 ^ RK(rk, 1)), 9);
	
	blk[0] = b0;
	blk[1] = b1;
	blk[2] = b2;
	blk[3] = b3;
}

#endif
