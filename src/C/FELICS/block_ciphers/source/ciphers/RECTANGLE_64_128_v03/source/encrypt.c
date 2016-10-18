/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security, 
 * Institute of Information Engineering
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * Written in 2016 by Luo Peng <luopeng@iie.ac.cn>,
 *					  Bao Zhenzhen <baozhenzhen@iie.ac.cn>,
 *					  Zhang Wentao <zhangwentao@iie.ac.cn>
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

#ifdef AVR
#include "avr_basic_asm_macros.h"
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	/*------------------------------------------------------*/
        /* Registers allocation:				*/
        /* r0-r11  :   						*/
        /* r12-r19 : plain text					*/
        /* r20-r23 : temp use                           	*/
        /* r24     : currentRound				*/
        /* r25     : zero					*/
        /* r26:r27 : X point to plain text			*/
        /* r28:r29 : Y 						*/
        /* r30:r31 : Z roundKeys				*/
        /* ---------------------------------------------------- */
        /* Store all modified registers				*/
        /* ---------------------------------------------------- */
    asm volatile(
	/*
	 * http://www.atmel.com/webdoc/AVRLibcReferenceManual/FAQ_1faq_reg_usage.html
	 * 
	 * GCC AVR passes arguments from left to right in r25-r8. All arguments are aligned to start in even-numbered registers. 
	 * 			Pointers are 16-bits, so arguments are in r25:r24 and r23:22
	 * [r18-r27, r30-r31]:	You may use them freely in assembler subroutines. The caller is responsible for saving and restoring.
	 * [r2-r17, r28-r29]:	Calling C subroutines leaves them unchanged. Assembler subroutines are responsible for saving and restoring these 
	 * 			registers
	 * [r0, r1]:		Fixed registers. Never allocated by gcc for local data.
	 */
	"push 		r12			\n\t"
	"push 		r13			\n\t"
	"push 		r14			\n\t"
	"push 		r15			\n\t"
	"push 		r16			\n\t"
	"push 		r17			\n\t"
	/* ---------------------------------------------------- */
	/*
	 * input/output state s1:s0: a
	 * input/output state s3:s2: b
	 * input/output state s5:s4: c
	 * input/output state s7:s6: d
	 */
	/* load plain text					*/
	"ld 		r12, 		x+                      \n\t"
	"ld 		r13, 		x+                      \n\t"
	"ld 		r14, 		x+                      \n\t"
	"ld 		r15, 		x+                      \n\t"
	"ld 		r16, 		x+                      \n\t"
	"ld 		r17, 		x+                      \n\t"
	"ld 		r18, 		x+                      \n\t"
	"ld 		r19, 		x                       \n\t"
	/* set currentRound	 				*/
	"ldi 		r24,		25			\n\t"
	/* used for const zero 					*/
	"clr 		r25					\n\t"
	/* ---------------------------------------------------- */
	/* encryption 						*/
    "enc_loop:                      				\n\t"
	keyxor(r12, r13, r14, r15, r16, r17, r18, r19, r20)
	enc_round(r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r25)
	/* loop control 					*/
	"dec 		r24                          		\n\t"
	"brne		enc_loop				\n\t"
    "last_round:						\n\t"
	keyxor(r12, r13, r14, r15, r16, r17, r18, r19, r20)
	/* ---------------------------------------------------- */
	/* store cipher text 					*/
	"st 		x,  		r19			\n\t"
	"st 		-x, 		r18			\n\t"
	"st 		-x, 		r17			\n\t"
	"st 		-x, 		r16			\n\t"
	"st 		-x, 		r15			\n\t"
	"st 		-x, 		r14			\n\t"
	"st 		-x, 		r13			\n\t"
	"st 		-x, 		r12			\n\t"
	/* ---------------------------------------------------- */
	"pop 		r17			\n\t"
	"pop 		r16			\n\t"
	"pop 		r15			\n\t"
	"pop 		r14			\n\t"
	"pop 		r13			\n\t"
	"pop 		r12			\n\t"
    :
    : [block] "x" (block), [roundKeys] "z" (roundKeys));
}

#else
#ifdef MSP
#include "msp430_basic_asm_macros.h"
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	/*------------------------------------------------------*/
        /* Registers allocation:				*/
        /* r0-r3   :   						*/
        /* r4-r7   : plain text                           	*/
	/* r8-r9   : temp use                           	*/
        /* r12     : temp use					*/
        /* r13     : currentRound				*/
        /* r14     : point to roundKeys				*/
        /* r15     : block					*/
        /* ---------------------------------------------------- */
        /* Store all modified registers				*/
        /* ---------------------------------------------------- */
    asm volatile (
	/*
	 * http://www.ti.com/lit/an/slaa664/slaa664.pdf
	 *
	 * [r15-r12]: In MSPGCC, registers are passed starting with R15 and descending to R12. For example, if two integers are passed, 
	 * 	      the first is passed in R15 and the second is passed in R14.
	 * [r11-r4]:  r11-r4 must be pushed if used.
	 */
	"push 		r4			\n\t"
	"push 		r5			\n\t"
	"push 		r6			\n\t"
	"push 		r7			\n\t"
	"push 		r8			\n\t"
	/* ---------------------------------------------------- */
	/* load plain text					*/
        "mov    	@r15+,       	r4			\n\t" /* r15 will add two */ 
        "mov    	@r15+,       	r5			\n\t"
        "mov    	@r15+,       	r6			\n\t"
        "mov    	@r15+,       	r7			\n\t"
	/* set currentRound	 				*/
	"mov 		#25,		r13			\n\t"
	/* ---------------------------------------------------- */
	/* encryption						*/
    "enc_loop:                      				\n\t"
	/* enc_round(s0, s1, s2, s3, x, t0, t1)			*/
	enc_round(r4, r5, r6, r7, r14, r8, r12)
	/* loop control 					*/
	"dec		r13					\n\t"
	"jne		enc_loop				\n\t"
	keyxor(r4, r5, r6, r7, r8, r14)
	/* ---------------------------------------------------- */
	/* store cipher text 					*/
	"mov		r4,		-8(r15)			\n\t"
	"mov		r5,		-6(r15)			\n\t"
	"mov		r6,		-4(r15)			\n\t"
	"mov		r7,		-2(r15)			\n\t"
	/* ---------------------------------------------------- */
	"pop 		r8			\n\t"
	"pop 		r7			\n\t"
	"pop 		r6			\n\t"
	"pop 		r5			\n\t"
	"pop 		r4			\n\t"	
    :
    : [block] "m" (block), [roundKeys] "m" (roundKeys)); 
}

#else
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t *block32 = (uint32_t*)block;
	uint32_t *roundKeys32 = (uint32_t*)roundKeys;

	uint32_t temprk = *block32;
	uint16_t w0 = (uint16_t)temprk;		// first line
	uint16_t w1 = (uint16_t)(temprk>>16);	// second line
	temprk = *(block32+1);
	uint16_t w2 = (uint16_t)temprk;		// third line
	uint16_t w3 = (uint16_t)(temprk>>16);	// forth line

	uint16_t sbox0, sbox1;
	uint8_t i;
	for ( i = 0; i < NUMBER_OF_ROUNDS; i++ ) {
		/* AddRoundKey */
		temprk = READ_ROUND_KEY_DOUBLE_WORD(*roundKeys32++);
		w0 ^= (uint16_t)temprk;
		w1 ^= (uint16_t)(temprk>>16);
		temprk = READ_ROUND_KEY_DOUBLE_WORD(*(roundKeys32++));
		w2 ^= (uint16_t)temprk;
		w3 ^= (uint16_t)(temprk>>16);
		/* SubColumn */	
		sbox1 = ~w1;
		sbox0 = sbox1 | w3;
		sbox0 ^= w0;
		w0 &= sbox1;
		sbox1 = w2 ^ w3;
		w0 ^= sbox1;
		w3 = w1 ^ w2;
		w1 = w2 ^ sbox0;
		sbox1 &= sbox0;
		w3 ^= sbox1;
		w2 = w0 | w3;
		w2 ^= sbox0;
		/* ShiftRow */
		w1 = (w1<<1  | w1 >> 15);
		w2 = (w2<<12 | w2 >> 4);
		w3 = (w3<<13 | w3 >> 3);
	}
	/* last round add key */
	temprk = READ_ROUND_KEY_DOUBLE_WORD(*roundKeys32++);
	w0 ^= (uint16_t)temprk;
	w1 ^= (uint16_t)(temprk>>16);
	temprk = READ_ROUND_KEY_DOUBLE_WORD(*roundKeys32++);
	w2 ^= (uint16_t)temprk;
	w3 ^= (uint16_t)(temprk>>16);
	/* store cipher text */
	*block32 = ((uint32_t)w1<<16) + w0;
	*(block32+1) = ((uint32_t)w3<<16) + w2;
}
#endif
#endif
