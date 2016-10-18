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
 *		      Bao Zhenzhen <baozhenzhen@iie.ac.cn>,
 *		      Zhang Wentao <zhangwentao@iie.ac.cn>
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
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	/*------------------------------------------------------*/
        /* Registers allocation:				*/
        /* r0-r13  :   						*/
        /* r14-r21 : cipher text				*/
	/* r22-r23 : temp use	                           	*/
        /* r24     : currentRound				*/
        /* r25     : zero					*/
        /* r26:r27 : X point to cipher text			*/
        /* r28:r29 : Y 						*/
        /* r30:r31 : Z roundKeys				*/
        /* ---------------------------------------------------- */
    asm volatile (
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
	"push 		r14			\n\t"
	"push 		r15			\n\t"
	"push 		r16			\n\t"
	"push 		r17			\n\t"
	/*
	 * input/output state s1:s0: a
	 * input/output state s3:s2: b
	 * input/output state s5:s4: c
	 * input/output state s7:s6: d
	 */
	"clr 		r25					\n\t"
    #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
	"ldi		r24,		200			\n\t"
    #else
	"ldi		r24,		208			\n\t"
    #endif
	/* The source register can not be r24. So adiw is wrong	*/
	"add		r30,		r24			\n\t"
	"adc		r31,		r25			\n\t"
	/* set currentRound	 				*/
	"ldi		r24,		25			\n\t"
	/* load cipher text					*/
	"ld 		r14, 		x+			\n\t"
	"ld 		r15, 		x+			\n\t"
	"ld 		r16, 		x+			\n\t"
	"ld 		r17, 		x+			\n\t"
	"ld 		r18, 		x+			\n\t"
	"ld 		r19, 		x+			\n\t"
	"ld 		r20, 		x+			\n\t"
	"ld 		r21, 		x			\n\t"
	/* decryption 						*/
    "dec_loop:                      				\n\t"
	dec_keyxor(r14, r15, r16, r17, r18, r19, r20, r21, r22)
	dec_round(r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r25)
	/* brne <==> PC<----PC+k+1. -64 <= k <= 63		*/
	/* For scenario1, 64 instrucions is before. therefore dec(replace inc and cpi) and cpse can be used to reduce one instruction. */
	/* For scenario2, there is a sbiw instrucion in keyeor(-65 < -64). So dec can not be used.*/
	"dec		r24					\n\t"
	"breq		last_round                       	\n\t"
	"rjmp		dec_loop				\n\t"
    "last_round:						\n\t"
	dec_keyxor(r14, r15, r16, r17, r18, r19, r20, r21, r22)
	/* store plain text 					*/
	"st 		x,  		r21			\n\t"
	"st 		-x,  		r20			\n\t"
	"st 		-x,  		r19			\n\t"
	"st 		-x, 		r18			\n\t"
	"st 		-x, 		r17			\n\t"
	"st 		-x, 		r16			\n\t"
	"st 		-x, 		r15			\n\t"
	"st 		-x, 		r14			\n\t"
	/* ---------------------------------------------------- */
	"pop 		r17			\n\t"
	"pop 		r16			\n\t"
	"pop 		r15			\n\t"
	"pop 		r14			\n\t"
    :
    : [block] "x" (block), [roundKeys] "z" (roundKeys));
}

#else
#ifdef MSP
#include "msp430_basic_asm_macros.h"
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	/*------------------------------------------------------*/
        /* Registers allocation:				*/
        /* r0-r3   :   						*/
        /* r4-r7   : cipher text                           	*/
	/* r8	   : temp use                           	*/
        /* r12     : temp use					*/
        /* r13     : currentRound				*/
        /* r14     : point to roundKeys				*/
        /* r15     : pointer to block				*/
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
	/* load cipher text					*/
        "mov    	@r15+,       	r4			\n\t"
        "mov    	@r15+,       	r5			\n\t"
        "mov    	@r15+,       	r6			\n\t"
        "mov    	@r15+,       	r7			\n\t"
	/* set currentRound	 				*/
	"mov 		#25,		r13			\n\t"
	/* point to the last byte-8 (200) of roundKeys	 	*/
	"add		#200,		r14			\n"
	/* decryption						*/
    "dec_loop:                      				\n\t"
	/* dec_round(s0, s1, s2, s3, Z, t0, t1)			*/
	dec_round(r4, r5, r6, r7, r14, r8, r12)
	"sub		#8,		r14			\n\t"
	"dec		r13					\n\t"
	"jne		dec_loop				\n\t"
	dec_keyxor(r4, r5, r6, r7, r14)
	/* store plain text 					*/
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
#ifdef ARM
#include "arm_basic_asm_macros.h"
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	/* ---------------------------------------------------- */
        /* r0  - point of block					*/
        /* r1  - point of round keys				*/
        /* r2  - c0 16 bits					*/
        /* r3  - c1						*/
        /* r4  - c2						*/
        /* r5  - c3 16 bits					*/
        /* r6  - temp 0						*/
        /* r7  - temp 1						*/
        /* r8  - loop counter					*/
    asm volatile (
	/* the first argument is stored in r0, the second in r1 */
        "stmdb        	sp!,   		{r2-r9}			\n\t"
	"adds		r1,		r1,		#200	\n\t"
        "mov        	r8,           	#25			\n\t"
	/* load cipher text					*/
	"ldrd		r2,r4,		[r0,#0]			\n\t"
	"mov		r3,		r2,lsr #16		\n\t"
	"mov		r5,		r4,lsr #16		\n\t"
	/* decrypt						*/
    "dec_loop:                      				\n\t"
	dec_keyxor(r2, r3, r4, r5, r6, r7, r1)
	rotate16_right_row(r3, r4, r5)
	invert_sbox(r2, r3, r4, r5, r6, r7, r9)
	"subs		r8,		r8,		#1	\n\t"
	"bne		dec_loop				\n\t"
	dec_keyxor(r2, r3, r4, r5, r6, r7, r1)
	/* store plain text 					*/
	"bfi		r2,		r3,#16,#16		\n\t"
	"bfi		r4,		r5,#16,#16		\n\t"
	"strd		r2,r4,		[r0,#0]			\n\t"
        /* ---------------------------------------------------- */
        "ldmia		sp!,		{r2-r9}			\n\t"
    :
    : [block] "r" (block), [roundKeys] "r" (roundKeys));
}

#else
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint16_t *block16 = (uint16_t*)block;
	uint16_t *roundKeys16 = (uint16_t*)roundKeys;
	// point to the start address of round 26
	roundKeys16 += 100;

	uint16_t w0 = *block16;     // first line
	uint16_t w1 = *(block16+1); // second line
	uint16_t w2 = *(block16+2); // third line
	uint16_t w3 = *(block16+3); // forth line

	uint16_t sbox0;
	uint8_t i;
	for ( i = 0; i < NUMBER_OF_ROUNDS; i++ ) {
		/* AddRoundKey */
		w0 ^= READ_ROUND_KEY_WORD(*(roundKeys16));
		w1 ^= READ_ROUND_KEY_WORD(*(roundKeys16+1));
		w2 ^= READ_ROUND_KEY_WORD(*(roundKeys16+2));
		w3 ^= READ_ROUND_KEY_WORD(*(roundKeys16+3));
		roundKeys16 -= 4;
		/* ShiftRow */
		w1 = (w1>>1  | w1 << 15);
		w2 = (w2>>12 | w2 << 4);
		w3 = (w3>>13 | w3 << 3);
		/* Invert sbox */
		sbox0 =  w0;
		w0    &= w2;
		w0    ^= w3;
		w3    |= sbox0;
		w3    ^= w2;
		w1    ^= w3;
		w2    =  w1;
		w1    ^= sbox0;
		w1    ^= w0;
		w3    =  ~w3;
		sbox0 =  w3;
		w3    |= w1;
		w3    ^= w0;
		w0    &= w1;
		w0    ^= sbox0;
	}
	/* last round add key */
	w0 ^= READ_ROUND_KEY_WORD(*(roundKeys16));
	w1 ^= READ_ROUND_KEY_WORD(*(roundKeys16+1));
	w2 ^= READ_ROUND_KEY_WORD(*(roundKeys16+2));
	w3 ^= READ_ROUND_KEY_WORD(*(roundKeys16+3));
	/* store plain text */
	*block16 = w0;
	*(block16+1) = w1;
	*(block16+2) = w2;
	*(block16+3) = w3;
}
#endif
#endif
#endif
