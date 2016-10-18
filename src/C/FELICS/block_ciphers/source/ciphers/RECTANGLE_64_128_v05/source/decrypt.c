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
 * Written in 2016 by Bao Zhenzhen <baozhenzhen@iie.ac.cn>,
 *		      Luo Peng <luopeng@iie.ac.cn>
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
        /* r0-r11  :   						*/
	/* r12-r13 : the fixed two-byte sub keys of last round	*/
        /* r14-r21 : cipher text				*/
	/* r22-r23 : temp use	                           	*/
        /* r24     : currentRound				*/
        /* r25     : zero					*/
        /* r26:r27 : X point to cipher text			*/
        /* r28:r29 : Y 						*/
        /* r30:r31 : Z roundKeys				*/
        /* ---------------------------------------------------- */
    asm volatile (
	"push 		r12			\n\t"
	"push 		r13			\n\t"
	"push 		r14			\n\t"
	"push 		r15			\n\t"
	"push 		r16			\n\t"
	"push 		r17			\n\t"
	/* used for const zero 					*/
	"clr 		r25					\n\t"
	/* let z points to roundKeys 				*/
    #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
	"ldi		r24,		156			\n\t"
    #else
	"ldi		r24,		158			\n\t"
    #endif
	"add		r30,		r24			\n\t"
	"adc		r31,		r25			\n\t"
	/* set currentRound to zero 				*/
	"ldi 		r24,		25			\n\t"
	/* load cipher text					*/
	"ld 		r14, 		x+			\n\t"
	"ld 		r15, 		x+			\n\t"
	"ld 		r16, 		x+			\n\t"
	"ld 		r17, 		x+			\n\t"
	"ld 		r18, 		x+			\n\t"
	"ld 		r19, 		x+			\n\t"
	"ld 		r20, 		x+			\n\t"
	"ld 		r21, 		x			\n\t"
	/* ---------------------------------------------------- */
	/* decryption 						*/
	/* load the first two bytes				*/
    #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
	"lpm		r12,		z+			\n\t"
	"lpm		r13,		z+			\n\t"
	"sbiw		r30,		8			\n\t"
    #else
	"ld		r13,		-z			\n\t"
	"ld		r12,		-z			\n\t"
    #endif
    "dec_loop:                      				\n\t"
	dec_keyxor(r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22)
	dec_round(r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r25)
	"dec 		r24                          		\n\t"
	"brne		dec_loop                       		\n\t"
    "last_round:						\n\t"
	dec_keyxor(r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22)
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
	"pop 		r13			\n\t"
	"pop 		r12			\n\t"
    :
    : [block] "x" (block), [roundKeys] "z" (roundKeys));
}

#else
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint16_t *block16 = (uint16_t*)block;
	uint16_t *roundKeys16 = (uint16_t*)roundKeys;

	uint16_t w0 = *block16;     // first line
	uint16_t w1 = *(block16+1); // second line
	uint16_t w2 = *(block16+2); // third line
	uint16_t w3 = *(block16+3); // forth line

	roundKeys16 += 78;
	uint16_t k0, k3;
	uint32_t k12;
	k3 = READ_ROUND_KEY_WORD(*roundKeys16);
	
	uint16_t sbox0;
	uint8_t i;
	for ( i = 0; i < NUMBER_OF_ROUNDS; i++ ) {
		/* AddRoundKey */
		k12 = READ_ROUND_KEY_DOUBLE_WORD(*(uint32_t*)(roundKeys16-2));
		k0 = READ_ROUND_KEY_WORD(*(roundKeys16-3));
		w0 ^= ( (k3&0xff00) | (((uint16_t)k12)&0x00ff) );
		w1 ^= ( (k0<<8) | (((uint16_t)k12)>>8) );
		w2 ^= ( (k3<<8) | (((uint16_t)(k12>>16))&0x00ff) );
		w3 ^= ( (k0&0xff00) | ((uint16_t)(k12>>24)) );
		roundKeys16 -= 3;
		k3 = k0;
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
	k12 = READ_ROUND_KEY_DOUBLE_WORD(*(uint32_t*)(roundKeys16-2));
	k0 = READ_ROUND_KEY_WORD(*(roundKeys16-3));
	w0 ^= ( (k3&0xff00) | (((uint16_t)k12)&0x00ff) );
	w1 ^= ( (k0<<8) | (((uint16_t)k12)>>8) );
	w2 ^= ( (k3<<8) | (((uint16_t)(k12>>16))&0x00ff) );
	w3 ^= ( (k0&0xff00) | ((uint16_t)(k12>>24)) );
	/* store cipher text */
	*block16 = w0;
	*(block16+1) = w1;
	*(block16+2) = w2;
	*(block16+3) = w3;
}
#endif
