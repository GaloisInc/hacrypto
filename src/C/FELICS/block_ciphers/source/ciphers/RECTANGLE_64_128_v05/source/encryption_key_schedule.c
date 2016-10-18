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
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    	/*------------------------------------------------------*/
        /* Registers allocation:				*/
        /* r0-r3   :   						*/
        /* r4-r19  : key state                           	*/
	/* r20-r23 : temp use	                           	*/
        /* r24     : currentRound				*/
        /* r25     : 						*/
        /* r26:r27 : X point to key				*/
        /* r28:r29 : Y point to roundKeys			*/
        /* r30:r31 : Z point to RC				*/
        /* ---------------------------------------------------- */
    asm volatile (
	"push 		r4			\n\t"
	"push 		r5			\n\t"
	"push 		r6			\n\t"
	"push 		r7			\n\t"
	"push 		r8			\n\t"
	"push 		r9			\n\t"
	"push 		r10			\n\t"
	"push 		r11			\n\t"
	"push 		r12			\n\t"
	"push 		r13			\n\t"
	"push 		r14			\n\t"
	"push 		r15			\n\t"
	"push 		r16			\n\t"
	"push 		r17			\n\t"
	"push 		r28			\n\t"
	"push 		r29			\n\t"
	/* ---------------------------------------------------- */
	"movw 		r28, 		r30			\n\t"
	"ldi 		r30, 		lo8(RC)          	\n\t"
	"ldi 		r31, 		hi8(RC)         	\n\t"
	load_key(r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19)
	store_subkey_first(r4, r5, r8, r9, r12, r13, r16, r17)
	"ldi 		r24,		25			\n\t"
	/* key schedule						*/
    "extend_loop:                      				\n\t"
	forward_key_update(r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23)
	/* store key: store_subkey(k0, k1, k4, k8, k9, k12) 	*/
	store_subkey(r4, r5, r8, r12, r13, r16)
	"dec 		r24                          		\n\t"
	"brne extend_loop                        		\n\t"
	/* ---------------------------------------------------- */
	"pop 		r29			\n\t"
	"pop 		r28			\n\t"
	"pop 		r17			\n\t"
	"pop 		r16			\n\t"
	"pop 		r15			\n\t"
	"pop 		r14			\n\t"
	"pop 		r13			\n\t"
	"pop 		r12			\n\t"
	"pop 		r11			\n\t"
	"pop 		r10			\n\t"
	"pop 		r9			\n\t"
	"pop 		r8			\n\t"
	"pop 		r7			\n\t"
	"pop 		r6			\n\t"
	"pop 		r5			\n\t"
	"pop 		r4			\n\t"
    :
    : [key] "x" (key), [roundKeys] "z" (roundKeys), [RC] "" (RC)); 
}

#else
#include "data_types.h"
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t key8[16];
	/* the master key can not be modified. */
	uint8_t i;
	for ( i = 0; i < KEY_SIZE; i++) {
		key8[i] = key[i];
	}

	uint16_t* key16 = (uint16_t*)key8;

	/* the first round keys */
	roundKeys[0] = key8[5];
	roundKeys[1] = key8[13];
	roundKeys[2] = key8[0];
	roundKeys[3] = key8[4];
	roundKeys[4] = key8[8];
	roundKeys[5] = key8[12];
	roundKeys[6] = key8[9];
	roundKeys[7] = key8[1];

	/* key schedule */
	uint8_t sbox0, sbox1;
	uint16_t halfRow2;
	uint32_t tempRow0;
	uint8_t index = 8;
	for ( i = 1; i <= NUMBER_OF_ROUNDS; i++) {
		/* S box */
		sbox0    =  key8[8];
		key8[8]  ^= key8[4];
		key8[4]  =  ~key8[4];
		sbox1    =  key8[0];
		key8[0]  &= key8[4];
		key8[4]  |= key8[12];
		key8[4]  ^= sbox1;
		key8[12] ^= sbox0;
		key8[0]  ^= key8[12];
		key8[12] &= key8[4];
		key8[12] ^= key8[8];
		key8[8]  |= key8[0];
		key8[8]  ^= key8[4];
		key8[4]  ^= sbox0;
		/* row */
		tempRow0 = *((uint32_t*)key8);
		*((uint32_t*)key8) = (tempRow0<<8 | tempRow0>>24) ^ *((uint32_t*)key8+1);
		*((uint32_t*)key8+1) = *((uint32_t*)key8+2);
		halfRow2 = *(key16+4);
		*(key16+4) = *(key16+5) ^ *(key16+6);
		*(key16+5) = halfRow2 ^ *(key16+7);
		*((uint32_t*)key8+3) = tempRow0;
		/* round const */
		*key8 ^= READ_RC_BYTE(RC[i-1]);
		/* store round key */
		roundKeys[index++] = key8[0];
		roundKeys[index++] = key8[4];
		roundKeys[index++] = key8[8];
		roundKeys[index++] = key8[12];
		roundKeys[index++] = key8[9];
		roundKeys[index++] = key8[1];
	}
}
#endif
