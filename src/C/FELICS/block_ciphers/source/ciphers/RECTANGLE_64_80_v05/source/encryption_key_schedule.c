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
/*
 * Optimized for RAM
 */
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    	/*------------------------------------------------------*/
        /* Registers allocation:				*/
        /* r0-r7   :   						*/
        /* r8-r13  : temp use                           	*/
	/* r14-r15 : k8-k9					*/
	/* r16-r23 : k0-k7	                           	*/
        /* r24     : 0xf0					*/
	/* r25     : currentRound				*/
        /* r26:r27 : X point to key				*/
        /* r28:r29 : Y point to roundKeys			*/
        /* r30:r31 : Z point to RC				*/
        /* ---------------------------------------------------- */
        /* Store all modified registers				*/
        /* ---------------------------------------------------- */
    asm volatile (
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
	"ldi		r25,		25			\n\t"
	"ldi		r24,		0xf0			\n\t"
	/* ---------------------------------------------------- */
	/* load_key(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9) 	*/
	load_key(r16, r17, r18, r19, r20, r21, r22, r23, r14, r15)
	/* store_subkey(k0, k1, k2, k3, k4, k5, k6, k7) 	*/
	store_subkey_first(r16, r17, r18, r19, r20, r21, r22, r23)
	/* key schedule						*/
    "extend_loop:                      				\n\t"
	forward_key_update(r16, r17, r18, r19, r20, r21, r22, r23, r14, r15, r8, r9, r10, r11, r12, r13, r24)
	store_subkey(r16, r17, r18, r20, r22, r23)
	"dec 		r25                          		\n\t"
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
    :
    : [key] "x" (key), [roundKeys] "z" (roundKeys), [RC] "" (RC)); 
}

#else
#include "data_types.h"
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t key8[10];
	/* the master key can not be modified. */
	uint8_t i;
	for ( i = 0; i < KEY_SIZE; i++) {
		key8[i] = key[i];
	}

	uint16_t *key16 = (uint16_t*)key8;

	/* the first round keys */
	roundKeys[0] = key8[3];
	roundKeys[1] = key8[5];
	roundKeys[2] = key8[0];
	roundKeys[3] = key8[1];
	roundKeys[4] = key8[2];
	roundKeys[5] = key8[4];
	roundKeys[6] = key8[6];
	roundKeys[7] = key8[7];
	uint8_t index = 8;

	/* key schedule */
	uint8_t sbox0, sbox1;
	uint8_t temp[4];
	uint16_t tempk0;
	for ( i = 1; i <= NUMBER_OF_ROUNDS; i++) {
		temp[0] = key8[0];
		temp[1] = key8[2];
		temp[2] = key8[4];
		temp[3] = key8[6];
		/* S box */
		sbox0    =  key8[4];
		key8[4]  ^= key8[2];
		key8[2]  =  ~key8[2];
		sbox1    =  key8[0];
		key8[0]  &= key8[2];
		key8[2]  |= key8[6];
		key8[2]  ^= sbox1;
		key8[6] ^= sbox0;
		key8[0]  ^= key8[6];
		key8[6] &= key8[2];
		key8[6] ^= key8[4];
		key8[4]  |= key8[0];
		key8[4]  ^= key8[2];
		key8[2]  ^= sbox0;
		/* just change 4-bit*/
		key8[0] = (key8[0]&0x0f) ^ (temp[0]&0xf0);
		key8[2] = (key8[2]&0x0f) ^ (temp[1]&0xf0);
		key8[4] = (key8[4]&0x0f) ^ (temp[2]&0xf0);
		key8[6] = (key8[6]&0x0f) ^ (temp[3]&0xf0);
		/* row */
		tempk0 = *(key16);
		*(key16) = *(key16+1);
		*(key16+1) = *(key16+2);
		*(key16+2) = *(key16+3);
		*(key16+3) = *(key16+4);
		*(key16+4) = tempk0;
		*(key16) ^= ((tempk0<<8)|(tempk0>>8));
		tempk0 = *(key16+2);
		*(key16+3) ^= ((tempk0<<12)|(tempk0>>4));
		/* round const */
		*key8 ^= READ_RC_BYTE(RC[i-1]);
		/* store round key */
		roundKeys[index++] = key8[0];
		roundKeys[index++] = key8[1];
		roundKeys[index++] = key8[2];
		roundKeys[index++] = key8[4];
		roundKeys[index++] = key8[6];
		roundKeys[index++] = key8[7];
	}
}
#endif
