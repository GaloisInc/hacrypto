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
	/* let y points to roundKeys				*/
	"movw 		r28, 		r30			\n\t"
	/* let z points to RC 					*/
	"ldi 		r30, 		lo8(RC)          	\n\t"
	"ldi 		r31, 		hi8(RC)         	\n\t"
	/* set currentRound to ROUNDS 				*/
	"ldi		r25,		25			\n\t"
	"ldi		r24,		0xf0			\n\t"
	/* ---------------------------------------------------- */
	/* load_key(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9) 	*/
	/* w0: k1:k0						*/
	/* w1: k3:k2						*/
	/* w2: k5:k4						*/
	/* w3: k7:k6						*/
	/* w4: k9:k8						*/
	load_key(r16, r17, r18, r19, r20, r21, r22, r23, r14, r15)
	/* store_subkey(k0, k1, k2, k3, k4, k5, k6, k7) 	*/
	store_subkey(r16, r17, r18, r19, r20, r21, r22, r23)
	/* ---------------------------------------------------- */
	/* key schedule						*/
    "extend_loop:                      				\n\t"
	/* forward_key_update(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, a0, a1, t0, t1, t2, t3, xf0) */
	forward_key_update(r16, r17, r18, r19, r20, r21, r22, r23, r14, r15, r8, r9, r10, r11, r12, r13, r24)
	/* store_subkey(k0, k1, k2, k3, k4, k5, k6, k7) 	*/
	store_subkey(r16, r17, r18, r19, r20, r21, r22, r23)
	/* loop control 					*/
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
#ifdef MSP
#include "msp430_basic_asm_macros.h"
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
 	/*------------------------------------------------------*/
        /* Registers allocation:				*/
        /* r0-r3   :   						*/
        /* r4-r7   : temp use					*/
	/* k8-k12  : key state                           	*/
        /* r13     : currentRound				*/
        /* r14     : point to roundKeys				*/
        /* r15     : point to key and RC			*/
        /* ---------------------------------------------------- */
        /* Store all modified registers				*/
        /* ---------------------------------------------------- */
    asm volatile (\
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
	"push 		r9			\n\t"
	"push 		r10			\n\t"
	"push 		r11			\n\t"
	/* ---------------------------------------------------- */
	/* load master key					*/
	/* w0: r8						*/
	/* w1: r9						*/
	/* w2: r10						*/
	/* w3: r11						*/
	/* w3: r12						*/
        "mov    	@r15+,       	r8			\n\t"
        "mov    	@r15+,      	r9			\n\t"
        "mov    	@r15+,      	r10			\n\t"
        "mov    	@r15+,      	r11			\n\t"
        "mov    	@r15+,       	r12			\n\t"
	store_subkey(r8, r9, r10, r11)
	/* ---------------------------------------------------- */
	"mov 		%[RC], 		r15  			\n\t"
	/* set currentRound to ROUNDS 				*/
	"mov 		#25,		r13			\n\t"
	/* make some place to store temp data			*/
	"sub		#4,		r1			\n\t"
	/* ---------------------------------------------------- */
	/* key schedule						*/
    "extend_loop:                    				\n\t"
	/* key_schedule(k0, k1, k2, k3, k4, t0, t1, t2, t3)	*/
	key_schedule(r8, r9, r10, r11, r12, r4, r5, r6, r7)
	store_subkey(r8, r9, r10, r11)
	/* loop control 					*/
	"dec		r13					\n\t"
	"jne		extend_loop				\n\t"
	"add		#4,		r1			\n\t"
	/* ---------------------------------------------------- */
	"pop 		r11			\n\t"
	"pop 		r10			\n\t"
	"pop 		r9			\n\t"
	"pop 		r8			\n\t"
	"pop 		r7			\n\t"
	"pop 		r6			\n\t"
	"pop 		r5			\n\t"
	"pop 		r4			\n\t"	
    :
    : [key] "m" (key), [roundKeys] "m" (roundKeys), [RC] "" (RC));
}

#else
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t key8[10];
	/* the master key can not be modified. */
	uint8_t i;
	*((uint16_t*)key8) = *((uint16_t*)key);
	*((uint16_t*)key8+1) = *((uint16_t*)key+1);
	*((uint16_t*)key8+2) = *((uint16_t*)key+2);
	*((uint16_t*)key8+3) = *((uint16_t*)key+3);
	*((uint16_t*)key8+4) = *((uint16_t*)key+4);

	uint16_t *key16 = (uint16_t*)key8;
	uint16_t *roundKeys16 = (uint16_t*)roundKeys;

	/* the first round keys */
	roundKeys16[0] = key16[0];
	roundKeys16[1] = key16[1];
	roundKeys16[2] = key16[2];
	roundKeys16[3] = key16[3];

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
		sbox1 = ~key8[2];
		sbox0 = sbox1 | key8[6];
		sbox0 ^= key8[0];
		key8[0] &= sbox1;
		sbox1 = key8[4] ^ key8[6];
		key8[0] ^= sbox1;
		key8[6] = key8[2] ^ key8[4];
		key8[2] = key8[4] ^ sbox0;
		sbox1 &= sbox0;
		key8[6] ^= sbox1;
		key8[4] = key8[0] | key8[6];
		key8[4] ^= sbox0;
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
		*key8 ^= READ_Z_BYTE(RC[i-1]);
		/* store round key */
		roundKeys16[4*i] = key16[0];
		roundKeys16[4*i+1] = key16[1];
		roundKeys16[4*i+2] = key16[2];
		roundKeys16[4*i+3] = key16[3];
	}
}
#endif
#endif
