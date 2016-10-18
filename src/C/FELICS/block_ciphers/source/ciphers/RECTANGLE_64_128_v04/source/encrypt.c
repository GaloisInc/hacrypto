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

/*
 * For AVR, 8-bit operations always
 * For MSP, 16-bit operations when possible
 * For ARM, 32-bit operations when possible
 */

#ifdef AVR
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t s0 = *block;     // first line
	uint8_t s1 = *(block+1);
	uint8_t s2 = *(block+2); // second line
	uint8_t s3 = *(block+3);
	uint8_t s4 = *(block+4); // third line
	uint8_t s5 = *(block+5); 
	uint8_t s6 = *(block+6); // forth line
	uint8_t s7 = *(block+7);

	uint8_t sbox0, sbox1;
	uint8_t i;
	for ( i = 0; i < NUMBER_OF_ROUNDS; i++ ) {
		/* AddRoundKey */
		s0 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
		s1 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
		s2 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
		s3 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
		s4 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
		s5 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
		s6 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
		s7 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));

		/* SubColumn */
		// lower byte
		sbox0 =  s4;
		s4    ^= s2;
		s2    =  ~s2;
		sbox1 =  s0;
		s0    &= s2;
		s2    |= s6;
		s2    ^= sbox1;
		s6    ^= sbox0;
		s0    ^= s6;
		s6    &= s2;
		s6    ^= s4;
		s4    |= s0;
		s4    ^= s2;
		s2    ^= sbox0;
		// higher byte
		sbox0 =  s5;
		s5    ^= s3;
		s3    =  ~s3;
		sbox1 =  s1;
		s1    &= s3;
		s3    |= s7;
		s3    ^= sbox1;
		s7    ^= sbox0;
		s1    ^= s7;
		s7    &= s3;
		s7    ^= s5;
		s5    |= s1;
		s5    ^= s3;
		s3    ^= sbox0;

		/* ShiftRow */
		// s3 s2 <<< 1
		sbox0 = s2;
		s2 = (s2<<1 | s3>>7);
		s3 = (s3<<1 | sbox0>>7);
		// s5 s4 <<< 12 ==== s5 s4 >>> 4
		sbox0 = s4;
		s4 = (s4>>4 | s5<<4);
		s5 = (s5>>4 | sbox0<<4);
		// s7 s6 <<< 13 ==== s7 s6 >>> 3
		sbox0 = s6;
		s6 = (s6>>3 | s7<<5);
		s7 = (s7>>3 | sbox0<<5);
	}
	/* last round add key */
	s0 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
	s1 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
	s2 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
	s3 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
	s4 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
	s5 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
	s6 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
	s7 ^= READ_ROUND_KEY_BYTE(*(roundKeys++));
	/* store cipher text */
	*block = s0;
	*(block+1) = s1;
	*(block+2) = s2;
	*(block+3) = s3;
	*(block+4) = s4;
	*(block+5) = s5;
	*(block+6) = s6;
	*(block+7) = s7;
}

#else
#ifdef MSP
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint16_t *block16 = (uint16_t*)block;
	uint16_t *roundKeys16 = (uint16_t*)roundKeys;

	uint16_t w0 = *block16;     // first line
	uint16_t w1 = *(block16+1); // second line
	uint16_t w2 = *(block16+2); // third line
	uint16_t w3 = *(block16+3); // forth line

	uint16_t sbox0, sbox1;
	uint8_t i;
	for ( i = 0; i < NUMBER_OF_ROUNDS; i++ ) {
		/* AddRoundKey */
		w0 ^= READ_ROUND_KEY_WORD(*(roundKeys16));
		w1 ^= READ_ROUND_KEY_WORD(*(roundKeys16+1));
		w2 ^= READ_ROUND_KEY_WORD(*(roundKeys16+2));
		w3 ^= READ_ROUND_KEY_WORD(*(roundKeys16+3));
		roundKeys16 += 4;
		/* SubColumn */
		sbox0 =  w2;
		w2    ^= w1;
		w1    =  ~w1;
		sbox1 =  w0;
		w0    &= w1;
		w1    |= w3;
		w1    ^= sbox1;
		w3    ^= sbox0;
		w0    ^= w3;
		w3    &= w1;
		w3    ^= w2;
		w2    |= w0;
		w2    ^= w1;
		w1    ^= sbox0;
		/* ShiftRow */
		w1 = (w1<<1  | w1 >> 15);
		w2 = (w2<<12 | w2 >> 4);
		w3 = (w3<<13 | w3 >> 3);
	}
	/* last round add key */
	w0 ^= READ_ROUND_KEY_WORD(*(roundKeys16));
	w1 ^= READ_ROUND_KEY_WORD(*(roundKeys16+1));
	w2 ^= READ_ROUND_KEY_WORD(*(roundKeys16+2));
	w3 ^= READ_ROUND_KEY_WORD(*(roundKeys16+3));
	/* store cipher text */
	*block16 = w0;
	*(block16+1) = w1;
	*(block16+2) = w2;
	*(block16+3) = w3;
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
