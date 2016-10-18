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
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t key8[KEY_SIZE];
	/* the master key can not be modified. */
	uint8_t i;
	for ( i = 0; i < KEY_SIZE; i++) {
		key8[i] = key[i];
	}

	roundKeys[0] = key8[0];
	roundKeys[1] = key8[1];
	roundKeys[2] = key8[4];
	roundKeys[3] = key8[5];
	roundKeys[4] = key8[8];
	roundKeys[5] = key8[9];
	roundKeys[6] = key8[12];
	roundKeys[7] = key8[13];

	/* key schedule */
	uint8_t sbox0, sbox1;
	uint8_t temp[4];
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
		temp[0]  = key8[0];  temp[1]  = key8[1];  temp[2]  = key8[2];   temp[3]  = key8[3];
		key8[0]  = key8[4];  key8[1]  = key8[5];  key8[2]  = key8[6];   key8[3]  = key8[7];
		key8[4]  = key8[8];  key8[5]  = key8[9];  key8[6]  = key8[10];  key8[7]  = key8[11];
		key8[8]  = key8[12]; key8[9]  = key8[13]; key8[10] = key8[14];  key8[11] = key8[15];
		key8[12] = temp[0];  key8[13] = temp[1];  key8[14] = temp[2];   key8[15] = temp[3];
		key8[0]  ^= temp[3]; key8[1]  ^= temp[0]; key8[2]  ^= temp[1];  key8[3]  ^= temp[2];
		key8[8]  ^= key8[6]; key8[9]  ^= key8[7]; key8[10] ^= key8[4];  key8[11] ^= key8[5];
		/* round const */
		key8[0] ^= READ_Z_BYTE(RC[i-1]);
		/* store round key */
		roundKeys[index++] = key8[0];
		roundKeys[index++] = key8[1];
		roundKeys[index++] = key8[4];
		roundKeys[index++] = key8[5];
		roundKeys[index++] = key8[8];
		roundKeys[index++] = key8[9];
		roundKeys[index++] = key8[12];
		roundKeys[index++] = key8[13];
	}
}

#else
#ifdef MSP
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t key8[16];
	/* the master key can not be modified. */
	uint8_t i;
	for ( i = 0; i < KEY_SIZE; i++) {
		key8[i] = key[i];
	}

	uint16_t *key16 = (uint16_t*)key8;
	uint16_t *roundKeys16 = (uint16_t*)roundKeys;

	/* the first round keys */
	roundKeys16[0] = key16[0];
	roundKeys16[1] = key16[2];
	roundKeys16[2] = key16[4];
	roundKeys16[3] = key16[6];

	/* key schedule */
	uint8_t sbox0, sbox1;
	uint16_t temp[2];
	uint8_t index = 4;
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
		temp[0] = key16[0];   temp[1] = key16[1];
		key16[0] = key16[2];  key16[1] = key16[3];
		key16[2] = key16[4];  key16[3] = key16[5];
		key16[4] = key16[6];  key16[5] = key16[7];
		key16[6] = temp[0];   key16[7] = temp[1];
		key16[0] ^= (temp[0]<<8 | temp[1]>>8);
		key16[1] ^= (temp[1]<<8 | temp[0]>>8);
		key16[4] ^= key16[3];
		key16[5] ^= key16[2];
		/* round const */
		key8[0] ^= READ_Z_BYTE(RC[i-1]);
		/* store round key */
		roundKeys16[index++] = key16[0];
		roundKeys16[index++] = key16[2];
		roundKeys16[index++] = key16[4];
		roundKeys16[index++] = key16[6];
	}
}

#else
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t key8[16];
	/* the master key can not be modified. */
	uint8_t i;
	*((uint32_t*)key8) = *((uint32_t*)key);
	*((uint32_t*)key8+1) = *((uint32_t*)key+1);
	*((uint32_t*)key8+2) = *((uint32_t*)key+2);
	*((uint32_t*)key8+3) = *((uint32_t*)key+3);

	uint16_t *key16 = (uint16_t*)key8;
	uint16_t *roundKeys16 = (uint16_t*)roundKeys;

	/* the first round keys */
	roundKeys16[0] = key16[0];
	roundKeys16[1] = key16[2];
	roundKeys16[2] = key16[4];
	roundKeys16[3] = key16[6];

	/* key schedule */
	uint8_t sbox0, sbox1;
	uint16_t halfRow2;
	uint32_t tempRow0;
	for ( i = 1; i <= NUMBER_OF_ROUNDS; i++) {
		/* S box */
		sbox1 = ~key8[4];
		sbox0 = sbox1 | key8[12];
		sbox0 ^= key8[0];
		key8[0] &= sbox1;
		sbox1 = key8[8] ^ key8[12];
		key8[0] ^= sbox1;
		key8[12] = key8[4] ^ key8[8];
		key8[4] = key8[8] ^ sbox0;
		sbox1 &= sbox0;
		key8[12] ^= sbox1;
		key8[8] = key8[0] | key8[12];
		key8[8] ^= sbox0;
		/* row */
		tempRow0 = *((uint32_t*)key8);
		*((uint32_t*)key8) = (tempRow0<<8 | tempRow0>>24) ^ *((uint32_t*)key8+1);
		*((uint32_t*)key8+1) = *((uint32_t*)key8+2);
		halfRow2 = *(key16+4);
		*(key16+4) = *(key16+5) ^ *(key16+6);
		*(key16+5) = halfRow2 ^ *(key16+7);
		*((uint32_t*)key8+3) = tempRow0;
		/* round const */
		*key8 ^= READ_Z_BYTE(RC[i-1]);
		/* store round key */
		roundKeys16[4*i] = key16[0];
		roundKeys16[4*i+1] = key16[2];
		roundKeys16[4*i+2] = key16[4];
		roundKeys16[4*i+3] = key16[6];
	}
}
#endif
#endif
