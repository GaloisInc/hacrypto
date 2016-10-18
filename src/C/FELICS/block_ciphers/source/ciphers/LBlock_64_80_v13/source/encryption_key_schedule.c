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


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t i;
	uint8_t shiftedKey[4];
	uint8_t keyCopy[KEY_SIZE];

	
	keyCopy[9] = key[9];
	keyCopy[8] = key[8];
	keyCopy[7] = key[7];
	keyCopy[6] = key[6];
	keyCopy[5] = key[5];
	keyCopy[4] = key[4];
	keyCopy[3] = key[3];
	keyCopy[2] = key[2];
	keyCopy[1] = key[1];
	keyCopy[0] = key[0];
	

	/* Set round subkey K(1) */
	roundKeys[3] = keyCopy[9];
	roundKeys[2] = keyCopy[8];
	roundKeys[1] = keyCopy[7];
	roundKeys[0] = keyCopy[6];


	/* Update the key register K */
	for(i = 1; i < NUMBER_OF_ROUNDS; i++)
	{
		/* (a) K <<< 29 */               
		shiftedKey[3] = keyCopy[9];
		shiftedKey[2] = keyCopy[8];
		shiftedKey[1] = keyCopy[7];     
		shiftedKey[0] = keyCopy[6];     
		

		keyCopy[9]=(((keyCopy[6] & 0x07) << 5) & 0xE0) ^ (((keyCopy[5] & 0xF8) >> 3) & 0x1F);
		keyCopy[8]=(((keyCopy[5] & 0x07) << 5) & 0xE0) ^ (((keyCopy[4] & 0xF8) >> 3) & 0x1F);
		keyCopy[7]=(((keyCopy[4] & 0x07) << 5) & 0xE0) ^ (((keyCopy[3] & 0xF8) >> 3) & 0x1F);
		keyCopy[6]=(((keyCopy[3] & 0x07) << 5) & 0xE0) ^ (((keyCopy[2] & 0xF8) >> 3) & 0x1F);
		keyCopy[5]=(((keyCopy[2] & 0x07) << 5) & 0xE0) ^ (((keyCopy[1] & 0xF8) >> 3) & 0x1F);
		keyCopy[4]=(((keyCopy[1] & 0x07) << 5) & 0xE0) ^ (((keyCopy[0] & 0xF8) >> 3) & 0x1F);
		keyCopy[3]=(((keyCopy[0] & 0x07) << 5) & 0xE0) ^ (((shiftedKey[3] & 0xF8) >> 3) & 0x1F);
		keyCopy[2]=(((shiftedKey[3] & 0x07) << 5) & 0xE0) ^ (((shiftedKey[2] & 0xF8) >> 3) & 0x1F);
		keyCopy[1]=(((shiftedKey[2] & 0x07) << 5) & 0xE0) ^ (((shiftedKey[1] & 0xF8) >> 3) & 0x1F);
		keyCopy[0]=(((shiftedKey[1] & 0x07) << 5) & 0xE0) ^ (((shiftedKey[0] & 0xF8) >> 3) & 0x1F);

		
		/* (b) S-boxes */
		keyCopy[9] = (READ_SBOX_BYTE(S9[((keyCopy[9] >> 4) & 0x0F)]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);


		/* (c) XOR */
		keyCopy[6] = keyCopy[6] ^ ((i >> 2) & 0x07);
		keyCopy[5] = keyCopy[5] ^ ((i & 0x03) << 6);


		/* (d) Set the round subkey K(i+1) */
		roundKeys[4 * i + 3] = keyCopy[9];
		roundKeys[4 * i + 2] = keyCopy[8];
		roundKeys[4 * i + 1] = keyCopy[7];
		roundKeys[4 * i] = keyCopy[6];
	}                   
}
