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
	uint16_t shiftedKey[2];
	uint8_t keyCopy[KEY_SIZE];


	uint16_t *Key = (uint16_t *)key;
	uint32_t *RoundKeys = (uint32_t *)roundKeys;


	uint16_t *KeyCopy = (uint16_t *)keyCopy;

	
	KeyCopy[4] = Key[4];
	KeyCopy[3] = Key[3];
	KeyCopy[2] = Key[2];
	KeyCopy[1] = Key[1];
	KeyCopy[0] = Key[0];

	
	/* Set round subkey K(1) */
	RoundKeys[0] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];


	/* Update the key register K */
	for(i = 1; i < NUMBER_OF_ROUNDS; i++)
	{
		/* (a) K <<< 29 */
		shiftedKey[1] = KeyCopy[4];     
		shiftedKey[0] = KeyCopy[3];


		KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
		KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
		KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
		KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
		KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

		
		/* (b) S-boxes */
		keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);
		
		
		/* (c) XOR */
		keyCopy[6] = keyCopy[6] ^ (i >> 2);
		keyCopy[5] = keyCopy[5] ^ (i << 6);

		
		/* (d) Set the round subkey K(i+1) */
		RoundKeys[i] = (((uint32_t)KeyCopy[4]) << 16) ^ (uint32_t)KeyCopy[3];
	}                   
}
