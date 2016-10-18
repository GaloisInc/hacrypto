/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu>
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


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	 /* set of nibbles */
	uint8_t state[16];

	uint8_t t[16];
	uint8_t i, r;

	
	state[0] = block[0] & 0xF;
	state[1] = (block[0] & 0xF0) >> 4;
	state[2] = block[1] & 0xF;
	state[3] = (block[1] & 0xF0) >> 4;
	state[4] = block[2] & 0xF;
	state[5] = (block[2] & 0xF0) >> 4;
	state[6] = block[3] & 0xF;
	state[7] = (block[3] & 0xF0) >> 4;
	state[8] = block[4] & 0xF;
	state[9] = (block[4] & 0xF0) >> 4;
	state[10] = block[5] & 0xF;
	state[11] = (block[5] & 0xF0) >> 4;
	state[12] = block[6] & 0xF;
	state[13] = (block[6] & 0xF0) >> 4;
	state[14] = block[7] & 0xF;
	state[15] = (block[7] & 0xF0) >> 4;

	/* 35 tours */
	for (r = 35; r > 0; r--)
	{
		for (i = 0; i < 8; i++)
		{
			state[2 * i + 1] = READ_SBOX_BYTE(Sbox_byte[state[2 * i] ^ 
								READ_ROUND_KEY_BYTE(roundKeys[8 * r + i])]) ^ 
								state[2 * i + 1] & 0x0F;
		}

		for (i = 0; i < 16; i++)
		{
			t[READ_SBOX_BYTE(Pi_inv_byte[i])] = state[i];
		}

		for (i = 0; i < 16; i++)
		{
			state[i] = t[i];
		}

	}

	for (i = 0; i < 8; i++)
	{
		state[2 * i + 1] = READ_SBOX_BYTE(Sbox_byte[state[2 * i] ^ 
							READ_ROUND_KEY_BYTE(roundKeys[i])]) ^ 
							state[2 * i + 1] & 0x0F;
	}
	
	block[0] = state[0] ^ (state[1] << 4);
	block[1] = state[2] ^ (state[3] << 4);
	block[2] = state[4] ^ (state[5] << 4);
	block[3] = state[6] ^ (state[7] << 4);
	block[4] = state[8] ^ (state[9] << 4);
	block[5] = state[10] ^ (state[11] << 4);
	block[6] = state[12] ^ (state[13] << 4);
	block[7] = state[14] ^ (state[15] << 4);
}
