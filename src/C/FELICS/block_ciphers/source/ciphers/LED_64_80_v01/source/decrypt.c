/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Johann Großschädl <johann.groszschaedl@uni.lu>
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
#include "shared_functions.h"


void invSubCell(uint8_t state[4][4])
{
	uint8_t i,j;

	for(i = 0; i < 4; i++)
	{
		for(j = 0; j <  4; j++)
		{
			state[i][j] = READ_INVERSE_SBOX_BYTE(invSbox[state[i][j]]);
		}
	}
}

void invShiftRow(uint8_t state[4][4])
{
	uint8_t i, j;
	uint8_t tmp[4];

	for(i = 1; i < 4; i++) 
	{
		for(j = 0; j < 4; j++)
		{
			tmp[j] = state[i][j];
		}
		for(j = 0; j < 4; j++)
		{
			/* Modified from tmp[(j + (4 - i)) % 4] */
			state[i][j] = tmp[(j + (4 - i)) & 3];  
		}
	}
}


void invMixColumn(uint8_t state[4][4])
{
	uint8_t i, j, k;
	uint8_t sum, tmp[4];

	for(j = 0; j < 4; j++)
	{
		for(i = 0; i < 4; i++) 
		{
			sum = 0;
			for(k = 0; k < 4; k++)
			{
				sum ^= FieldMult(READ_INVERSE_SBOX_BYTE(invMixColMatrix[i][k]), state[k][j]);
			}
			tmp[i] = sum;
		}
		for(i = 0; i < 4; i++)
		{
			state[i][j] = tmp[i];
		}
	}
}


void Decrypt(uint8_t *block, uint8_t *keyBytes)
{
	int8_t i, j;
	uint8_t state[4][4];

	for(i = 0; i < 16; i++) 
	{
		if(i % 2) 
		{
			state[i / 4][i % 4] = block[i >> 1] & 0xF;
		}
		else 
		{
			state[i / 4][i % 4] = (block[i >> 1] >> 4) & 0xF;
		}
	}

	for(i = (NUMBER_OF_ROUNDS >> 2) - 1; i >= 0; i--)
	{
		AddKey(state, keyBytes, i+1);
		for(j = 3; j >= 0; j--)
		{
			invMixColumn(state);
			invShiftRow(state);
			invSubCell(state);
			AddConstants(state, i * 4 + j);
		}
	}
	AddKey(state, keyBytes, 0);

	for(i = 0; i < 8; i++)
	{
		block[i] = ((state[(2 * i) / 4][(2 * i) % 4] & 0xF) << 4) | 
					(state[(2 * i + 1) / 4][(2 * i + 1) % 4] & 0xF);
	}
}
