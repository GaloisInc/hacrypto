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
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "shared_functions.h"


void SCShRMCS(uint8_t state[4][4])
{
	uint8_t c, r;
	uint16_t v;
	uint8_t os[4][4];

	  
	memcpy(os, state, 16);
	
	for(c = 0; c < 4; c++)
	{
		v = 0;
		
		for(r = 0; r < 4; r++) 
		{
			v ^= READ_ROUND_TABLE_WORD(RndTab[r][(os[r][(r + c) & 3])]);
		}

		for(r = 1; r <= 4; r++)
    	{
			state[4 - r][c] = ((uint8_t) v) & 0xF;
			v >>= 4;
		}
	}
}


void Encrypt(uint8_t *block, uint8_t *keyBytes)
{
	int8_t i,j;
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

	AddKey(state, keyBytes, 0);
	for(i = 0; i < (NUMBER_OF_ROUNDS >> 2); i++)
	{
		for(j = 0; j < 4; j++)
		{
			AddConstants(state, i * 4 + j);
			SCShRMCS(state);
		}
		AddKey(state, keyBytes, i + 1);
	}

	for(i = 0; i < 8; i++)
	{
		block[i] = ((state[(2 * i) / 4][(2 * i) % 4] & 0xF) << 4) | 
					(state[(2 * i + 1) / 4][(2 * i + 1) % 4] & 0xF);
	}
}
