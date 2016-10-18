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

#include "shared_functions.h"
#include "constants.h"


/* 
 * If half & 1 == 0 the use first half of the key
 * else use the second half of the key
 * 
 * The key bytes are added row wise, i.e., first row , then second row etc.
 * 
 */
void AddKey(uint8_t state[4][4], uint8_t* keyBytes, uint8_t half)
{
	uint8_t i, j;


	/*
	#define LED 80

	if((half&1) == 0)
	{
		for(i = 0; i < 4; i++)
		{
			for(j = 0; j < 4; j++)
			{
				state[i][j] ^= keyBytes[4*i+j];
			}
		}
	}
	else
	{
		for(i = 0; i < 4; i++)
		{
			for(j = 0; j < 4; j++)
			{
				state[i][j] ^= keyBytes[4 * i + j + ((LED - 64) >> 2)];
			}
		}
	}
	*/

	for(i = 0; i < 4; i++)
	{
		for(j = 0; j < 4; j++)
		{
			state[i][j] ^= READ_ROUND_KEY_BYTE(keyBytes[(4 * i + j + half * 16) % ROUND_KEYS_SIZE]);
		}
	}
}

void AddConstants(uint8_t state[4][4], uint8_t r)
{
	uint8_t tmp;


	/*
	state[1][0] ^= 1;
	state[2][0] ^= 2;
	state[3][0] ^= 3;
	*/
  
	/* Added from reference implementation and merged with the above code */
	state[0][0] ^= 5;   /* (    ((KEY_SIZE>>1) & 0xf)); */
	state[1][0] ^= 4;   /* (1 ^ ((KEY_SIZE>>1) & 0xf)); */
	state[2][0] ^= 2;   /* (2 ^ ((KEY_SIZE<<3) & 0xf)); */
	state[3][0] ^= 3;   /* (3 ^ ((KEY_SIZE<<3) & 0xf)); */
  
	tmp = (READ_ROUND_CONSTANT_BYTE(RC[r]) >> 3) & 7;
	state[0][1] ^= tmp;
	state[2][1] ^= tmp;

	tmp = READ_ROUND_CONSTANT_BYTE(RC[r]) & 7;
	state[1][1] ^= tmp;
	state[3][1] ^= tmp;
}
