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
#include "round_function.h"


void DecryptRound(uint8_t x[8], uint8_t k[4])
{
	uint8_t temp[4];
	uint8_t y[4];
	uint8_t q;

	
	/* Save a copy of the left half of X */
	temp[3] = x[7];	
	temp[2] = x[6];
	temp[1] = x[5];
	temp[0] = x[4];
	
	
	/* (1) Round functon F */
	F(x + 4, k, y);
	
	
	/* (F(X(j+1), K(j+1)) XOR X(j+2)) */
	x[3] = y[3] ^ x[3];
	x[2] = y[2] ^ x[2];
	x[1] = y[1] ^ x[1];
	x[0] = y[0] ^ x[0];

	
	/* (F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8 */  	
	q = x[0];	
	x[0] = x[1];
	x[1] = x[2];	
	x[2] = x[3];
	x[3] = q;
	
	
	/* Put the copy of the left half of X in the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
}



void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	int8_t i;

	
	DecryptRound(block, &roundKeys[124]);
	
	for(i = NUMBER_OF_ROUNDS - 2; i >= 0; i--)
	{
		Swap(block);
		DecryptRound(block, &roundKeys[4 * i]);
	}
}
