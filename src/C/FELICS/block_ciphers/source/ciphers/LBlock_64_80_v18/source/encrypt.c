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


void EncryptRound(uint8_t x[8], uint8_t k[4])
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
	

	/* (X(i-2) <<< 8) */
	q = x[3];
	x[3] = x[2];	
	x[2] = x[1];
	x[1] = x[0];
	x[0] = q;

	
	/* F(X(i-1), K(i-1)) XOR (X(i-2) <<< 8) */
	x[3] = y[3] ^ x[3];
	x[2] = y[2] ^ x[2];
	x[1] = y[1] ^ x[1]; 
	x[0] = y[0] ^ x[0];
 	

	/* Put the copy of the left half of X in the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
}

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i;
	
	
	for(i = 0; i < NUMBER_OF_ROUNDS - 1; i++)
	{
		EncryptRound(block, &roundKeys[4 * i]);
		Swap(block);
	}

	EncryptRound(block, &roundKeys[4 * (NUMBER_OF_ROUNDS - 1)]);
}
