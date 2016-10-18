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

	
	/* Save a copy of the left half of X */
	temp[3] = x[7];	
	temp[2] = x[6];
	temp[1] = x[5];
	temp[0] = x[4];
	
	
	/* (1) Round functon F */
	F(x + 4, k, y);
	
	
	/* F(X(j+1), K(j+1) XOR (X(j+2)) >>> 8) */  	
	x[7] = y[0] ^ x[0];
	x[6] = y[3] ^ x[3]; 	
	x[5] = y[2] ^ x[2]; 	
	x[4] = y[1] ^ x[1]; 
	
	
	/* Put the copy of the left half of X in the right half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
}



void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	int8_t i;
	uint8_t temp[4];
	
	
	for(i = NUMBER_OF_ROUNDS - 1; i >= 0; i--)
	{
		DecryptRound(block, &roundKeys[4 * i]);   
	}
	

	temp[3] = block[3];
	temp[2] = block[2];
	temp[1] = block[1];
	temp[0] = block[0];
	
	block[3] = block[7];
	block[2] = block[6];
	block[1] = block[5];
	block[0] = block[4];
	
	block[7] = temp[3];
	block[6] = temp[2];
	block[5] = temp[1];
	block[4] = temp[0];
}
