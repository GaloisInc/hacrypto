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


void DecryptInitialTransfomation(uint8_t *x, const uint8_t *wk)
{
	x[0] = x[0] - READ_ROUND_KEY_BYTE(wk[0]);
	x[2] = x[2] ^ READ_ROUND_KEY_BYTE(wk[1]); 
	x[4] = x[4] - READ_ROUND_KEY_BYTE(wk[2]);
	x[6] = x[6] ^ READ_ROUND_KEY_BYTE(wk[3]);
}

void DecryptRoundFunction(uint8_t *x, const uint8_t *sk)
{
	uint8_t temp0 = x[0];
	
	
	x[0] = x[1];
	x[1] = x[2] - (F1(x[0]) ^ READ_ROUND_KEY_BYTE(sk[0]));
	x[2] = x[3];
	x[3] = x[4] ^ (F0(x[2]) + READ_ROUND_KEY_BYTE(sk[1]));	
	x[4] = x[5];
	x[5] = x[6] - (F1(x[4]) ^ READ_ROUND_KEY_BYTE(sk[2]));
	x[6] = x[7];	
	x[7] = temp0 ^ (F0(x[6]) + READ_ROUND_KEY_BYTE(sk[3]));
}

void DecryptFinalTransfomation(uint8_t *x, const uint8_t *wk)
{
	uint8_t temp = x[7];

	
	x[7] = x[6] ^ READ_ROUND_KEY_BYTE(wk[7]); 
	x[6] = x[5]; 
	x[5] = x[4] - READ_ROUND_KEY_BYTE(wk[6]);
	x[4] = x[3]; 
	x[3] = x[2] ^ READ_ROUND_KEY_BYTE(wk[5]);
	x[2] = x[1]; 
	x[1] = x[0] - READ_ROUND_KEY_BYTE(wk[4]);
	x[0] = temp;
}


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	int8_t i;
	
	
	DecryptFinalTransfomation(block, roundKeys);
	
	for(i = NUMBER_OF_ROUNDS - 1; i >= 0; i--)
	{
		DecryptRoundFunction(block, &roundKeys[8 + (i << 2)]);
	}	
	
	DecryptInitialTransfomation(block, roundKeys);
}
