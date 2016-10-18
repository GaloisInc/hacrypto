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


void EncryptInitialTransfomation(uint8_t *x, const uint8_t *wk)
{
	x[0] = x[0] + READ_ROUND_KEY_BYTE(wk[0]); 
	x[2] = x[2] ^ READ_ROUND_KEY_BYTE(wk[1]); 
	x[4] = x[4] + READ_ROUND_KEY_BYTE(wk[2]); 
	x[6] = x[6] ^ READ_ROUND_KEY_BYTE(wk[3]);
}

void EncryptRoundFunction(uint8_t *x, const uint8_t *sk)
{
	uint8_t temp6 = x[6];
	uint8_t temp7 = x[7];
	
	
	x[7] = x[6];
	x[6] = x[5] + (F1(x[4]) ^ READ_ROUND_KEY_BYTE(sk[2]));
	x[5] = x[4]; 
	x[4] = x[3] ^ (F0(x[2]) + READ_ROUND_KEY_BYTE(sk[1]));
	x[3] = x[2]; 
	x[2] = x[1] + (F1(x[0]) ^ READ_ROUND_KEY_BYTE(sk[0]));
	x[1] = x[0]; 
	x[0] = temp7 ^ (F0(temp6) + READ_ROUND_KEY_BYTE(sk[3]));
}

void EncryptFinalTransfomation(uint8_t *x, const uint8_t *wk)
{
	uint8_t temp = x[0];


	x[0] = x[1] + READ_ROUND_KEY_BYTE(wk[4]); 
	x[1] = x[2]; 
	x[2] = x[3] ^ READ_ROUND_KEY_BYTE(wk[5]); 
	x[3] = x[4];
	x[4] = x[5] + READ_ROUND_KEY_BYTE(wk[6]); 
	x[5] = x[6]; 
	x[6] = x[7] ^ READ_ROUND_KEY_BYTE(wk[7]); 
	x[7] = temp;
}


void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i;
	

	EncryptInitialTransfomation(block, roundKeys);
	
	for(i = 0; i < NUMBER_OF_ROUNDS; i++)
	{
		EncryptRoundFunction(block, &roundKeys[8 + (i << 2)]);
	}
	
	EncryptFinalTransfomation(block, roundKeys);
}
