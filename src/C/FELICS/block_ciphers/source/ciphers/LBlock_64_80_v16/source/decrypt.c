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


void DecryptRound(uint8_t x[8], uint8_t k[4])
{
	uint8_t temp[4];
	uint8_t p[4];

	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = x[7] ^ READ_ROUND_KEY_BYTE(k[3]); 
	temp[2] = x[6] ^ READ_ROUND_KEY_BYTE(k[2]); 
	temp[1] = x[5] ^ READ_ROUND_KEY_BYTE(k[1]); 
	temp[0] = x[4] ^ READ_ROUND_KEY_BYTE(k[0]);  
	
	
	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]);    
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);

	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) */
	temp[3] = p[3] ^ x[3];	
	temp[2] = p[2] ^ x[2];
	temp[1] = p[1] ^ x[1];	
	temp[0] = p[0] ^ x[0];
	
	
	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */
	x[3] = temp[0]; 
	x[2] = temp[3]; 
	x[1] = temp[2]; 
	x[0] = temp[1];
}

void SwapDecrypt(uint8_t block[8])
{
	uint8_t temp[4];
	

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

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	int8_t i;

	
	DecryptRound(block, &roundKeys[124]);

	
	for(i = NUMBER_OF_ROUNDS - 2; i >= 0; i--)
	{
		SwapDecrypt(block);
		DecryptRound(block, &roundKeys[4 * i]);
	}
}
