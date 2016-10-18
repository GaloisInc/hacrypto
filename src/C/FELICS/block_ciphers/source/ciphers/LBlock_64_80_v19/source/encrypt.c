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


void EncryptRound(uint8_t x[8], uint8_t k[4])
{
	uint16_t temp[2];
	uint8_t p[4];
	
	
	uint16_t *X = (uint16_t *)x;
	uint16_t *K = (uint16_t *)k;

	
	/* Save a copy of the left half of X */
	temp[1] = X[3];
	temp[0] = X[2];
	
	
	/* XOR X left half with the round key: X XOR K(i) */
	X[3] = X[3] ^ READ_ROUND_KEY_WORD(K[1]);
	X[2] = X[2] ^ READ_ROUND_KEY_WORD(K[0]);
	
	
	/* (2) Confusion function S: S(X XOR K(i)) */
	x[7] = (READ_SBOX_BYTE(S7[x[7] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[x[7] & 0x0F]);
	x[6] = (READ_SBOX_BYTE(S5[x[6] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[x[6] & 0x0F]);
	x[5] = (READ_SBOX_BYTE(S3[x[5] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[x[5] & 0x0F]);
	x[4] = (READ_SBOX_BYTE(S1[x[4] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[x[4] & 0x0F]);
	         
	
	/* (3) Diffusion function P: P(S(X XOR K(i))) */
	p[3] = (x[7] << 4) ^ (x[6] & 0x0F);	
	p[2] = (x[7] & 0xF0) ^ (x[6] >> 4);
	p[1] = (x[5] << 4) ^ (x[4] & 0x0F);
	p[0] = (x[5] & 0xF0) ^ (x[4] >> 4);	
	
	
	/* F(X(i-1), K(i-1)) XOR (X(i-2) <<< 8) */  	
	x[7] = p[3] ^ x[2];
	x[6] = p[2] ^ x[1];
	x[5] = p[1] ^ x[0]; 
	x[4] = p[0] ^ x[3];

	
	/* Put the copy of the left half of X in the right half of X */
	X[1] = temp[1];
	X[0] = temp[0];
}

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i;
	uint16_t temp[2];

	
	for(i = 0; i < NUMBER_OF_ROUNDS; i++)
	{
		EncryptRound(block, &roundKeys[4 * i]);  
	}
	

	uint16_t *Block = (uint16_t *)block;
	
	
	temp[1] = Block[1];
	temp[0] = Block[0];
	
	Block[1] = Block[3];
	Block[0] = Block[2];

	Block[3] = temp[1];
	Block[2] = temp[0];
}
