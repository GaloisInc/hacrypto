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

#include "shared_functions.h"
#include "constants.h"


void SLayer(uint8_t *block)
{
	uint8_t i;
	

	for(i = 0; i < 8; i++)
	{
		block[i] = ((READ_SBOX_BYTE(S0[(block[i] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[i] & 0x0F)]));
	}
}

void InverseSLayer(uint8_t *block)
{
	uint8_t i;
	

	for(i = 0; i < 8; i++)
	{
		block[i] = ((READ_INVERSE_SBOX_BYTE(S1[(block[i] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[i] & 0x0F)]));
	}
}

void M0Multiplication(uint8_t *block)
{
	uint8_t temp[2];

	
	temp[1] = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp[1] = (temp[1] << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp[0] = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp[0] = (temp[0] << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);

	
	block[1] = temp[1];
	block[0] = temp[0];
}

void M1Multiplication(uint8_t *block)
{
	uint8_t temp[2];

	
	temp[1] = (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
	temp[1] = (temp[1] << 4) ^ (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
		
	temp[0] = (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	temp[0] = (temp[0] << 4) ^ (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	
	
	block[1] = temp[1];
	block[0] = temp[0];
}

void SR(uint8_t *block)
{
	uint8_t temp0, temp1;


	/* Shift left column 1 by 1 */
	temp0 = block[7];
	block[7] = (block[7] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[1] & 0x0F);
	block[1] = (block[1] & 0xF0) ^ (temp0 & 0x0F);


	/* Shift left column 2 by 2 and column 3 by 3 */
	temp0 = block[0];
	temp1 = block[2];

	block[0] = (block[4] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (block[6] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (temp0 & 0xF0) ^ (block[6] & 0x0F);
	block[6] = (temp1 & 0xF0) ^ (temp0 & 0x0F);
}

void InverseSR(uint8_t *block)
{
	uint8_t temp0, temp1;


	/* Shift right column 1 by 1 */
	temp0 = block[1];
	block[1] = (block[1] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[7] & 0x0F);
	block[7] = (block[7] & 0xF0) ^ (temp0 & 0x0F);

	
	/* Shift right column 2 by 2 and column 3 by 3 */
	temp0 = block[6];
	temp1 = block[4];

	block[6] = (block[2] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (block[0] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (temp0 & 0xF0) ^ (block[0] & 0x0F);
	block[0] = (temp1 & 0xF0) ^ (temp0 & 0x0F);
}

void AddRoundRoundKeyAndRoundConstant(uint8_t *block, uint8_t *roundKey, const uint8_t *roundConstant)
{
	uint8_t i;


	uint16_t *Block = (uint16_t *)block;
	uint16_t *RoundKey = (uint16_t *)roundKey;
	uint16_t *RoundConstant = (uint16_t *)roundConstant;


	for(i = 0; i < 4; i++)
	{
		Block[i] = Block[i] ^ READ_ROUND_CONSTANT_WORD(RoundConstant[i]);
		Block[i] = Block[i] ^ READ_ROUND_KEY_WORD(RoundKey[i]);
	}
}

void Round(uint8_t *block, uint8_t *roundKey, const uint8_t *roundConstant)
{	
	/* S-Layer */
	SLayer(block);

	/* M-Layer */
	M0Multiplication(&block[6]);
	M1Multiplication(&block[4]);
	M1Multiplication(&block[2]);
	M0Multiplication(&block[0]);

	/* SR */
	SR(block);

	/* XOR K1, XOR RCi */
	AddRoundRoundKeyAndRoundConstant(block, roundKey, roundConstant);
}

void InverseRound(uint8_t *block, uint8_t *roundKey, const uint8_t *roundConstant)
{
	/* XOR K1, XOR RCi */
	AddRoundRoundKeyAndRoundConstant(block, roundKey, roundConstant);

	/* Inverse SR */
	InverseSR(block);

	/* M-Layer */
	M0Multiplication(&block[6]);
	M1Multiplication(&block[4]);
	M1Multiplication(&block[2]);
	M0Multiplication(&block[0]);

	/* Inverse S-Layer */
	InverseSLayer(block);
}

void Whitening(uint8_t *block, uint8_t *roundKey)
{
	uint8_t i;


	uint16_t *Block = (uint16_t *)block;
	uint16_t *RoundKey = (uint16_t *)roundKey;


	for(i = 0; i < 4; i++)
	{
		Block[i] = Block[i] ^ READ_ROUND_KEY_WORD(RoundKey[i]);
	}
}
