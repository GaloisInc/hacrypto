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

#include "rotate.h"


void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i;

	uint32_t *Block = (uint32_t *)block;
	uint32_t *RoundKeys = (uint32_t *)roundKeys;
	

	Block[0] = Block[0] + READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[0]);
	Block[1] = Block[1] + READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[1]);

	for(i = 1; i <= NUMBER_OF_ROUNDS; i++) 
	{ 
		Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[2 * i]); 
		Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[2 * i + 1]); 
	}
}
