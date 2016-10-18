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

#include "scenario1.h"
#include "cipher.h"


void EncryptScenario1(uint8_t *data, uint8_t *roundKeys, uint8_t *iv)
{
	int16_t i;
	int8_t j;

	
	/* Encrypt first data block */
	for(i = 0; i < BLOCK_SIZE; i++)
	{
		data[i] ^= iv[i];
	}

	Encrypt(&data[0], roundKeys);		


	/* Encrypt the remaining data blocks */
	for(i = BLOCK_SIZE; i < DATA_SIZE; i += BLOCK_SIZE)
	{
		for(j = 0; j < BLOCK_SIZE; j++)
		{
			int16_t index = i + j;
			data[index] ^= data[index - BLOCK_SIZE];
		}
		
		Encrypt(&data[i], roundKeys);
	}
}
