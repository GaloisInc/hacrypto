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


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t i;


	uint16_t *Key = (uint16_t *)key;
	uint16_t *RoundKeys = (uint16_t *)roundKeys;

	
	for(i = 0; i < 4; i++)
	{
		/* Copy K0 to round keys */
		RoundKeys[i] = Key[i];
	
		/* Copy K1 to round keys */
		RoundKeys[i + 8] = Key[i + 4];
	}


	/* Generate K0' */
	for(i = 0; i < 3; i++)
	{
		RoundKeys[i + 4] = ((Key[i + 1] << 15) & 0x8000) ^ (Key[i] >> 1);
	}

	RoundKeys[7] = ((Key[0] << 15) & 0x8000) ^ (Key[3] >> 1);
	RoundKeys[4] = RoundKeys[4] ^ ((Key[3] >> 15) & 0x0001);
}
