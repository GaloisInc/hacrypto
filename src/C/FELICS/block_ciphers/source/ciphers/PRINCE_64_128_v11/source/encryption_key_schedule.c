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
	uint32_t *Key = (uint32_t *)key;
	uint32_t *RoundKeys = (uint32_t *)roundKeys;

	
	/* Copy K0 to round keys */
	RoundKeys[0] = Key[0];
	RoundKeys[1] = Key[1];
	

	/* Copy K1 to round keys */
	RoundKeys[4] = Key[2];
	RoundKeys[5] = Key[3];


	/* Generate K0' */
	RoundKeys[2] = ((Key[1] << 31) & 0x80000000) ^ (Key[0] >> 1) ^ ((Key[1] >> 31) & 0x00000001);
	RoundKeys[3] = ((Key[0] << 31) & 0x80000000) ^ (Key[1] >> 1);
}
