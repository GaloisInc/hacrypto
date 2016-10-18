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
	/* Copy K0 to round keys */
	roundKeys[0] = key[0];
	roundKeys[1] = key[1];
	roundKeys[2] = key[2];
	roundKeys[3] = key[3];
	roundKeys[4] = key[4];
	roundKeys[5] = key[5];
	roundKeys[6] = key[6];
	roundKeys[7] = key[7];

	
	/* Copy K1 to round keys */
	roundKeys[16] = key[8];
	roundKeys[17] = key[9];
	roundKeys[18] = key[10];
	roundKeys[19] = key[11];
	roundKeys[20] = key[12];
	roundKeys[21] = key[13];
	roundKeys[22] = key[14];
	roundKeys[23] = key[15];


	/* Generate K0' */
	roundKeys[8] = ((key[1] << 7) & 0x80) ^ (key[0] >> 1);
	roundKeys[9] = ((key[2] << 7) & 0x80) ^ (key[1] >> 1);
	roundKeys[10] = ((key[3] << 7) & 0x80) ^ (key[2] >> 1);
	roundKeys[11] = ((key[4] << 7) & 0x80) ^ (key[3] >> 1);
	roundKeys[12] = ((key[5] << 7) & 0x80) ^ (key[4] >> 1);
	roundKeys[13] = ((key[6] << 7) & 0x80) ^ (key[5] >> 1);
	roundKeys[14] = ((key[7] << 7) & 0x80) ^ (key[6] >> 1);

	roundKeys[15] = ((key[0] << 7) & 0x80) ^ (key[7] >> 1);
	roundKeys[8] = roundKeys[8] ^ ((key[7] >> 7) & 0x01);
}
