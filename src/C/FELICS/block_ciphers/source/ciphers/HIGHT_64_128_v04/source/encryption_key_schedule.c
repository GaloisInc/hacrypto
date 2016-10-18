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


void WhiteningKeyGeneration(const uint8_t *mk, uint8_t *wk)
{
	wk[0] = mk[12];
	wk[1] = mk[13];
	wk[2] = mk[14];
	wk[3] = mk[15];

	wk[4] = mk[0];
	wk[5] = mk[1];
	wk[6] = mk[2];
	wk[7] = mk[3];
}

void SubkeyGeneration(const uint8_t *mk, uint8_t *sk)
{
	uint8_t i, j, index;
	
	
	for(i = 0; i < 8; i++)
	{
		for(j = 0; j < 8; j++)
		{
			index = (j - i + 8) & 0x07;
			sk[16 * i + j] = mk[index] + READ_DELTA_BYTE(delta[16 * i + j]);
			sk[16 * i + j + 8] = mk[index + 8] + READ_DELTA_BYTE(delta[16 * i + j + 8]);
		}
	}
}


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	WhiteningKeyGeneration(key, roundKeys);
	SubkeyGeneration(key, &roundKeys[8]);
}
