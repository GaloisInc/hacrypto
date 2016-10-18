/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu>
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


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint64_t state = *(uint64_t*)block;
	uint64_t temp;
	uint32_t subkey_lo, subkey_hi;
	uint8_t keyindex = 31;
	uint8_t i, k;
	
	
	for (i = 0; i < 31; i++)
	{
		/* addRoundkey */
		subkey_lo = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * keyindex]);
		subkey_hi = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * keyindex + 1]);

		state ^= (uint64_t)subkey_lo ^ (((uint64_t)subkey_hi) << 32);

		keyindex--;


		/* pLayer */
		temp = 0;
		for (k = 0; k < 64; k++)
		{
			/* arithmetic calculation of the p-Layer */
			uint16_t position = (4 * k) % 63;

			/* exception for bit 63 */
			if (k == 63)
			{										
				position = 63;
			}

			/* result writing */
			temp |= ((state >> k) & 0x1) << position;
		}
		state = temp;


		/* sBoxLayer */
		for (k = 0; k < 16; k++)
		{
			/* get lowest nibble */
			uint16_t sBoxValue = state & 0xF;

			/* kill lowest nibble */			
			state &= 0xFFFFFFFFFFFFFFF0;

			/* put new value to lowest nibble (sbox) */				
			state |= READ_SBOX_BYTE(invsBox4[sBoxValue]);

			/* next(rotate by one nibble) */				
			state = rotate4l_64(state);						
		}
	}

	
	/* addRoundkey (Round 31) */
	subkey_lo = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * keyindex]);
	subkey_hi = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * keyindex + 1]);

	state ^= (uint64_t)subkey_lo ^ (((uint64_t)subkey_hi) << 32);

	
	*(uint64_t*)block = state;
}
