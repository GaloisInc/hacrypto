/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Johann Großschädl <johann.groszschaedl@uni.lu>
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
#include <string.h>

#include "cipher.h"
#include "constants.h"


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	/* memcpy(roundKeys, key, KEY_SIZE); */

	uint8_t i;


	for(i = 0; i < ROUND_KEYS_SIZE; i ++)
	{
		if(i % 2) 
		{
			roundKeys[i] = key[i >> 1] & 0xF;
		}
		else 
		{
			roundKeys[i] = (key[i >> 1] >> 4) & 0xF;
		}
	}
}
