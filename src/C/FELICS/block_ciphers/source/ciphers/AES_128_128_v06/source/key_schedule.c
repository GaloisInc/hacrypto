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

#include "constants.h"
#include "key_schedule.h"


void KeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint32_t w[44], temp;
	int i, j;


	for (i = 0; i < 4; i++)
	{
		w[i] = ((uint32_t*)key)[i];
	}

	i = 4;
	while (i < 44)
	{
		temp = w[i - 1];

		temp = ((uint32_t)READ_SBOX_BYTE(Sbox[temp & 0xFF]) << 24) ^
			((uint32_t)READ_SBOX_BYTE(Sbox[(temp >> 8) & 0xFF])) ^
			((uint32_t)READ_SBOX_BYTE(Sbox[(temp >> 16) & 0xFF]) << 8) ^
			((uint32_t)READ_SBOX_BYTE(Sbox[(temp >> 24) & 0xFF]) << 16) ^
			(uint32_t)READ_KS_BYTE(Rcon[i / 4]);
		w[i] = w[i - 4] ^ temp;
		i++;

		temp = w[i - 1];
		w[i] = w[i - 4] ^ temp;
		i++;

		temp = w[i - 1];
		w[i] = w[i - 4] ^ temp;
		i++;

		temp = w[i - 1];
		w[i] = w[i - 4] ^ temp;
		i++;
	}

	for (i = 0; i <= 10; i++)
	{
		for (j = 0; j < 4; j++)
		{
			((uint32_t*)roundKeys)[4 * i + j] = w[4 * i + j];
		}
	}
}
