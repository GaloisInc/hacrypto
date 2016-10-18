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


void Setup(uint8_t *state, uint8_t *key, uint8_t *iv)
{
	uint8_t i;
	uint8_t t1, t2, t3;
	uint8_t x1, x2, x3, x4, x5;


	for (i = 0; i < KEY_SIZE; i++)
	{
		state[i] = key[9 - i];
	}

	state[10] = 0x00;
	state[11] = iv[9] >> 5;

	for (i = 0; i < IV_SIZE - 1; i++)
	{
		state[i + 12] = (iv[9 - i] << 3) ^ (iv[8 - i] >> 5);
	}

	state[21] = iv[0] << 3;

	for (i = 22; i < 35; i++)
	{
		state[i] = 0x00;
	}

	state[35] = 0x07;


	for	(i = 0; i < 144; i++)
	{
		x1 = (state[7] << 2) ^ (state[8] >> 6);
		x2 = (state[10] << 3) ^ (state[11] >> 5);
		x3 = (state[10] << 4) ^ (state[11] >> 4);
		x4 = (state[10] << 5) ^ (state[11] >> 3);
		x5 = (state[20] << 3) ^ (state[21] >> 5);

		t1 = x1 ^ (x2 & x3) ^ x4 ^ x5;


		x1 = (state[19] << 2) ^ (state[20] >> 6);
		x2 = (state[20] << 7) ^ (state[21] >> 1);
		x3 = state[21];
		x4 = (state[21] << 1) ^ (state[22] >> 7);
		x5 = state[32];

		t2 = x1 ^ (x2 & x3) ^ x4 ^ x5;


		x1 = (state[29] << 3) ^ (state[30] >> 5);
		x2 = (state[34] << 6) ^ (state[35] >> 2);
		x3 = (state[34] << 7) ^ (state[35] >> 1);
		x4 = state[35];
		x5 = (state[7] << 5) ^ (state[8] >> 3);

		t3 = x1 ^ (x2 & x3) ^ x4 ^ x5;


		Rotate(state, &t1, &t2, &t3);
	}
}
