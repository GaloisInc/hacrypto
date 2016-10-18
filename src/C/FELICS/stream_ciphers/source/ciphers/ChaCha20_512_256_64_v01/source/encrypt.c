/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 University of Luxembourg
 *
 * Written in 2016 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#include "update.h"


void Encrypt(uint8_t *state, uint8_t *stream, uint16_t length)
{
	uint16_t i;
	uint8_t j;

	uint8_t keyStream[STATE_SIZE];


	for (i = 0; i < length / STATE_SIZE; i++)
	{
		Update(state, keyStream);

		for (j = 0; j < STATE_SIZE; j++)
		{
			stream[i * STATE_SIZE + j] ^= keyStream[j];
		}
	}
}
