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
#include "update.h"
#include "rotate.h"


void Setup(uint8_t *state, uint8_t *key, uint8_t *iv)
{
	uint8_t i;
	uint16_t t1, t2, t3;
	uint16_t s;


	uint16_t *State = (uint16_t *)state;
	uint16_t *Key = (uint16_t *)key;
	uint16_t *IV = (uint16_t *)iv;


	for (i = 0; i < KEY_SIZE / 2; i++)
	{
		State[i] = Key[4 - i];
	}

	State[5] = IV[4] >> 13;

	for (i = 0; i < IV_SIZE / 2 - 1; i++)
	{
		State[i + 6] = (IV[4 - i] << 3) ^ (IV[3 - i] >> 13);
	}

	State[10] = IV[0] << 3;

	for (i = 11; i < 17; i++)
	{
		State[i] = 0x0000;
	}

	State[17] = 0x0007;


	for	(i = 0; i < 72; i++)
	{
		Update(State, &t1, &t2, &t3, &s);
		Rotate(State, &t1, &t2, &t3);
	}
}
