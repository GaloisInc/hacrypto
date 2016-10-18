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
	uint8_t t1, t2, t3;
	uint8_t s;

	
	/* Initialize register A */
	for (i = 0; i < KEY_SIZE; i++)
	{
		state[i] = key[9 - i];
	}

	state[10] = 0x00;
	state[11] = 0x00;

	
	/* Initialize register B */
	for (i = 0; i < IV_SIZE; i++)
	{
		state[i + 12] = iv[9 - i];
	}

	state[22] = 0x00;


	/* Initialize register C */
	for (i = 23; i < 36; i++)
	{
		state[i] = 0x00;
	}

	state[36] = 0x0E;


	for (i = 0; i < 144; i++)
	{
		Update(state, &t1, &t2, &t3, &s);
		Rotate(state, &t1, &t2, &t3);
	}
}
