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
	uint64_t t1, t2, t3;
	uint64_t x1, x2, x3, x4, x5;


	uint64_t *State = (uint64_t *)state;


	/* Initialize register A */
	state[14] = key[0];
	state[15] = key[1];	

	for (i = 2; i < KEY_SIZE; i++)
	{
		state[i - 2] = key[i];
	}

	for (i = 8; i < 14; i++)
	{
		state[i] = 0x00;
	}


	/* Initialize register B */
	state[30] = iv[0];
	state[31] = iv[1];

	for (i = 2; i < IV_SIZE; i++)
	{
		state[i + 14] = iv[i];
	}

	for (i = 24; i < 30; i++)
	{
		state[i] = 0x00;
	}


	/* Initialize register C */
	for (i = 32; i < 42; i++)
	{
		state[i] = 0x00;
	}

	state[42] = 0x0E;

	for (i = 43; i < 48; i++)
	{
		state[i] = 0x00;
	}


	for	(i = 0; i < 18; i++)
	{
		x1 = (State[0] << 2) ^ (State[1] >> 62);
		x2 = (State[0] << 27) ^ (State[1] >> 37);
		x3 = (State[0] << 28) ^ (State[1] >> 36);
		x4 = (State[0] << 29) ^ (State[1] >> 35);
		x5 = (State[2] << 14) ^ (State[3] >> 50);

		t1 = x1 ^ (x2 & x3) ^ x4 ^ x5;


		x1 = (State[2] << 5) ^ (State[3] >> 59);
		x2 = (State[2] << 18) ^ (State[3] >> 46);
		x3 = (State[2] << 19) ^ (State[3] >> 45);
		x4 = (State[2] << 20) ^ (State[3] >> 44);
		x5 =  (State[4] << 23) ^ (State[5] >> 41);

		t2 = x1 ^ (x2 & x3) ^ x4 ^ x5;


		x1 = (State[4] << 2) ^ (State[5] >> 62);
		x2 = (State[4] << 45) ^ (State[5] >> 19);
		x3 = (State[4] << 46) ^ (State[5] >> 18);
		x4 = (State[4] << 47) ^ (State[5] >> 17);
		x5 = (State[0] << 5) ^ (State[1] >> 59);

		t3 = x1 ^ (x2 & x3) ^ x4 ^ x5;


		Rotate(State, &t1, &t2, &t3);
	}
}
