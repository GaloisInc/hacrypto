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

#include "update.h"


void Update(uint8_t *state, uint16_t *t1, uint16_t *t2, uint16_t *t3, uint16_t *stream)
{
	uint16_t x1, x2, x3;

	uint16_t *State = (uint16_t *)state;
		

	x1 = (State[3] << 2) ^ (State[4] >> 14);
	x2 = (State[4] << 13) ^ (State[5] >> 3);

	*t1 = x1 ^ x2;


	x1 = (State[9] << 5) ^ (State[10] >> 11);
	x2 = (State[10] << 4) ^ (State[11] >> 12);

	*t2 = x1 ^ x2;


	x1 = (State[14] << 10) ^ (State[15] >> 6);
	x2 = (State[17] << 7) ^ ((uint16_t)state[36] >> 1);
	
	*t3 = x1 ^ x2;


	*stream ^= *t1 ^ *t2 ^ *t3;


	x1 = (State[4] << 11) ^ (State[5] >> 5);
	x2 = (State[4] << 12) ^ (State[5] >> 4);
	x3 = (State[9] << 14) ^ (State[10] >> 2);

	*t1 ^= (x1 & x2) ^ x3;


	x1 = (State[10] << 2) ^ (State[11] >> 14);
	x2 = (State[10] << 3) ^ (State[11] >> 13);
	x3 = (State[15] << 15) ^ (State[16] >> 1);

	*t2 ^= (x1 & x2) ^ x3;


	x1 = (State[17] << 5) ^ ((uint16_t)state[36] >> 3);
	x2 = (State[17] << 6) ^ ((uint16_t)state[36] >> 2);
	x3 = (State[3] << 5) ^ (State[4] >> 11);
	
	*t3 ^= (x1 & x2) ^ x3;
}
