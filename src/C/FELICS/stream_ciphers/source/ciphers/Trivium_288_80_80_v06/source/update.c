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


void Update(uint16_t *state, uint16_t *t1, uint16_t *t2, uint16_t *t3, uint16_t *stream)
{
	uint16_t x1, x2, x3, x4, x5;
	

	x1 = (state[3] << 2) ^ (state[4] >> 14);
	x4 = (state[4] << 13) ^ (state[5] >> 3);

	*t1 = x1 ^ x4;


	x1 = (state[9] << 2) ^ (state[10] >> 14);
	x4 = (state[10] << 1) ^ (state[11] >> 15);

	*t2 = x1 ^ x4;


	x1 = (state[14] << 3) ^ (state[15] >> 13);
	x4 = state[17];
	
	*t3 = x1 ^ x4;

	
	*stream ^= *t1 ^ *t2 ^ *t3;


	x2 = (state[4] << 11) ^ (state[5] >> 5);
	x3 = (state[4] << 12) ^ (state[5] >> 4);
	x5 = (state[9] << 11) ^ (state[10] >> 5);

	*t1 ^= (x2 & x3) ^ x5;


	x2 = (state[9] << 15) ^ (state[10] >> 1);
	x3 = state[10];
	x5 = (state[15] << 8) ^ (state[16] >> 8);

	*t2 ^= (x2 & x3) ^ x5;


	x2 = (state[16] << 14) ^ (state[17] >> 2);
	x3 = (state[16] << 15) ^ (state[17] >> 1);
	x5 = (state[3] << 5) ^ (state[4] >> 11);
	
	*t3 ^= (x2 & x3) ^ x5;
}
