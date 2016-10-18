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


void Update(uint64_t *state, uint64_t *t1, uint64_t *t2, uint64_t *t3, uint64_t *stream)
{
	uint64_t x1, x2, x3, x4, x5;
	

	x1 = (state[0] << 2) ^ (state[1] >> 62);
	x4 = (state[0] << 29) ^ (state[1] >> 35);		

	*t1 = x1 ^ x4;


	x1 = (state[2] << 5) ^ (state[3] >> 59);
	x4 = (state[2] << 20) ^ (state[3] >> 44);

	*t2 = x1 ^ x4;


	x1 = (state[4] << 2) ^ (state[5] >> 62);
	x4 = (state[4] << 47) ^ (state[5] >> 17);

	*t3 = x1 ^ x4;


	*stream ^= *t1 ^ *t2 ^ *t3;


	x2 = (state[0] << 27) ^ (state[1] >> 37);
	x3 = (state[0] << 28) ^ (state[1] >> 36);
	x5 = (state[2] << 14) ^ (state[3] >> 50);

	*t1 ^= (x2 & x3) ^ x5;


	x2 = (state[2] << 18) ^ (state[3] >> 46);
	x3 = (state[2] << 19) ^ (state[3] >> 45);
	x5 =  (state[4] << 23) ^ (state[5] >> 41);

	*t2 ^= (x2 & x3) ^ x5;


	x2 = (state[4] << 45) ^ (state[5] >> 19);
	x3 = (state[4] << 46) ^ (state[5] >> 18);
	x5 = (state[0] << 5) ^ (state[1] >> 59);

	*t3 ^= (x2 & x3) ^ x5;
}
