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

#include "rotate.h"


void Rotate(uint16_t *state, uint16_t *t1, uint16_t *t2, uint16_t *t3)
{
	uint8_t i;


	/* Rotate register C */
	for (i = 17; i > 12 ; i--)
	{
		state[i] = state[i - 1];
	}

	state[12] = (*t2 << 15) ^ (state[11] & 0x7FFF);
	state[11] =  (state[10] & 0x8000) ^ ((*t2 >> 1));


	/* Rotate register B */
	for (i = 10; i > 6 ; i--)
	{
		state[i] = state[i - 1];
	}

	state[6] = (*t1 << 3) ^ (state[5] & 0x0007);
	state[5] = (state[4] & 0xFFF8) ^ (*t1 >> 13);
	

	/* Rotate register A */
	for (i = 4; i > 0 ; i--)
	{
		state[i] = state[i - 1];
	}

	state[0] = *t3;
}
