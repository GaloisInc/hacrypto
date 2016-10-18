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


void Rotate(uint8_t *state, uint16_t *t1, uint16_t *t2, uint16_t *t3)
{
	uint8_t i;

	uint16_t *State = (uint16_t *)state;


	/* Rotate register C */
	state[36] = state[35];

	for (i = 17; i > 12 ; i--)
	{
		State[i] = State[i - 1];
	}

	state[25] = (uint8_t)*t2;					
	state[24] = state[22];
	state[23] = state[21];


	/* Rotate register B */
	state[22] = (uint8_t)(*t2 >> 8);
	
	for (i = 10; i > 6 ; i--)
	{
		State[i] = State[i - 1];
	}

	State[6] = *t1;
	

	/* Rotate register A */
	for (i = 5; i > 0 ; i--)
	{
		State[i] = State[i - 1];
	}

	State[0] = *t3;
}
