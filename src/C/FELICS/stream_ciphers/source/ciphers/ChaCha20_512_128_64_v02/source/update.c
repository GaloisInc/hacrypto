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

#include "update.h"
#include "constants.h"
#include "rot32.h"


#define NUMBER_OF_ROUNDS 20


void static inline QuarterRound(uint32_t *state, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	state[a] += state[b];
	state[d] ^= state[a];
	state[d] = rot32l16(state[d]);

	state[c] += state[d];
	state[b] ^= state[c];
	state[b] = rot32l12(state[b]);

	state[a] += state[b];
	state[d] ^= state[a];
	state[d] = rot32l8(state[d]);

	state[c] += state[d];
	state[b] ^= state[c];
	state[b] = rot32l7(state[b]);
}


void Update(uint8_t *state, uint8_t *keyStream)
{
	uint8_t i;

	uint32_t *State = (uint32_t *)state;
	uint32_t *KeyStream = (uint32_t *)keyStream;
	

	for(i = 0; i < STATE_SIZE / 4; i++)
	{
		KeyStream[i] = State[i];
	}
	

	for(i = 0; i < NUMBER_OF_ROUNDS / 2; i++)
	{
		QuarterRound(KeyStream, 0, 4, 8, 12);
		QuarterRound(KeyStream, 1, 5, 9, 13);
		QuarterRound(KeyStream, 2, 6, 10, 14);
		QuarterRound(KeyStream, 3, 7, 11, 15);

		QuarterRound(KeyStream, 0, 5, 10, 15);
		QuarterRound(KeyStream, 1, 6, 11, 12);
		QuarterRound(KeyStream, 2, 7, 8, 13);
		QuarterRound(KeyStream, 3, 4, 9, 14);
	}


	for(i = 0; i < STATE_SIZE / 4; i++)
	{
		KeyStream[i] += State[i];
	}


	State[12] += 1;
    if(!State[12]) 
	{
		State[13] += 1;
	}
}
