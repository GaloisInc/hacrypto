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


/* u = w / 8 = 32 / 8 = 4 */
#define u 4

/* c = ceil(b / u) = ceil (KEY_SIZE / u) = ceil (16 / 4) = 4 */
#define c 4

/* t = 2 * (r + 1) = 2 * (NUMBER_OF_ROUNDS + 1) = 2 * (20 + 1) = 42 */
#define t 42 

 /* magic constants */
#define P 0xb7e15163
#define Q 0x9e3779b9 


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	int32_t i;
	uint32_t j, k;
	uint32_t A, B; 
	uint32_t L[c];

	uint32_t *RoundKeys = (uint32_t *)roundKeys;

	
	/* Initialize L, then S, then mix key into S */
	L[c - 1] = 0;
	for(i = KEY_SIZE - 1; i != -1; i--) 
	{
		L[i / u] = (L[i / u] << 8) + key[i];
	}

	RoundKeys[0] = P;
	for(i = 1; i < t; i++) 
	{
		RoundKeys[i] = RoundKeys[i - 1] + Q;
	}

	A = B = i = j = 0;
	for(k = 0; k < 3 * t; k++) 
	{
		A = RoundKeys[i] = RC5_ROTL(RoundKeys[i] + (A + B), 3);
		B = L[j] = RC5_ROTL(L[j] + (A + B), (A + B));

		i = (i + 1) % t;
		j = (j + 1) % c;
	}
}
