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

	
	/* Initialize register A */
	State[0] = Key[4];
	State[1] = Key[3];
	State[2] = Key[2];
	State[3] = Key[1];
	State[4] = Key[0];

	State[5] = 0x0000;

	
	/* Initialize register B */
	State[6] = IV[4];
	State[7] = IV[3];
	State[8] = IV[2];
	State[9] = IV[1];
	State[10] = IV[0];

	State[11] = 0x0000;


	/* Initialize register C */
	State[12] = 0x0000;
	State[13] = 0x0000;
	State[14] = 0x0000;
	State[15] = 0x0000;
	State[16] = 0x0000;
	State[17] = 0x0000;

	state[36] = 0x0E;


	for (i = 0; i < 72; i++)
	{
		Update(state, &t1, &t2, &t3, &s);
		Rotate(state, &t1, &t2, &t3);
	}
}
