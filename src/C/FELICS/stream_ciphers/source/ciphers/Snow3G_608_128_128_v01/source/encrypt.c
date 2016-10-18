/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu>
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
#include "primitives.h"


void ClockLFSRKeyStreamMode(uint8_t *state)
{
	uint32_t *LFSR = (uint32_t *)state;
	uint32_t v;

	v = (
		((LFSR[0] << 8) & 0xffffff00) ^
		READ_ROM_DATA_DOUBLE_WORD(MULALPHA[(uint8_t)((LFSR[0] >> 24) & 0xff)]) ^
		LFSR[2] ^
		((LFSR[11] >> 8) & 0x00ffffff) ^
		READ_ROM_DATA_DOUBLE_WORD(DIVALPHA[(uint8_t)((LFSR[11]) & 0xff)])
	);
	LFSR[0] = LFSR[1];
	LFSR[1] = LFSR[2];
	LFSR[2] = LFSR[3];
	LFSR[3] = LFSR[4];
	LFSR[4] = LFSR[5];
	LFSR[5] = LFSR[6];
	LFSR[6] = LFSR[7];
	LFSR[7] = LFSR[8];
	LFSR[8] = LFSR[9];
	LFSR[9] = LFSR[10];
	LFSR[10] = LFSR[11];
	LFSR[11] = LFSR[12];
	LFSR[12] = LFSR[13];
	LFSR[13] = LFSR[14];
	LFSR[14] = LFSR[15];
	LFSR[15] = v;
}

void Encrypt(uint8_t *state, uint8_t *stream, uint16_t length)
{
	uint32_t *LFSR = (uint32_t *)state;
	uint32_t t;
	uint32_t F;
	uint32_t ks;
	uint32_t *stream32 = (uint32_t *)stream;
	uint32_t *FSM_R1 = ((uint32_t *)state) + 16;
	uint32_t *FSM_R2 = FSM_R1 + 1;

	ClockFSM(state);
	ClockLFSRKeyStreamMode(state); /* Clock LFSR in keystream mode once. */
	for (t = 0; t < length/4 - 1; t++)
	{
		F = ClockFSM(state); /* STEP 1 */
		ks = (F ^ LFSR[0]); /* STEP 2 */
		*(stream32 + t) = ks;
		ClockLFSRKeyStreamMode(state); /* STEP 3 */
	}
	/* reduced ClockFSM() for last round */
	F = ((LFSR[15] + *FSM_R1)) ^ *FSM_R2;
	/* produce last keystream sample */
	ks = (F ^ LFSR[0]);
	*(stream32 + t) = ks;
}
