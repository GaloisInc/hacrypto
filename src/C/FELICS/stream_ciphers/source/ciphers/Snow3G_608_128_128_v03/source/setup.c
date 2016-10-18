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

void Setup(uint8_t *state, uint8_t *key, uint8_t *iv)
{
    uint8_t i;
    uint32_t F;
	uint32_t v;
	uint32_t *LFSR = (uint32_t *)state;
	uint32_t *FSM_R1 = ((uint32_t *)state) + 16;
	uint32_t *FSM_R2 = FSM_R1 + 1;
	uint32_t *FSM_R3 = FSM_R1 + 2;
	uint32_t *k32 = (uint32_t *)key;
	uint32_t *iv32 = (uint32_t *)iv;

    LFSR[15] = k32[3] ^ iv32[0];
    LFSR[14] = k32[2];
    LFSR[13] = k32[1];
    LFSR[12] = k32[0] ^ iv32[1];
    LFSR[11] = k32[3] ^ 0xffffffff;
    LFSR[10] = k32[2] ^ 0xffffffff ^ iv32[2];
    LFSR[9] = k32[1] ^ 0xffffffff ^ iv32[3];
    LFSR[8] = k32[0] ^ 0xffffffff;
    LFSR[7] = k32[3];
    LFSR[6] = k32[2];
    LFSR[5] = k32[1];
    LFSR[4] = k32[0];
    LFSR[3] = k32[3] ^ 0xffffffff;
    LFSR[2] = k32[2] ^ 0xffffffff;
    LFSR[1] = k32[1] ^ 0xffffffff;
    LFSR[0] = k32[0] ^ 0xffffffff;
    *FSM_R1 = 0x0;
    *FSM_R2 = 0x0;
    *FSM_R3 = 0x0;

	/* 1st iteration can be optimized since we know that R1 = R2 = R3 = 0 */
	F = LFSR[15];
	*FSM_R3 = 0x25252525;
	*FSM_R2 = 0x63636363;
	*FSM_R1 = LFSR[5];
	v = (
		((LFSR[0] << 8) & 0xffffff00) ^
		READ_ROM_DATA_DOUBLE_WORD(MULALPHA[(uint8_t)((LFSR[0] >> 24) & 0xff)]) ^
		LFSR[2] ^
		((LFSR[11] >> 8) & 0x00ffffff) ^
		READ_ROM_DATA_DOUBLE_WORD(DIVALPHA[(uint8_t)((LFSR[11]) & 0xff)]) ^
		F
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
	/* other iterations */
    for (i = 1; i < 32; i++)
    {
		F = ClockFSM(state);
		v = (
			((LFSR[0] << 8) & 0xffffff00) ^
			READ_ROM_DATA_DOUBLE_WORD(MULALPHA[(uint8_t)((LFSR[0] >> 24) & 0xff)]) ^
			LFSR[2] ^
			((LFSR[11] >> 8) & 0x00ffffff) ^
			READ_ROM_DATA_DOUBLE_WORD(DIVALPHA[(uint8_t)((LFSR[11]) & 0xff)]) ^
			F
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
}
