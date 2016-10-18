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

#include "constants.h"

/* rotate w by 8 bits to the left */
static inline uint32_t rotateLeft8(uint32_t w)
{
	return (w << 8) | (w >> 24);
}

/* rotate w by 16 bits to the left */
static inline uint32_t rotateLeft16(uint32_t w)
{
	return (w << 16) | (w >> 16);
}

/* rotate w by 24 bits to the left */
static inline uint32_t rotateLeft24(uint32_t w)
{
	return (w << 24) | (w >> 8);
}

/* The 32x32-bit S-Box S1 */
uint32_t S1(uint32_t w)
{
	uint8_t w3 = (w >> 24) & 0xff;
	uint8_t w2 = (w >> 16) & 0xff;
	uint8_t w1 = (w >> 8) & 0xff;
	uint8_t w0 = (w >> 0) & 0xff;

	return READ_ROM_DATA_DOUBLE_WORD(S1_T0[w0]) ^
	       rotateLeft8(READ_ROM_DATA_DOUBLE_WORD(S1_T0[w1])) ^
	       rotateLeft16(READ_ROM_DATA_DOUBLE_WORD(S1_T0[w2])) ^
	       rotateLeft24(READ_ROM_DATA_DOUBLE_WORD(S1_T0[w3]));
}

/* The 32x32-bit S-Box S2 */
uint32_t S2(uint32_t w)
{
	uint8_t w3 = (w >> 24) & 0xff;
	uint8_t w2 = (w >> 16) & 0xff;
	uint8_t w1 = (w >> 8) & 0xff;
	uint8_t w0 = (w >> 0) & 0xff;

	return READ_ROM_DATA_DOUBLE_WORD(S2_T0[w0]) ^
	       rotateLeft8(READ_ROM_DATA_DOUBLE_WORD(S2_T0[w1])) ^
	       rotateLeft16(READ_ROM_DATA_DOUBLE_WORD(S2_T0[w2])) ^
	       rotateLeft24(READ_ROM_DATA_DOUBLE_WORD(S2_T0[w3]));
}


/* Clocking FSM */
uint32_t ClockFSM(uint8_t *state)
{
	uint32_t *LFSR = (uint32_t *)state;
	uint32_t *FSM_R1 = ((uint32_t *)state) + 16;
	uint32_t *FSM_R2 = FSM_R1 + 1;
	uint32_t *FSM_R3 = FSM_R1 + 2;
    uint32_t F;
    uint32_t r;

    F = ((LFSR[15] + *FSM_R1)) ^ *FSM_R2;
    r = (*FSM_R2 + (*FSM_R3 ^ LFSR[5]));
    *FSM_R3 = S2(*FSM_R2);
    *FSM_R2 = S1(*FSM_R1);
    *FSM_R1 = r;

    return F;
}
