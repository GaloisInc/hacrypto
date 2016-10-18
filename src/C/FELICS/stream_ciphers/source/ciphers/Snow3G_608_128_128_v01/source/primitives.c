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

/* MULx_0x1b */
inline static uint8_t MULx_0x1b(uint8_t v)
{
    uint8_t r;

    r = v << 1;
    if (v & 0x80)
    {
        r ^= 0x1b;
    }

    return r;
}

/* MULx_0x69 */
inline static uint8_t MULx_0x69(uint8_t v)
{
    uint8_t r;

    r = v << 1;
    if (v & 0x80)
    {
        r ^= 0x69;
    }
    return r;
}

/* The 32x32-bit S-Box S1 */
uint32_t S1(uint32_t w)
{
    uint8_t r0;
    uint8_t r1;
    uint8_t r2;
    uint8_t r3;
    uint8_t srw0;
    uint8_t srw1;
    uint8_t srw2;
    uint8_t srw3;

    srw0 = READ_ROM_DATA_BYTE(SR[(uint8_t)((w >> 24) & 0xff)]);
    srw1 = READ_ROM_DATA_BYTE(SR[(uint8_t)((w >> 16) & 0xff)]);
    srw2 = READ_ROM_DATA_BYTE(SR[(uint8_t)((w >> 8) & 0xff)]);
    srw3 = READ_ROM_DATA_BYTE(SR[(uint8_t)((w) & 0xff)]);
    r0 = MULx_0x1b(srw0) ^ srw1 ^ srw2 ^ MULx_0x1b(srw3) ^ srw3;
    r1 = MULx_0x1b(srw0) ^ srw0 ^ MULx_0x1b(srw1) ^ srw2 ^ srw3;
    r2 = srw0 ^ MULx_0x1b(srw1) ^ srw1 ^ MULx_0x1b(srw2) ^ srw3;
    r3 = srw0 ^ srw1 ^ MULx_0x1b(srw2) ^ srw2 ^ MULx_0x1b(srw3);

    return ((((uint32_t)r0) << 24) | (((uint32_t)r1) << 16) | (((uint32_t)r2) << 8) | (((uint32_t)r3)));
}

/* The 32x32-bit S-Box S2 */
uint32_t S2(uint32_t w)
{
    uint8_t r0;
    uint8_t r1;
    uint8_t r2;
    uint8_t r3;
    uint8_t sqw0;
    uint8_t sqw1;
    uint8_t sqw2;
    uint8_t sqw3;

    sqw0 = READ_ROM_DATA_BYTE(SQ[(uint8_t)((w >> 24) & 0xff)]);
    sqw1 = READ_ROM_DATA_BYTE(SQ[(uint8_t)((w >> 16) & 0xff)]);
    sqw2 = READ_ROM_DATA_BYTE(SQ[(uint8_t)((w >> 8) & 0xff)]);
    sqw3 = READ_ROM_DATA_BYTE(SQ[(uint8_t)((w) & 0xff)]);
    r0 = MULx_0x69(sqw0) ^ sqw1 ^ sqw2 ^ MULx_0x69(sqw3) ^ sqw3;
    r1 = MULx_0x69(sqw0) ^ sqw0 ^ MULx_0x69(sqw1) ^ sqw2 ^ sqw3;
    r2 = sqw0 ^ MULx_0x69(sqw1) ^ sqw1 ^ MULx_0x69(sqw2) ^ sqw3;
    r3 = sqw0 ^ sqw1 ^ MULx_0x69(sqw2) ^ sqw2 ^ MULx_0x69(sqw3);

    return ((((uint32_t)r0) << 24) | (((uint32_t)r1) << 16) | (((uint32_t)r2) << 8) | (((uint32_t)r3)));
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

    F = ((LFSR[15] + *FSM_R1) & 0xffffffff) ^ *FSM_R2 ;
    r = (*FSM_R2 + (*FSM_R3 ^ LFSR[5])) & 0xffffffff ;
    *FSM_R3 = S2(*FSM_R2);
    *FSM_R2 = S1(*FSM_R1);
    *FSM_R1 = r;

    return F;
}
