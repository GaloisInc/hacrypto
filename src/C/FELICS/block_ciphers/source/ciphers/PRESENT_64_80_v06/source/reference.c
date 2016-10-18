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

/****************************************************************************** 
 *
 * Reference implementation for cipher layers
 *
 * Compiled but should not be present in the final elf file since
 * no function is used
 * 
 ******************************************************************************/

/******** Intentionally not mentionned in implementation.info *******/

#include <stdint.h>
#include "cipher.h"
#include "constants.h"

#include <stdio.h>
#include <string.h>

void printBlock(uint8_t *block)
{
	uint8_t i;

	for (i = 0; i < 8; i++)
	{
		printf("0x%02x ", block[i]);
	}
	printf("\n");
}

void pLayerRef(uint8_t *block)
{
    ALIGNED uint8_t k;
    ALIGNED uint32_t *stateDWordPtr = (uint32_t *)block;
    ALIGNED uint8_t position;
    ALIGNED uint8_t temp[8];
    ALIGNED uint8_t srcByte;
    ALIGNED uint8_t srcBit;
    ALIGNED uint8_t tgtByte;
    ALIGNED uint8_t tgtBit;

    position = 0;
    *(uint64_t *)temp = 0;
    for (k = 0; k < 63; k++)
    {
        if (position > 62)
        {
            position = position - 63;
        }
        srcByte = k >> 3;
        srcBit = k & 0x07;
        tgtByte = position >> 3;
        tgtBit = position & 0x07;
        temp[tgtByte] |= (((block[srcByte] >> srcBit) & 0x01) << tgtBit);
        position += 16;
    }

    /* bit #63 */
    temp[7] |= block[7] & 0x80;

    /* result writing */
    stateDWordPtr[0] = *(uint32_t *)(&temp[0]);
    stateDWordPtr[1] = *(uint32_t *)(&temp[4]);
}

void sboxLayerRef(uint8_t *block)
{
    ALIGNED uint8_t k;

    for (k = 0; k < 8; k++)
    {
        block[k] = READ_SBOX_BYTE(sBox[block[k]]);
    }
}

void invSboxLayerRef(uint8_t *block)
{
    ALIGNED uint8_t k;

    for (k = 0; k < 8; k++)
    {
        block[k] = READ_SBOX_BYTE(invsBox[block[k]]);
    }
}

void addRoundKeyLayerRef(uint8_t *block, uint8_t *roundKey)
{
    ALIGNED uint32_t subkey;
    ALIGNED uint32_t *stateDWordPtr = (uint32_t *)block;

    subkey = *((uint32_t *)roundKey);
    stateDWordPtr[0] ^= subkey;
    subkey = *((uint32_t *)roundKey + 1);
    stateDWordPtr[1] ^= subkey;
}

#define MOVE_BIT(x, n ,p) ((((x) >> (n)) & 0x01) << p)

void invpLayerRef(uint8_t *block)
{
	uint8_t i;
    uint8_t temp[8];

	for (i = 0; i < 8; i++)
	{
		temp[i] = 0;
	}

	temp[0] =
		MOVE_BIT(block[0], 0, 0) | MOVE_BIT(block[2], 0, 1) | MOVE_BIT(block[4], 0, 2) | MOVE_BIT(block[6], 0, 3) |
		MOVE_BIT(block[0], 1, 4) | MOVE_BIT(block[2], 1, 5) | MOVE_BIT(block[4], 1, 6) | MOVE_BIT(block[6], 1, 7);
	temp[1] =
		MOVE_BIT(block[0], 2, 0) | MOVE_BIT(block[2], 2, 1) | MOVE_BIT(block[4], 2, 2) | MOVE_BIT(block[6], 2, 3) |
		MOVE_BIT(block[0], 3, 4) | MOVE_BIT(block[2], 3, 5) | MOVE_BIT(block[4], 3, 6) | MOVE_BIT(block[6], 3, 7);
	temp[2] =
		MOVE_BIT(block[0], 4, 0) | MOVE_BIT(block[2], 4, 1) | MOVE_BIT(block[4], 4, 2) | MOVE_BIT(block[6], 4, 3) |
		MOVE_BIT(block[0], 5, 4) | MOVE_BIT(block[2], 5, 5) | MOVE_BIT(block[4], 5, 6) | MOVE_BIT(block[6], 5, 7);
	temp[3] =
		MOVE_BIT(block[0], 6, 0) | MOVE_BIT(block[2], 6, 1) | MOVE_BIT(block[4], 6, 2) | MOVE_BIT(block[6], 6, 3) |
		MOVE_BIT(block[0], 7, 4) | MOVE_BIT(block[2], 7, 5) | MOVE_BIT(block[4], 7, 6) | MOVE_BIT(block[6], 7, 7);
	temp[4] =
		MOVE_BIT(block[1], 0, 0) | MOVE_BIT(block[3], 0, 1) | MOVE_BIT(block[5], 0, 2) | MOVE_BIT(block[7], 0, 3) |
		MOVE_BIT(block[1], 1, 4) | MOVE_BIT(block[3], 1, 5) | MOVE_BIT(block[5], 1, 6) | MOVE_BIT(block[7], 1, 7);
	temp[5] =
		MOVE_BIT(block[1], 2, 0) | MOVE_BIT(block[3], 2, 1) | MOVE_BIT(block[5], 2, 2) | MOVE_BIT(block[7], 2, 3) |
		MOVE_BIT(block[1], 3, 4) | MOVE_BIT(block[3], 3, 5) | MOVE_BIT(block[5], 3, 6) | MOVE_BIT(block[7], 3, 7);
	temp[6] =
		MOVE_BIT(block[1], 4, 0) | MOVE_BIT(block[3], 4, 1) | MOVE_BIT(block[5], 4, 2) | MOVE_BIT(block[7], 4, 3) |
		MOVE_BIT(block[1], 5, 4) | MOVE_BIT(block[3], 5, 5) | MOVE_BIT(block[5], 5, 6) | MOVE_BIT(block[7], 5, 7);
	temp[7] =
		MOVE_BIT(block[1], 6, 0) | MOVE_BIT(block[3], 6, 1) | MOVE_BIT(block[5], 6, 2) | MOVE_BIT(block[7], 6, 3) |
		MOVE_BIT(block[1], 7, 4) | MOVE_BIT(block[3], 7, 5) | MOVE_BIT(block[5], 7, 6) | MOVE_BIT(block[7], 7, 7);

	for (i = 0; i < 8; i++)
	{
		block[i] = temp[i];
	}
}

void eksRef(uint8_t *key, uint8_t *roundKeys)
{
    /*
     *  The following instructions are failing on ARMv7-M using the
     * arm-none-eabi-g++ (Sourcery CodeBench Lite 2014.05-28) 4.8.3 20140320
     * (prerelease) compiler because of the optimizer is grouping the 2 memory
     * accesses in one LDRD instruction. However the 2 memory addresses are not
     * aligned on 64-bit boundaries and the instruction causes an UNALIGN_TRAP
     * (which can not be disabled for LDRD instruction):
     *      uint64_t keylow = *(uint64_t *)key;
     *      uint64_t keyhigh = *(uint64_t*)(key + 2);
     *
     *  The next 3 lines replace the wrong instruction sequence:
     *      uint64_t keylow = *(uint64_t *)key;
     *      uint16_t highBytes = *(uint16_t *)(key + 8);
     *      uint64_t keyhigh = ((uint64_t)(highBytes) << 48) | (keylow >> 16);
     *
     */
    ALIGNED uint64_t keylow = *(uint64_t *)key;
    ALIGNED uint16_t highBytes = *(uint16_t *)(key + 8);
    ALIGNED uint64_t keyhigh = ((uint64_t)(highBytes) << 48) | (keylow >> 16);
    ALIGNED uint64_t temp;
    ALIGNED uint8_t round;

    for (round = 0; round < 32; round++)
    {
        /* 61-bit left shift */
        ((uint64_t*)roundKeys)[round] = keyhigh;
        temp = keyhigh;
        keyhigh <<= 61;
        keyhigh |= (keylow << 45);
        keyhigh |= (temp >> 19);
        keylow = (temp >> 3) & 0xFFFF;

        /* S-Box application */
        temp = keyhigh >> 60;
        keyhigh &= 0x0FFFFFFFFFFFFFFF;
        temp = READ_SBOX_BYTE(sBox[temp]);
        temp &= 0x0f;
        keyhigh |= temp << 60;

        /* round counter addition */
        keylow ^= (((uint64_t)(round + 1) & 0x01) << 15);
        keyhigh ^= ((uint64_t)(round + 1) >> 1);
    }
}
