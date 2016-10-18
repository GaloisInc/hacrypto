/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu>
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


void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	ALIGNED uint64_t *stateQWordPtr = (uint64_t *)block;
	ALIGNED uint8_t *stateByte0Ptr = (uint8_t *)block;
	ALIGNED uint32_t *stateDWordPtr = (uint32_t *)block;
	ALIGNED uint32_t subkey;
	ALIGNED uint8_t round;
	ALIGNED uint8_t k;
	ALIGNED uint8_t sBoxValue;
	ALIGNED uint8_t position;
	ALIGNED uint8_t temp[8];
	ALIGNED uint8_t srcByte;
	ALIGNED uint8_t srcBit;
	ALIGNED uint8_t tgtByte;
	ALIGNED uint8_t tgtBit;

	for (round = 0; round < 31; round++)
	{
		/* addRoundkey */
		subkey = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * round]);
		stateDWordPtr[0] ^= subkey;
		subkey = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * round + 1]);
		stateDWordPtr[1] ^= subkey;

		/* sBoxLayer */
		for (k = 0; k < 16; k++)
		{
			/* get lowest nibble */
			sBoxValue = *stateByte0Ptr & 0xF;

			/* kill lowest nibble */
			stateByte0Ptr[0] &= 0xF0; 

			/* put new value to lowest nibble (sBox) */
			stateByte0Ptr[0] |= READ_SBOX_BYTE(sBox4[sBoxValue]);

			/* next(rotate by one nibble) */
			*stateQWordPtr = rotate4l_64(*stateQWordPtr);
		}

		/* pLayer */
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
			temp[tgtByte] |= (((stateByte0Ptr[srcByte] >> srcBit) & 0x01) << tgtBit);
			position += 16;
		}

		/* bit #63 */
		temp[7] |= stateByte0Ptr[7] & 0x80;

		/* result writing */
		stateDWordPtr[0] = *(uint32_t *)(&temp[0]);
		stateDWordPtr[1] = *(uint32_t *)(&temp[4]);
	}

	/* addRoundkey (Round 31) */
	subkey = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[62]);
	stateDWordPtr[0] ^= subkey;
	subkey = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[63]);
	stateDWordPtr[1] ^= subkey;
}
