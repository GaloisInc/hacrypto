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


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	/* 
	 * 	The following instructions are failing on ARMv7-M using the 
	 * arm-none-eabi-g++ (Sourcery CodeBench Lite 2014.05-28) 4.8.3 20140320 
	 * (prerelease) compiler because of the optimizer is grouping the 2 memory 
	 * accesses in one LDRD instruction. However the 2 memory addresses are not 
	 * aligned on 64-bit boundaries and the instruction causes an UNALIGN_TRAP 
	 * (which can not be disabled for LDRD instruction):
	 * 		uint64_t keylow = *(uint64_t *)key;
	 * 		uint64_t keyhigh = *(uint64_t*)(key + 2);
	 *  
	 *	The next 3 lines replace the wrong instruction sequence:
	 * 		uint64_t keylow = *(uint64_t *)key;
	 * 		uint16_t highBytes = *(uint16_t *)(key + 8);
	 * 		uint64_t keyhigh = ((uint64_t)(highBytes) << 48) | (keylow >> 16);
	 *
	 */
	uint64_t keylow = *(uint64_t *)key;
	uint16_t highBytes = *(uint16_t *)(key + 8);
	uint64_t keyhigh = ((uint64_t)(highBytes) << 48) | (keylow >> 16);

	uint64_t temp;
	uint8_t round;
	

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
		temp = READ_SBOX_BYTE(sBox4[temp]);
		keyhigh |= temp << 60;

		/* round counter addition */
		keylow ^= (((uint64_t)(round + 1) & 0x01) << 15);
		keyhigh ^= ((uint64_t)(round + 1) >> 1);
	}
}
