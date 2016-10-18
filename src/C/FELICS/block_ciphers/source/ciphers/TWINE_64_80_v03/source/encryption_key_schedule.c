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
	uint8_t KeyR[20];
	uint8_t temp, temp1, temp2, temp3;
	uint8_t i;
	
	uint16_t *master_key = (uint16_t*)key;

	
	for (i = 0; i < 20; i++)
	{
		KeyR[i] = (master_key[(i / 4)] >> (4 * (i & 0x03))) & 0x0F;
	}

	for (i = 0; i < 35; i++)
	{
		roundKeys[8 * i + 0] = KeyR[1];
		roundKeys[8 * i + 1] = KeyR[3];
		roundKeys[8 * i + 2] = KeyR[4];
		roundKeys[8 * i + 3] = KeyR[6];
		roundKeys[8 * i + 4] = KeyR[13];
		roundKeys[8 * i + 5] = KeyR[14];
		roundKeys[8 * i + 6] = KeyR[15];
		roundKeys[8 * i + 7] = KeyR[16];

		KeyR[1] = KeyR[1] ^ READ_SBOX_BYTE(Sbox_byte[KeyR[0]]);
		KeyR[4] = KeyR[4] ^ READ_SBOX_BYTE(Sbox_byte[KeyR[16]]);
		KeyR[7] = KeyR[7] ^ (READ_KS_BYTE(RCON[i]) >> 3);
		KeyR[19] = KeyR[19] ^ (READ_KS_BYTE(RCON[i]) & 0x07);

		temp = KeyR[0];
		KeyR[0] = KeyR[1];
		KeyR[1] = KeyR[2];
		KeyR[2] = KeyR[3];
		KeyR[3] = temp;

		temp = KeyR[0];
		temp1 = KeyR[1];
		temp2 = KeyR[2];
		temp3 = KeyR[3];

		KeyR[0] = KeyR[4];
		KeyR[1] = KeyR[5];
		KeyR[2] = KeyR[6];
		KeyR[3] = KeyR[7];

		KeyR[4] = KeyR[8];
		KeyR[5] = KeyR[9];
		KeyR[6] = KeyR[10];
		KeyR[7] = KeyR[11];

		KeyR[8] = KeyR[12];
		KeyR[9] = KeyR[13];
		KeyR[10] = KeyR[14];
		KeyR[11] = KeyR[15];

		KeyR[12] = KeyR[16];
		KeyR[13] = KeyR[17];
		KeyR[14] = KeyR[18];
		KeyR[15] = KeyR[19];

		KeyR[16] = temp;
		KeyR[17] = temp1;
		KeyR[18] = temp2;
		KeyR[19] = temp3;
	}

	roundKeys[280] = KeyR[1];
	roundKeys[281] = KeyR[3];
	roundKeys[282] = KeyR[4];
	roundKeys[283] = KeyR[6];
	roundKeys[284] = KeyR[13];
	roundKeys[285] = KeyR[14];
	roundKeys[286] = KeyR[15];
	roundKeys[287] = KeyR[16];
}
