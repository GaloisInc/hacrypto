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


#define SPLayer(SPtable_lo, SPtable_hi,index) \
{ \
	sboxvalue = (state >> index) & 0xF; \
	state_lo ^= READ_SBOX_DOUBLE_WORD(SPtable_lo[sboxvalue]); \
	state_hi ^= READ_SBOX_DOUBLE_WORD(SPtable_hi[sboxvalue]); \
}


void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t round;
	uint64_t state = *(uint64_t*)block;

	
	/* Encryption */
	for (round = 0; round < 31; round++)
	{
		/* addRoundkey */
		uint32_t subkey_lo = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * round]);
		uint32_t subkey_hi = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * round + 1]);
		state ^= (uint64_t)subkey_lo ^ (((uint64_t)subkey_hi) << 32);


		/* sBoxLayer */
		uint8_t sboxvalue;
		uint64_t state_lo = 0;
		uint64_t state_hi = 0;
		SPLayer(spBox0_lo, spBox0_hi, 0);
		SPLayer(spBox1_lo, spBox1_hi, 4);
		SPLayer(spBox2_lo, spBox2_hi, 8);
		SPLayer(spBox3_lo, spBox3_hi, 12);
		SPLayer(spBox4_lo, spBox4_hi, 16);
		SPLayer(spBox5_lo, spBox5_hi, 20);
		SPLayer(spBox6_lo, spBox6_hi, 24);
		SPLayer(spBox7_lo, spBox7_hi, 28);
		SPLayer(spBox8_lo, spBox8_hi, 32);
		SPLayer(spBox9_lo, spBox9_hi, 36);
		SPLayer(spBox10_lo, spBox10_hi, 40);
		SPLayer(spBox11_lo, spBox11_hi, 44);
		SPLayer(spBox12_lo, spBox12_hi, 48);
		SPLayer(spBox13_lo, spBox13_hi, 52);
		SPLayer(spBox14_lo, spBox14_hi, 56);
		SPLayer(spBox15_lo, spBox15_hi, 60);

		state = (state_hi << 32) ^ state_lo;
	}


	/* addRoundkey (Round 31) */
	uint32_t subkey_lo = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[62]);
	uint32_t subkey_hi = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[63]);
	state ^= (uint64_t)subkey_lo ^ (((uint64_t)subkey_hi) << 32);


	*(uint64_t*)block = state;
}
