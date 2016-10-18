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


/* input rotated left (4x) */
#define rotate4l_64(r4lin) 	( high4_64(r4lin) | ( r4lin << 4 ) )


/* 4 MSB as LSB */
#define high4_64(h4in)		( (uint64_t)h4in >> 60 )


#define PLayer(Ptable_lo, Ptable_hi,index) \
{ \
	sboxvalue = (state >> index) & 0xF; \
	state_lo ^= READ_SBOX_DOUBLE_WORD(Ptable_lo[sboxvalue]); \
	state_hi ^= READ_SBOX_DOUBLE_WORD(Ptable_hi[sboxvalue]); \
}

#define SBOXANDROTATE \
{ \
	sboxvalue = state & 0xF;	\
	state &= 0xFFFFFFFFFFFFFFF0;			\
	state |= READ_SBOX_BYTE(invsBox4[sboxvalue]); \
	state = rotate4l_64(state);				\
}


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint64_t state = *(uint64_t*)block;
	uint64_t temp;
	uint32_t subkey_lo, subkey_hi;

	uint8_t keyindex = 31;
	uint8_t i;
	

	for (i = 0; i < 31; i++)
	{
		/* addRoundkey */
		subkey_lo = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * keyindex]);
		subkey_hi = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * keyindex + 1]);

		state ^= (uint64_t)subkey_lo ^ (((uint64_t)subkey_hi) << 32);

		keyindex--;
		

		/* pLayer */
		temp = 0;
		uint8_t sboxvalue;
		uint64_t state_lo = 0;
		uint64_t state_hi = 0;
		PLayer(ipBox0_lo, ipBox0_hi, 0);
		PLayer(ipBox1_lo, ipBox1_hi, 4);
		PLayer(ipBox2_lo, ipBox2_hi, 8);
		PLayer(ipBox3_lo, ipBox3_hi, 12);
		PLayer(ipBox4_lo, ipBox4_hi, 16);
		PLayer(ipBox5_lo, ipBox5_hi, 20);
		PLayer(ipBox6_lo, ipBox6_hi, 24);
		PLayer(ipBox7_lo, ipBox7_hi, 28);
		PLayer(ipBox8_lo, ipBox8_hi, 32);
		PLayer(ipBox9_lo, ipBox9_hi, 36);
		PLayer(ipBox10_lo, ipBox10_hi, 40);
		PLayer(ipBox11_lo, ipBox11_hi, 44);
		PLayer(ipBox12_lo, ipBox12_hi, 48);
		PLayer(ipBox13_lo, ipBox13_hi, 52);
		PLayer(ipBox14_lo, ipBox14_hi, 56);
		PLayer(ipBox15_lo, ipBox15_hi, 60);

		state = (state_hi << 32) ^ state_lo;
		

		/* sBoxLayer */
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
		SBOXANDROTATE;
	}


	/* addRoundkey (Round 31) */
	subkey_lo = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * keyindex]);
	subkey_hi = READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)roundKeys)[2 * keyindex + 1]);

	state ^= (uint64_t)subkey_lo ^ (((uint64_t)subkey_hi) << 32);


	*(uint64_t*)block = state;
}
