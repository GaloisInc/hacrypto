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

/*
This file is part of the AVR-Crypto-Lib.
Copyright (C) 2008, 2009  Daniel Otte (daniel.otte@rub.de)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "gmul_o.h"


void aes_invshiftcol(uint8_t *data, uint8_t shift)
{
	uint8_t tmp[4];

	
	tmp[0] = data[0];
	tmp[1] = data[4];
	tmp[2] = data[8];
	tmp[3] = data[12];

	data[0] = tmp[(4 - shift + 0) & 3];
	data[4] = tmp[(4 - shift + 1) & 3];
	data[8] = tmp[(4 - shift + 2) & 3];
	data[12] = tmp[(4 - shift + 3) & 3];
}

static void aes_dec_round(uint8_t *block, uint8_t *roundKey)
{
	uint8_t tmp[16];
	uint8_t i;
	uint8_t t, u, v, w;

	
	/* keyAdd */
	for (i = 0; i < 16; ++i)
	{
		tmp[i] = block[i] ^ READ_ROUND_KEY_BYTE(roundKey[i]);
	}
	
	/* mixColums */
	for (i = 0; i < 4; ++i)
	{
		t = tmp[4 * i + 3] ^ tmp[4 * i + 2];
		u = tmp[4 * i + 1] ^ tmp[4 * i + 0];
		v = t ^ u;
		v = gmul_o(0x09, v);
		w = v ^ gmul_o(0x04, tmp[4 * i + 2] ^ tmp[4 * i + 0]);
		v = v ^ gmul_o(0x04, tmp[4 * i + 3] ^ tmp[4 * i + 1]);
		
		block[4 * i + 3] = tmp[4 * i + 3] ^ v ^ gmul_o(0x02, tmp[4 * i + 0] ^ tmp[4 * i + 3]);
		block[4 * i + 2] = tmp[4 * i + 2] ^ w ^ gmul_o(0x02, t);
		block[4 * i + 1] = tmp[4 * i + 1] ^ v ^ gmul_o(0x02, tmp[4 * i + 2] ^ tmp[4 * i + 1]);
		block[4 * i + 0] = tmp[4 * i + 0] ^ w ^ gmul_o(0x02, u);

		
	}
	
	/* shiftRows */
	aes_invshiftcol(block + 1, 1);
	aes_invshiftcol(block + 2, 2);
	aes_invshiftcol(block + 3, 3);
	
	/* subBytes */
	for (i = 0; i < 16; ++i)
	{
		block[i] = READ_SBOX_BYTE(aes_invsbox[block[i]]);
	}
}

static void aes_dec_firstround(uint8_t *block, uint8_t *roundKey)
{
	uint8_t i;

	
	/* keyAdd */
	for (i = 0; i < 16; ++i)
	{
		block[i] ^= READ_ROUND_KEY_BYTE(roundKey[i]);
	}
	
	/* shiftRows */
	aes_invshiftcol(block + 1, 1);
	aes_invshiftcol(block + 2, 2);
	aes_invshiftcol(block + 3, 3);
	
	/* subBytes */
	for (i = 0; i < 16; ++i)
	{
		block[i] = READ_SBOX_BYTE(aes_invsbox[block[i]]);
	}
}


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i;

	
	aes_dec_firstround(block, roundKeys + 16 * 10);

	for (i = 9; i > 0; --i)
	{
		aes_dec_round(block, roundKeys + 16 * i);
	}
	
	for (i = 0; i < 16; ++i)
	{
		block[i] ^= READ_ROUND_KEY_BYTE(roundKeys[i]);
	}
}
