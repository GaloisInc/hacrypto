/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 University of Luxembourg
 *
 * Written in 2016 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#include "update.h"


void Encrypt(uint8_t *state, uint8_t *stream, uint16_t length)
{
	uint16_t i;

	uint8_t keyStream[STATE_SIZE];


	for (i = 0; i < length / STATE_SIZE; i++)
	{
		Update(state, keyStream);

		stream[i * STATE_SIZE + 0] ^= keyStream[0];
		stream[i * STATE_SIZE + 1] ^= keyStream[1];
		stream[i * STATE_SIZE + 2] ^= keyStream[2];
		stream[i * STATE_SIZE + 3] ^= keyStream[3];
		stream[i * STATE_SIZE + 4] ^= keyStream[4];
		stream[i * STATE_SIZE + 5] ^= keyStream[5];
		stream[i * STATE_SIZE + 6] ^= keyStream[6];
		stream[i * STATE_SIZE + 7] ^= keyStream[7];

		stream[i * STATE_SIZE + 8] ^= keyStream[8];
		stream[i * STATE_SIZE + 9] ^= keyStream[9];
		stream[i * STATE_SIZE + 10] ^= keyStream[10];
		stream[i * STATE_SIZE + 11] ^= keyStream[11];
		stream[i * STATE_SIZE + 12] ^= keyStream[12];
		stream[i * STATE_SIZE + 13] ^= keyStream[13];
		stream[i * STATE_SIZE + 14] ^= keyStream[14];
		stream[i * STATE_SIZE + 15] ^= keyStream[15];

		stream[i * STATE_SIZE + 16] ^= keyStream[16];
		stream[i * STATE_SIZE + 17] ^= keyStream[17];
		stream[i * STATE_SIZE + 18] ^= keyStream[18];
		stream[i * STATE_SIZE + 19] ^= keyStream[19];
		stream[i * STATE_SIZE + 20] ^= keyStream[20];
		stream[i * STATE_SIZE + 21] ^= keyStream[21];
		stream[i * STATE_SIZE + 22] ^= keyStream[22];
		stream[i * STATE_SIZE + 23] ^= keyStream[23];

		stream[i * STATE_SIZE + 24] ^= keyStream[24];
		stream[i * STATE_SIZE + 25] ^= keyStream[25];
		stream[i * STATE_SIZE + 26] ^= keyStream[26];
		stream[i * STATE_SIZE + 27] ^= keyStream[27];
		stream[i * STATE_SIZE + 28] ^= keyStream[28];
		stream[i * STATE_SIZE + 29] ^= keyStream[29];
		stream[i * STATE_SIZE + 30] ^= keyStream[30];
		stream[i * STATE_SIZE + 31] ^= keyStream[31];

		stream[i * STATE_SIZE + 32] ^= keyStream[32];
		stream[i * STATE_SIZE + 33] ^= keyStream[33];
		stream[i * STATE_SIZE + 34] ^= keyStream[34];
		stream[i * STATE_SIZE + 35] ^= keyStream[35];
		stream[i * STATE_SIZE + 36] ^= keyStream[36];
		stream[i * STATE_SIZE + 37] ^= keyStream[37];
		stream[i * STATE_SIZE + 38] ^= keyStream[38];
		stream[i * STATE_SIZE + 39] ^= keyStream[39];


		stream[i * STATE_SIZE + 40] ^= keyStream[40];
		stream[i * STATE_SIZE + 41] ^= keyStream[41];
		stream[i * STATE_SIZE + 42] ^= keyStream[42];
		stream[i * STATE_SIZE + 43] ^= keyStream[43];
		stream[i * STATE_SIZE + 44] ^= keyStream[44];
		stream[i * STATE_SIZE + 45] ^= keyStream[45];
		stream[i * STATE_SIZE + 46] ^= keyStream[46];
		stream[i * STATE_SIZE + 47] ^= keyStream[47];

		stream[i * STATE_SIZE + 48] ^= keyStream[48];
		stream[i * STATE_SIZE + 49] ^= keyStream[49];
		stream[i * STATE_SIZE + 50] ^= keyStream[50];
		stream[i * STATE_SIZE + 51] ^= keyStream[51];
		stream[i * STATE_SIZE + 52] ^= keyStream[52];
		stream[i * STATE_SIZE + 53] ^= keyStream[53];
		stream[i * STATE_SIZE + 54] ^= keyStream[54];
		stream[i * STATE_SIZE + 55] ^= keyStream[55];

		stream[i * STATE_SIZE + 56] ^= keyStream[56];
		stream[i * STATE_SIZE + 57] ^= keyStream[57];
		stream[i * STATE_SIZE + 58] ^= keyStream[58];
		stream[i * STATE_SIZE + 59] ^= keyStream[59];
		stream[i * STATE_SIZE + 60] ^= keyStream[60];
		stream[i * STATE_SIZE + 61] ^= keyStream[61];
		stream[i * STATE_SIZE + 62] ^= keyStream[62];
		stream[i * STATE_SIZE + 63] ^= keyStream[63];
	}
}
