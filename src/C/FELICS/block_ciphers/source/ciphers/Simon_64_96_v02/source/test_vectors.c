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

#include "test_vectors.h"

/*
 *
 * Test vectors
 *
 */
const uint8_t expectedPlaintext[BLOCK_SIZE] =
{
	/* plaintext (64-bit format) is 0x6f7220676e696c63 */
	0x63, 0x6c, 0x69, 0x6e,
	0x67, 0x20, 0x72, 0x6f
};

const uint8_t expectedKey[KEY_SIZE] =
{
	
	/* keys are (32-bit format, as in specification): 0x03020100, 0x0b0a0908, 0x13121110 */
	0x00, 0x01, 0x02, 0x03,
	0x08, 0x09, 0x0a, 0x0b,
	0x10, 0x11, 0x12, 0x13
};

const uint8_t expectedCiphertext[BLOCK_SIZE] =
{
	/* plaintext (64-bit format) is 0x5ca2e27f111a8fc8 */
	0xc8, 0x8f, 0x1a, 0x11,
	0x7f, 0xe2, 0xa2, 0x5c
};
