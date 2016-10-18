/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu>,
 *                    Jason Smith <jksmit3@tycho.ncsc.mil>
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
	/* plaintext (64-bit format) is 0x656b696c20646e75 */
	0x75, 0x6e, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65
};

const uint8_t expectedKey[KEY_SIZE] =
{
	/* keys are (32-bit format, as in specification): 0x03020100,  0x0b0a0908, 0x13121110, 0x1b1a1918 */
	0x00, 0x01, 0x02, 0x03,
	0x08, 0x09, 0x0a, 0x0b,
	0x10, 0x11, 0x12, 0x13,
	0x18, 0x19, 0x1a, 0x1b
};

const uint8_t expectedCiphertext[BLOCK_SIZE] =
{
	/* ciphertext (64-bit format) is 0x44c8fc20b9dfa07a */
	0x7a, 0xa0, 0xdf, 0xb9,
	0x20, 0xfc, 0xc8, 0x44
};
