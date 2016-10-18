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

/* key is {0x2bd6459f, 0x82c5b300, 0x952c4910, 0x4881ff48} (in C format) */
const uint8_t expectedKey[KEY_SIZE] =
{
	0x9f, 0x45, 0xd6, 0x2b,
	0x00, 0xb3, 0xc5, 0x82,
	0x10, 0x49, 0x2c, 0x95,
	0x48, 0xff, 0x81, 0x48
};

/* IV is {0xea024714, 0xad5c4d84, 0xdf1f9b25, 0x1c0bf45f} (in C format) */
const uint8_t expectedIV[IV_SIZE] =
{
	0x14, 0x47, 0x02, 0xea,
	0x84, 0x4d, 0x5c, 0xad,
	0x25, 0x9b, 0x1f, 0xdf,
	0x5f, 0xf4, 0x0b, 0x1c
};

/* plaintext is 0x00...000 (i.e keystream mode) */
const uint8_t expectedPlaintext[TEST_STREAM_SIZE] =
{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

/* ciphertext is {0xabee9704, 0x7ac31373} (in C format) */
const uint8_t expectedCiphertext[TEST_STREAM_SIZE] =
{
	/* 0xabee9704 */
	0x04, 0x97, 0xee, 0xab,
	0x73, 0x13, 0xc3, 0x7a
};
