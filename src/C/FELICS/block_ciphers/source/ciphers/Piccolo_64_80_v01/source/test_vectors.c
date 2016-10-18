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
        /* p = 0x0123456789abcdef */
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
};

const uint8_t expectedKey[KEY_SIZE] =
{
        /* k = 0x0011, 0x2233, 0x4455, 0x6677, 0x8899 */
        0x11, 0x00,
        0x33, 0x22,
        0x55, 0x44,
        0x77, 0x66,
        0x99, 0x88
};

const uint8_t expectedCiphertext[BLOCK_SIZE] =
{
        /* c = 0x8d2bff9935f84056 */
        0x56, 0x40, 0xf8, 0x35,
        0x99, 0xff, 0x2b, 0x8d
};
