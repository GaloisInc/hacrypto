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
    /* p = 0x74614620736e6165 */
    0x65, 0x61, 0x6e, 0x73,
    0x20, 0x46, 0x61, 0x74
};

const uint8_t expectedKey[KEY_SIZE] =
{
    /* key = 0x03020100, 0x0b0a0908, 0x13121110 */
    0x00, 0x01, 0x02, 0x03,
    0x08, 0x09, 0x0a, 0x0b,
    0x10, 0x11, 0x12, 0x13
};

const uint8_t expectedCiphertext[BLOCK_SIZE] =
{
    /* c = 0x9f7952ec4175946c */
    0x6c, 0x94, 0x75, 0x41,
    0xec, 0x52, 0x79, 0x9f
};
