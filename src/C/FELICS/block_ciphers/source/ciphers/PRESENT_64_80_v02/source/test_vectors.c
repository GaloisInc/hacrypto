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

#include "test_vectors.h"


/*
 *
 * Test vectors
 *
 */
//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedKey[KEY_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x45, 0x84, 0x22, 0x7b, 0x38, 0xc1, 0x79, 0x55};

const uint8_t expectedPlaintext[BLOCK_SIZE] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t expectedKey[KEY_SIZE] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t expectedCiphertext[BLOCK_SIZE] = {0xd2, 0x10, 0x32, 0x21, 0xd3, 0xdc, 0x33, 0x33};
