/*
 *
 * Kocaeli University Computer Engineering
 * TÜBİTAK BİLGEM, Turkey
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 Kocaeli University
 *
 * Written in 2015 by Adnan Baysal <adnan.baysal@tubitak.gov.tr>
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
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

const uint8_t expectedPlaintext[BLOCK_SIZE] = {0};
const uint8_t expectedKey[KEY_SIZE] = {0};
const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x82,0xb4,0x10,0x9f,0xcc,0x70,0xbd,0x1f};

//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
//const uint8_t expectedKey[KEY_SIZE] = {0};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0xd7,0x0e,0x60,0x68,0x0a,0x17,0xb9,0x56};

//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0};
//const uint8_t expectedKey[KEY_SIZE] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x28,0xf1,0x9f,0x97,0xf5,0xe8,0x46,0xa9};

//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0};
//const uint8_t expectedKey[KEY_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0xd1,0x23,0xeb,0xaf,0x36,0x8f,0xce,0x62};

//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
//const uint8_t expectedKey[KEY_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0xd1,0x37,0x29,0x29,0x71,0x2d,0x33,0x6e};

