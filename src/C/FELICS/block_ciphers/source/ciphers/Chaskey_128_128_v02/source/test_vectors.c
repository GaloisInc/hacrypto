/*
 *
 * Katholieke Universiteit Leuven
 * Computer Security and Industrial Cryptography (COSIC)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 Katholieke Universiteit Leuven
 *
 * Written in 2015 by Nicky Mouha <nicky.mouha@esat.kuleuven.be>
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
const uint8_t expectedPlaintext[BLOCK_SIZE] =
{
    0xb8, 0x23, 0x28, 0x26,
    0xfd, 0x5e, 0x40, 0x5e,
    0x69, 0xa3, 0x01, 0xa9,
    0x78, 0xea, 0x7a, 0xd8
};

const uint8_t expectedKey[KEY_SIZE] =
{
    0x56, 0x09, 0xe9, 0x68,
    0x5f, 0x58, 0xe3, 0x29,
    0x40, 0xec, 0xec, 0x98,
    0xc5, 0x22, 0x98, 0x2f
};

const uint8_t expectedCiphertext[BLOCK_SIZE] =
{
    0x6d, 0x52, 0x0e, 0x94,
    0xc4, 0xff, 0x0f, 0x80,
    0x7c, 0x77, 0xf8, 0x24,
    0x9d, 0x79, 0xa3, 0x87
};
