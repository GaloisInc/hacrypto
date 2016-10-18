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

#include "cipher.h"
#include "constants.h"

#include "round_inverse.h"


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    int8_t i;

    uint16_t *left = (uint16_t *)block;
    uint16_t *right = (uint16_t *)block + 2;
    uint16_t *RoundKeys = (uint16_t *)roundKeys;


    /* post whitening */
    *left ^= READ_ROUND_KEY_WORD(RoundKeys[12 * NUMBER_OF_ROUNDS]);
    *(left + 1) ^= READ_ROUND_KEY_WORD(RoundKeys[12 * NUMBER_OF_ROUNDS + 1]);
    *right ^= READ_ROUND_KEY_WORD(RoundKeys[12 * NUMBER_OF_ROUNDS + 2]);
    *(right + 1) ^= READ_ROUND_KEY_WORD(RoundKeys[12 * NUMBER_OF_ROUNDS + 3]);


    for (i = NUMBER_OF_ROUNDS - 1; i >= 0 ; i--)
    {
        round_f_inverse(left, right, &RoundKeys[12 * i]);
    }
}
