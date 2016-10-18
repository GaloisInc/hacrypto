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

#include "round_inverse.h"
#include "cipher.h"
#include "rot32.h"
#include "speckey_inverse.h"


void round_f_inverse(uint32_t *left, uint32_t *right, uint32_t *roundKeys)
{
    uint32_t temp;

    uint16_t *b0_l = (uint16_t *)left;
    uint16_t *b0_r = (uint16_t *)left + 1;

    uint16_t *b1_l = (uint16_t *)right;
    uint16_t *b1_r = (uint16_t *)right + 1;


    /* linear layer */
    temp = *right;
    *left ^= *right ^ rot32l8(*right) ^ rot32r8(*right);
    *right = *left;
    *left = temp;


    /* right branch */
    speckey_inverse(b1_l, b1_r);
    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[5]);

    speckey_inverse(b1_l, b1_r);
    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[4]);

    speckey_inverse(b1_l, b1_r);
    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[3]);


    /* left branch */
    speckey_inverse(b0_l, b0_r);
    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[2]);

    speckey_inverse(b0_l, b0_r);
    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[1]);

    speckey_inverse(b0_l, b0_r);
    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[0]);
}
