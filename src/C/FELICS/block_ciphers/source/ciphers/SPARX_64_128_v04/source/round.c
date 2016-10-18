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

#include "round.h"
#include "cipher.h"
#include "rot32.h"
#include "speckey.h"


void round_f(uint32_t *left, uint32_t *right, uint32_t *roundKeys)
{
    uint16_t *b0_l = (uint16_t *)left;
    uint16_t *b0_r = (uint16_t *)left + 1;

    uint16_t *b1_l = (uint16_t *)right;
    uint16_t *b1_r = (uint16_t *)right + 1;


    /* First round - begin */
    /* left branch */
    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[0]);
    speckey(b0_l, b0_r);

    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[1]);
    speckey(b0_l, b0_r);

    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[2]);
    speckey(b0_l, b0_r);


    /* right branch */
    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[3]);
    speckey(b1_l, b1_r);

    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[4]);
    speckey(b1_l, b1_r);

    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[5]);
    speckey(b1_l, b1_r);


    /* linear layer */
    *right ^= *left ^ rot32l8(*left) ^ rot32r8(*left);
    /* First round - end */


    /* Second round - begin */
    /* left branch */
    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[6]);
    speckey(b1_l, b1_r);

    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[7]);
    speckey(b1_l, b1_r);

    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[8]);
    speckey(b1_l, b1_r);


    /* right branch */
    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[9]);
    speckey(b0_l, b0_r);

    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[10]);
    speckey(b0_l, b0_r);

    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[11]);
    speckey(b0_l, b0_r);


    /* linear layer */
    *left ^= *right ^ rot32l8(*right) ^ rot32r8(*right);
    /* Second round - end */
}
