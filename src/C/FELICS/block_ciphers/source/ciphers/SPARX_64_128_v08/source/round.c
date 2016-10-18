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
#include "rot16.h"
#include "speckey.h"


void round_f(uint16_t *left, uint16_t *right, uint16_t *roundKeys)
{
    uint16_t temp;


    /* left branch */
    *left ^= READ_ROUND_KEY_WORD(roundKeys[0]);
    *(left + 1) ^= READ_ROUND_KEY_WORD(roundKeys[1]);
    speckey(left, left + 1);

    *left ^= READ_ROUND_KEY_WORD(roundKeys[2]);
    *(left + 1) ^= READ_ROUND_KEY_WORD(roundKeys[3]);
    speckey(left, left + 1);

    *left ^= READ_ROUND_KEY_WORD(roundKeys[4]);
    *(left + 1) ^= READ_ROUND_KEY_WORD(roundKeys[5]);
    speckey(left, left + 1);


    /* right branch */
    *right ^= READ_ROUND_KEY_WORD(roundKeys[6]);
    *(right + 1) ^= READ_ROUND_KEY_WORD(roundKeys[7]);
    speckey(right, right + 1);

    *right ^= READ_ROUND_KEY_WORD(roundKeys[8]);
    *(right + 1) ^= READ_ROUND_KEY_WORD(roundKeys[9]);
    speckey(right, right + 1);

    *right ^= READ_ROUND_KEY_WORD(roundKeys[10]);
    *(right + 1) ^= READ_ROUND_KEY_WORD(roundKeys[11]);
    speckey(right, right + 1);


    /* linear layer */
    temp = *left ^ *(left + 1);
    temp = rot16l8(temp);
    *right ^= *left ^ temp;
    *(right + 1) ^= *(left + 1) ^ temp;

    temp = *left;
    *left = *right;
    *right = temp;

    temp = *(left + 1);
    *(left + 1) = *(right + 1);
    *(right + 1) = temp;
}
