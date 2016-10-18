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


void round_f(uint16_t *block, uint16_t *roundKeys)
{
    uint16_t temp;


    /* left branch */
    *block ^= READ_ROUND_KEY_WORD(roundKeys[0]);
    *(block + 1) ^= READ_ROUND_KEY_WORD(roundKeys[1]);
    speckey(block, block + 1);

    *block ^= READ_ROUND_KEY_WORD(roundKeys[2]);
    *(block + 1) ^= READ_ROUND_KEY_WORD(roundKeys[3]);
    speckey(block, block + 1);

    *block ^= READ_ROUND_KEY_WORD(roundKeys[4]);
    *(block + 1) ^= READ_ROUND_KEY_WORD(roundKeys[5]);
    speckey(block, block + 1);


    /* right branch */
    *(block + 2) ^= READ_ROUND_KEY_WORD(roundKeys[6]);
    *(block + 3) ^= READ_ROUND_KEY_WORD(roundKeys[7]);
    speckey(block + 2, block + 3);

    *(block + 2) ^= READ_ROUND_KEY_WORD(roundKeys[8]);
    *(block + 3) ^= READ_ROUND_KEY_WORD(roundKeys[9]);
    speckey(block + 2, block + 3);

    *(block + 2) ^= READ_ROUND_KEY_WORD(roundKeys[10]);
    *(block + 3) ^= READ_ROUND_KEY_WORD(roundKeys[11]);
    speckey(block + 2, block + 3);


    /* linear layer */
    temp = *block ^ *(block + 1);
    temp = rot16l8(temp);
    *(block + 2) ^= *block ^ temp;
    *(block + 3) ^= *(block + 1) ^ temp;

    temp = *block;
    *block = *(block + 2);
    *(block + 2) = temp;

    temp = *(block + 1);
    *(block + 1) = *(block + 3);
    *(block + 3) = temp;
}
