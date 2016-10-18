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
#include "rot16.h"
#include "speckey_inverse.h"


void round_f_inverse(uint16_t *block, uint16_t *roundKeys)
{
    uint16_t temp;


    /* linear layer */
    temp = *(block + 2) ^ *(block + 3);
    temp = rot16l8(temp);
    *block ^= *(block + 2) ^ temp;
    *(block + 1) ^= *(block + 3) ^ temp;

    temp = *block;
    *block = *(block + 2);
    *(block + 2) = temp;

    temp = *(block + 1);
    *(block + 1) = *(block + 3);
    *(block + 3) = temp;


    /* right branch */
    speckey_inverse(block + 2, block + 3);
    *(block + 3) ^= READ_ROUND_KEY_WORD(roundKeys[11]);
    *(block + 2) ^= READ_ROUND_KEY_WORD(roundKeys[10]);

    speckey_inverse(block + 2, block + 3);
    *(block + 3) ^= READ_ROUND_KEY_WORD(roundKeys[9]);
    *(block + 2) ^= READ_ROUND_KEY_WORD(roundKeys[8]);

    speckey_inverse(block + 2, block + 3);
    *(block + 3) ^= READ_ROUND_KEY_WORD(roundKeys[7]);
    *(block + 2) ^= READ_ROUND_KEY_WORD(roundKeys[6]);


    /* left branch */
    speckey_inverse(block, block + 1);
    *(block + 1) ^= READ_ROUND_KEY_WORD(roundKeys[5]);
    *block ^= READ_ROUND_KEY_WORD(roundKeys[4]);

    speckey_inverse(block, block + 1);
    *(block + 1) ^= READ_ROUND_KEY_WORD(roundKeys[3]);
    *block ^= READ_ROUND_KEY_WORD(roundKeys[2]);
    
    speckey_inverse(block, block + 1);
    *(block + 1) ^= READ_ROUND_KEY_WORD(roundKeys[1]);
    *block ^= READ_ROUND_KEY_WORD(roundKeys[0]);
}
