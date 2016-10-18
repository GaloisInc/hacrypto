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

#include "cipher.h"
#include "constants.h"
#include "primitives.h"

/*
 * In Piccolo, we need "whitening" keys in addition to roundKeys. We choose
 * to consider them as "additional" roundKeys that are stored on top of
 * actual roundKeys (i.e. roundKeys[50:53])
 */
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
        uint8_t i;
        uint16_t *x3 = (uint16_t *)block;
        uint16_t *x2 = x3 + 1;
        uint16_t *x1 = x3 + 2;
        uint16_t *x0 = x3 + 3;
        uint16_t *rk = (uint16_t *)roundKeys;

        *x2 ^= READ_ROUND_KEY_WORD(rk[53]);
        *x0 ^= READ_ROUND_KEY_WORD(rk[52]);
        for (i = 0; i < NUMBER_OF_ROUNDS - 1; ++i)
        {
                if ((i & 0x01) == 0)
                {
                        *x1 = *x1 ^ F(*x0) ^ READ_ROUND_KEY_WORD(rk[2*NUMBER_OF_ROUNDS - 2*i - 2]);
                        *x3 = *x3 ^ F(*x2) ^ READ_ROUND_KEY_WORD(rk[2*NUMBER_OF_ROUNDS - 2*i - 1]);
                }
                else
                {
                        *x1 = *x1 ^ F(*x0) ^ READ_ROUND_KEY_WORD(rk[2*NUMBER_OF_ROUNDS - 2*i - 1]);
                        *x3 = *x3 ^ F(*x2) ^ READ_ROUND_KEY_WORD(rk[2*NUMBER_OF_ROUNDS - 2*i - 2]);
                }
                RP(x0, x1, x2, x3);
        }
        *x1 = *x1 ^ F(*x0) ^ READ_ROUND_KEY_WORD(rk[0]);
        *x3 = *x3 ^ F(*x2) ^ READ_ROUND_KEY_WORD(rk[1]);
        *x0 ^= READ_ROUND_KEY_WORD(rk[50]);
        *x2 ^= READ_ROUND_KEY_WORD(rk[51]);
}
