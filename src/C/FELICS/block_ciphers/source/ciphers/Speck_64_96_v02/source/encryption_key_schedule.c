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

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint8_t i;
    uint32_t *rk = (uint32_t *)roundKeys;
    uint32_t *mk = (uint32_t *)key;
    uint32_t lp2;
    uint32_t lp1;
    uint32_t lp0;

    rk[0] = mk[0];
    for (i = 0; i < NUMBER_OF_ROUNDS - 1; ++i)
    {
        if (i == 0)
        {
            lp0 = mk[1];
            lp1 = mk[2];
        }
        else
        {
            lp0 = lp1;
            lp1 = lp2;
        }
        lp2 = (rorAlpha(lp0) + rk[i]) ^ i;
        rk[i + 1] = rolBeta(rk[i]) ^ lp2;
    }
}
