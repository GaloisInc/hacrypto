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

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint8_t i;
    uint8_t m;
	uint16_t *mk = (uint16_t *)key;
    uint32_t _rk;
	uint16_t *rk = (uint16_t *)roundKeys;
	uint16_t *wk = (uint16_t *)(&roundKeys[100]);

    wk[0] = (mk[0] & 0xff00) | (mk[1] & 0x00ff);
    wk[1] = (mk[1] & 0xff00) | (mk[0] & 0x00ff);
    wk[2] = (mk[4] & 0xff00) | (mk[3] & 0x00ff);
    wk[3] = (mk[3] & 0xff00) | (mk[4] & 0x00ff);

    m = 0;
    for (i = 0; i < NUMBER_OF_ROUNDS; ++i)
    {
        _rk = READ_CON80_DOUBLE_WORD(CON80[i]);
        switch (m)
        {
            case 0:
            case 2:
                _rk ^= *(uint32_t *)(&mk[2]);
                break;
            case 3:
                _rk ^= ((uint32_t)(mk[4]) << 16) | (uint32_t)(mk[4]);
                break;
            case 1:
            case 4:
                _rk ^= *(uint32_t *)(&mk[0]);
                break;
        }
        *(uint32_t *)&rk[2*i] = _rk;
        if (m == 4)
        {
            m = 0;
        }
        else
        {
            m++;
        }
    }
}
