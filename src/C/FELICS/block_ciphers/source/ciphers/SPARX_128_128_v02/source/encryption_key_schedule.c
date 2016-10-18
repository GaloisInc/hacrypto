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

#include "speckey.h"


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint8_t i;
    uint16_t temp[2];

    uint16_t *Key = (uint16_t *)key;
    uint16_t *RoundKeys = (uint16_t *)roundKeys;


    RoundKeys[0] = Key[0];
    RoundKeys[1] = Key[1];

    RoundKeys[2] = Key[2];
    RoundKeys[3] = Key[3];

    RoundKeys[4] = Key[4];
    RoundKeys[5] = Key[5];

    RoundKeys[6] = Key[6];
    RoundKeys[7] = Key[7];


    for(i = 1; i < 4 * NUMBER_OF_ROUNDS + 1; i++)
    {
        temp[0] = RoundKeys[8 * (i - 1) + 4];
        temp[1] = RoundKeys[8 * (i - 1) + 5];
        speckey(temp, temp + 1);
        RoundKeys[8 * i  + 6] = temp[0];
        RoundKeys[8 * i  + 7] = temp[1];

        RoundKeys[8 * i + 0] = temp[0] + RoundKeys[8 * (i - 1) + 6];
        RoundKeys[8 * i + 1] = temp[1] + RoundKeys[8 * (i - 1) + 7] + i;


        temp[0] = RoundKeys[8 * (i - 1) + 0];
        temp[1] = RoundKeys[8 * (i - 1) + 1];
        speckey(temp, temp + 1);
        RoundKeys[8 * i + 2] = temp[0];
        RoundKeys[8 * i + 3] = temp[1];

        RoundKeys[8 * i + 4] = temp[0] + RoundKeys[8 * (i - 1) + 2]; 
        RoundKeys[8 * i + 5] = temp[1] + RoundKeys[8 * (i - 1) + 3];
    }
}
