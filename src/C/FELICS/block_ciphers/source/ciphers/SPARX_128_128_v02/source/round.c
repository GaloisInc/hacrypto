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
#include "rot32.h"
#include "speckey.h"


void round_f(uint16_t *block, uint16_t *roundKeys)
{
    uint16_t temp;


    /* first branch */
    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[0]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[1]);
    speckey(&block[0], &block[1]);

    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[2]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[3]);
    speckey(&block[0], &block[1]);

    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[4]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[5]);
    speckey(&block[0], &block[1]);

    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[6]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[7]);
    speckey(&block[0], &block[1]);


    /* second branch */
    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[8]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[9]);
    speckey(&block[2], &block[3]);

    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[10]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[11]);
    speckey(&block[2], &block[3]);

    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[12]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[13]);
    speckey(&block[2], &block[3]);

    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[14]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[15]);
    speckey(&block[2], &block[3]);


    /* third branch */
    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[16]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[17]);
    speckey(&block[4], &block[5]);

    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[18]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[19]);
    speckey(&block[4], &block[5]);

    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[20]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[21]);
    speckey(&block[4], &block[5]);

    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[22]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[23]);
    speckey(&block[4], &block[5]);


    /* fourth branch */
    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[24]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[25]);
    speckey(&block[6], &block[7]);

    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[26]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[27]);
    speckey(&block[6], &block[7]);

    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[28]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[29]);
    speckey(&block[6], &block[7]);

    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[30]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[31]);
    speckey(&block[6], &block[7]);


    /* linear layer */
    /*uint16_t t[4];
    t[0] = block[0];
    t[1] = block[1];
    t[2] = block[2];
    t[3] = block[3];

    temp = block[0] ^ block[1] ^ block[2] ^ block[3];
    temp = rot16l8(temp);

    block[0] ^= temp;
    block[1] ^= temp;
    block[2] ^= temp;
    block[3] ^= temp;

    block[0] ^= block[6];
    block[1] ^= block[5];
    block[2] ^= block[4];
    block[3] ^= block[7];

    temp = block[0];
    block[0] = block[2];
    block[2] = temp;

    block[4] = t[0];
    block[5] = t[1];
    block[6] = t[2];
    block[7] = t[3];*/


    /*temp = block[0] ^ block[1] ^ block[2] ^ block[3];
    temp = rot16l8(temp);

    block[4] ^= block[2] ^ temp;
    block[5] ^= block[1] ^ temp;
    block[6] ^= block[0] ^ temp;
    block[7] ^= block[3] ^ temp;

    temp = block[0];
    block[0] = block[4];
    block[4] = temp;

    temp = block[1];
    block[1] = block[5];
    block[5] = temp;

    temp = block[2];
    block[2] = block[6];
    block[6] = temp;

    temp = block[3];
    block[3] = block[7];
    block[7] = temp;*/


    uint32_t *Block = (uint32_t *)block;
    uint32_t t = Block[0] ^ Block[1];
    uint32_t tx[2];

    tx[0] = Block[0];
    tx[1] = Block[1];

    t = rot32l8(t) ^ rot32r8(t);
    Block[0] ^= t;
    Block[1] ^= t;

    t = Block[0];
    Block[0] = (Block[0] & 0xffff0000) | (Block[1] & 0x0000ffff);
    Block[1] = (Block[1] & 0xffff0000) | (t & 0x0000ffff);

    Block[0] ^= Block[2];
    Block[1] ^= Block[3];

    Block[2] = tx[0];
    Block[3] = tx[1];
}
