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

    temp[0] = Key[6];
    temp[1] = Key[7];


    /* c = 1 */
    RoundKeys[6] = temp[0];
    RoundKeys[7] = temp[1] + 1;

    temp[0] = RoundKeys[0];
    temp[1] = RoundKeys[1];
    speckey(temp, temp + 1);

    RoundKeys[8] = temp[0];
    RoundKeys[9] = temp[1];

    RoundKeys[10] = temp[0] + RoundKeys[2]; 
    RoundKeys[11] = temp[1] + RoundKeys[3];

    temp[0] = RoundKeys[4];
    temp[1] = RoundKeys[5];


    /* c = 2 */
    RoundKeys[12] = temp[0];
    RoundKeys[13] = temp[1] + 2;

    temp[0] = RoundKeys[6];
    temp[1] = RoundKeys[7];
    speckey(temp, temp + 1);

    RoundKeys[14] = temp[0];
    RoundKeys[15] = temp[1];

    RoundKeys[16] = temp[0] + RoundKeys[8]; 
    RoundKeys[17] = temp[1] + RoundKeys[9];

    temp[0] = RoundKeys[10];
    temp[1] = RoundKeys[11];


   /* c = 3 */
    RoundKeys[18] = temp[0];
    RoundKeys[19] = temp[1] + 3;

    temp[0] = RoundKeys[12];
    temp[1] = RoundKeys[13];
    speckey(temp, temp + 1);

    RoundKeys[20] = temp[0];
    RoundKeys[21] = temp[1];

    RoundKeys[22] = temp[0] + RoundKeys[14]; 
    RoundKeys[23] = temp[1] + RoundKeys[15];

    temp[0] = RoundKeys[16];
    temp[1] = RoundKeys[17];


    /* c = 4 */
    RoundKeys[24] = temp[0];
    RoundKeys[25] = temp[1] + 4;

    temp[0] = RoundKeys[18];
    temp[1] = RoundKeys[19];
    speckey(temp, temp + 1);

    RoundKeys[26] = temp[0];
    RoundKeys[27] = temp[1];

    RoundKeys[28] = temp[0] + RoundKeys[20]; 
    RoundKeys[29] = temp[1] + RoundKeys[21];

    temp[0] = RoundKeys[22];
    temp[1] = RoundKeys[23];


    /* c = 5 */
    RoundKeys[30] = temp[0];
    RoundKeys[31] = temp[1] + 5;

    temp[0] = RoundKeys[24];
    temp[1] = RoundKeys[25];
    speckey(temp, temp + 1);

    RoundKeys[32] = temp[0];
    RoundKeys[33] = temp[1];

    RoundKeys[34] = temp[0] + RoundKeys[26]; 
    RoundKeys[35] = temp[1] + RoundKeys[27];

    temp[0] = RoundKeys[28];
    temp[1] = RoundKeys[29];


    /* c = 6 */
    RoundKeys[36] = temp[0];
    RoundKeys[37] = temp[1] + 6;

    temp[0] = RoundKeys[30];
    temp[1] = RoundKeys[31];
    speckey(temp, temp + 1);

    RoundKeys[38] = temp[0];
    RoundKeys[39] = temp[1];

    RoundKeys[40] = temp[0] + RoundKeys[32]; 
    RoundKeys[41] = temp[1] + RoundKeys[33];

    temp[0] = RoundKeys[34];
    temp[1] = RoundKeys[35];


    /* c = 7 */
    RoundKeys[42] = temp[0];
    RoundKeys[43] = temp[1] + 7;

    temp[0] = RoundKeys[36];
    temp[1] = RoundKeys[37];
    speckey(temp, temp + 1);

    RoundKeys[44] = temp[0];
    RoundKeys[45] = temp[1];

    RoundKeys[46] = temp[0] + RoundKeys[38]; 
    RoundKeys[47] = temp[1] + RoundKeys[39];

    temp[0] = RoundKeys[40];
    temp[1] = RoundKeys[41];


    /* c = 8 */
    RoundKeys[48] = temp[0];
    RoundKeys[49] = temp[1] + 8;

    temp[0] = RoundKeys[42];
    temp[1] = RoundKeys[43];
    speckey(temp, temp + 1);

    RoundKeys[50] = temp[0];
    RoundKeys[51] = temp[1];

    RoundKeys[52] = temp[0] + RoundKeys[44]; 
    RoundKeys[53] = temp[1] + RoundKeys[45];

    temp[0] = RoundKeys[46];
    temp[1] = RoundKeys[47];


    /* c = 9 */
    RoundKeys[54] = temp[0];
    RoundKeys[55] = temp[1] + 9;

    temp[0] = RoundKeys[48];
    temp[1] = RoundKeys[49];
    speckey(temp, temp + 1);

    RoundKeys[56] = temp[0];
    RoundKeys[57] = temp[1];

    RoundKeys[58] = temp[0] + RoundKeys[50]; 
    RoundKeys[59] = temp[1] + RoundKeys[51];

    temp[0] = RoundKeys[52];
    temp[1] = RoundKeys[53];


    /* c = 10 */
    RoundKeys[60] = temp[0];
    RoundKeys[61] = temp[1] + 10;

    temp[0] = RoundKeys[54];
    temp[1] = RoundKeys[55];
    speckey(temp, temp + 1);

    RoundKeys[62] = temp[0];
    RoundKeys[63] = temp[1];

    RoundKeys[64] = temp[0] + RoundKeys[56]; 
    RoundKeys[65] = temp[1] + RoundKeys[57];

    temp[0] = RoundKeys[58];
    temp[1] = RoundKeys[59];


    /* c = 11 */
    RoundKeys[66] = temp[0];
    RoundKeys[67] = temp[1] + 11;

    temp[0] = RoundKeys[60];
    temp[1] = RoundKeys[61];
    speckey(temp, temp + 1);

    RoundKeys[68] = temp[0];
    RoundKeys[69] = temp[1];

    RoundKeys[70] = temp[0] + RoundKeys[62]; 
    RoundKeys[71] = temp[1] + RoundKeys[63];

    temp[0] = RoundKeys[64];
    temp[1] = RoundKeys[65];


    /* c = 12 */
    RoundKeys[72] = temp[0];
    RoundKeys[73] = temp[1] + 12;

    temp[0] = RoundKeys[66];
    temp[1] = RoundKeys[67];
    speckey(temp, temp + 1);

    RoundKeys[74] = temp[0];
    RoundKeys[75] = temp[1];

    RoundKeys[76] = temp[0] + RoundKeys[68]; 
    RoundKeys[77] = temp[1] + RoundKeys[69];

    temp[0] = RoundKeys[70];
    temp[1] = RoundKeys[71];


    /* c = 13 */
    RoundKeys[78] = temp[0];
    RoundKeys[79] = temp[1] + 13;

    temp[0] = RoundKeys[72];
    temp[1] = RoundKeys[73];
    speckey(temp, temp + 1);

    RoundKeys[80] = temp[0];
    RoundKeys[81] = temp[1];

    RoundKeys[82] = temp[0] + RoundKeys[74]; 
    RoundKeys[83] = temp[1] + RoundKeys[75];

    temp[0] = RoundKeys[76];
    temp[1] = RoundKeys[77];


    /* c = 14 */
    RoundKeys[84] = temp[0];
    RoundKeys[85] = temp[1] + 14;

    temp[0] = RoundKeys[78];
    temp[1] = RoundKeys[79];
    speckey(temp, temp + 1);

    RoundKeys[86] = temp[0];
    RoundKeys[87] = temp[1];

    RoundKeys[88] = temp[0] + RoundKeys[80]; 
    RoundKeys[89] = temp[1] + RoundKeys[81];

    temp[0] = RoundKeys[82];
    temp[1] = RoundKeys[83];


    /* c = 15 */
    RoundKeys[90] = temp[0];
    RoundKeys[91] = temp[1] + 15;

    temp[0] = RoundKeys[84];
    temp[1] = RoundKeys[85];
    speckey(temp, temp + 1);

    RoundKeys[92] = temp[0];
    RoundKeys[93] = temp[1];

    RoundKeys[94] = temp[0] + RoundKeys[86]; 
    RoundKeys[95] = temp[1] + RoundKeys[87];

    temp[0] = RoundKeys[88];
    temp[1] = RoundKeys[89];


    RoundKeys[6 * 2 * NUMBER_OF_ROUNDS + 0] = temp[0];
    RoundKeys[6 * 2 * NUMBER_OF_ROUNDS + 1] = temp[1] + 2 * NUMBER_OF_ROUNDS;

    temp[0] = RoundKeys[6 * (2 * NUMBER_OF_ROUNDS - 1) + 0];
    temp[1] = RoundKeys[6 * (2 * NUMBER_OF_ROUNDS - 1) + 1];
    speckey(temp, temp + 1);

    RoundKeys[6 * 2 * NUMBER_OF_ROUNDS + 2] = temp[0];
    RoundKeys[6 * 2 * NUMBER_OF_ROUNDS + 3] = temp[1];
}
