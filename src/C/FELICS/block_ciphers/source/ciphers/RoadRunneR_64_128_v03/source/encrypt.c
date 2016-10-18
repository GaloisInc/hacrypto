/*
 *
 * Kocaeli University Computer Engineering
 * TÜBİTAK BİLGEM, Turkey
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 Kocaeli University
 *
 * Written in 2015 by Adnan Baysal <adnan.baysal@tubitak.gov.tr>
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

#define ROTL(x)   (((x)<<1)|((x)>>7))

#define rrr_sbox(data)\
    z = data[3];\
    data[3] &= data[2];\
    data[3] ^= data[1];\
    data[1] |= data[2];\
    data[1] ^= data[0];\
    data[0] &= data[3];\
    data[0] ^= z;\
    z &= data[1];\
    data[2] ^= z;

#define rrr_L(data)\
    z = data;\
    z = ROTL(z);\
    z ^= data;\
    z = ROTL(z);\
    data ^= z;

#define rrr_SLK(data)\
    rrr_sbox(data);\
    for(j=0;j<4;j++){\
        rrr_L(data[j]);\
        data[j] ^= READ_ROUND_KEY_BYTE(roundKeys[key_ctr+j]);\
    }\

#define rrr_enc_dec_round(block,round,mode)\
    for(j=0;j<4;j++) temp[j] = block[j];\
    rrr_SLK(block);\
    key_ctr = (key_ctr+4)&15;\
    rrr_SLK(block);\
    key_ctr = (key_ctr+4)&15;\
    block[3] ^= round;\
    rrr_SLK(block);\
    if(mode==1) key_ctr = (key_ctr+12)&15;\
    else key_ctr = (key_ctr+4)&15;\
    rrr_sbox(block);\
    for(j=0;j<4;j++) block[j] ^= block[j+4];\
    for(j=0;j<4;j++) block[j+4] = temp[j];

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i, j, temp[4] = {0}, z, key_ctr = 4;
	for(i=0;i<4;i++) block[i] ^= READ_ROUND_KEY_BYTE(roundKeys[i]);
	for(i=NUMBER_OF_ROUNDS;i>0;i--)
    {
		rrr_enc_dec_round(block,i,0)
	}
	for(i=0;i<4;i++) temp[i] = block[i];
	for(i=0;i<4;i++) block[i] = block[i+4]^READ_ROUND_KEY_BYTE(roundKeys[i+4]);
	for(i=0;i<4;i++) block[i+4] = temp[i];
}

