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

#include <stdint.h>
#include "cipher.h"
#include "constants.h"
#include "rrr_functions.h"

#define ROTL(x)   (((x)<<1)|((x)>>7))

void rrr_sbox(uint8_t *data)
{
	uint8_t temp = data[3];
	data[3] &= data[2];
	data[3] ^= data[1];
	data[1] |= data[2];
	data[1] ^= data[0];
	data[0] &= data[3];
	data[0] ^= temp;
	temp &= data[1];
	data[2] ^= temp;
}

void rrr_L(uint8_t *data)
{
	uint8_t temp = data[0];
	temp = ROTL(temp);
	temp ^= data[0];
	temp = ROTL(temp);
	data[0] ^= temp;
}

void rrr_SLK(uint8_t *data,uint8_t *key_part)
{
	uint8_t i;
	rrr_sbox(data);
	for(i=0;i<4;i++){
		rrr_L(data+i);
		data[i] ^= READ_ROUND_KEY_BYTE(key_part[i]);
	}
}

void rrr_enc_dec_round(uint8_t *block, uint8_t *roundKey,uint8_t round,uint8_t *key_ctr,uint8_t mode)
{
	uint8_t i, temp[4];
	
	for(i=0;i<4;i++) temp[i] = block[i];
	
	rrr_SLK(block,roundKey+key_ctr[0]);
	key_ctr[0] = (key_ctr[0]+4)&15;
	rrr_SLK(block,roundKey+key_ctr[0]);
	key_ctr[0] = (key_ctr[0]+4)&15;
	block[3] ^= round;
	rrr_SLK(block,roundKey+key_ctr[0]);
	if(mode==1) key_ctr[0] = (key_ctr[0]+12)&15;
	else key_ctr[0] = (key_ctr[0]+4)&15;
	rrr_sbox(block);
	
	for(i=0;i<4;i++) block[i] ^= block[i+4];
	for(i=0;i<4;i++) block[i+4] = temp[i];
}


