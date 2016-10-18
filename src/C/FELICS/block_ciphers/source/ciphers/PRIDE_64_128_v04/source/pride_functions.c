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
#include "pride_functions.h"

#define S_layer(data)\
	temp[0]  = data[0];\
	temp[1]  = data[1];\
	temp[2]  = data[2];\
	temp[3]  = data[3];\
	data[0] &= data[2];\
	data[0] ^= data[4];\
	data[2] &= data[4];\
	data[2] ^= data[6];\
	data[1] &= data[3];\
	data[1] ^= data[5];\
	data[3] &= data[5];\
	data[3] ^= data[7];\
	data[4]  = data[0];\
	data[5]  = data[1];\
	data[6]  = data[2];\
	data[7]  = data[3];\
	data[4] &= data[6];\
	data[4] ^= temp[0];\
	data[6] &= data[4];\
	data[6] ^= temp[2];\
	data[5] &= data[7];\
	data[5] ^= temp[1];\
	data[7] &= data[5];\
	data[7] ^= temp[3];

#define L0(data)\
	temp[0]  = data[0];\
	temp[1]  = data[1];\
	data[0]  = SWAP(data[0]);\
	data[1]  = SWAP(data[1]);\
	data[0] ^= data[1];\
	temp[0] ^= data[0];\
	data[1]  = temp[0];\
	data[0] ^= temp[1];

#define L1(data)\
	data[3]  = SWAP(data[3]);\
	temp[0]  = ROTL(data[2]);\
	temp[1]  = ROTR(data[3]);\
	data[2] ^= temp[1];\
	temp[1]  = data[2];\
	data[2] ^= temp[0];\
	data[3] ^= temp[1];

#define L1Inv(data)\
   temp[0]  = ROTR(data[2]);\
	temp[1]  = ROTR(data[3]);\
	temp[1] ^= temp[0];\
	data[3] ^= temp[1];\
	data[3]  = SWAP(data[3]);\
	data[2]  = ROTR(temp[1]);\
	data[2] ^= temp[0];

#define L2(data)\
	data[4]  = SWAP(data[4]);\
	temp[0]  = ROTL(data[4]);\
	temp[1]  = ROTR(data[5]);\
	data[4] ^= temp[1];\
	temp[1]  = data[4];\
	data[4] ^= temp[0];\
	data[5] ^= temp[1];

#define L2Inv(data)\
	temp[0]  = ROTR(data[4]);\
	temp[1]  = ROTR(data[5]);\
	temp[1] ^= temp[0];\
	data[5] ^= temp[1];\
	data[4]  = ROTR(temp[1]);\
	data[4] ^= temp[0];\
	data[4]  = SWAP(data[4]);

#define L3(data)\
	temp[0]  = data[6];\
	temp[1]  = data[7];\
	data[6]  = SWAP(data[6]);\
	data[7]  = SWAP(data[7]);\
	data[6] ^= data[7];\
	temp[1] ^= data[6];\
	data[7]  = temp[1];\
	data[6] ^= temp[0];

#define L_layer(data)\
	L0(data)\
	L1(data)\
	L2(data)\
	L3(data)

#define L_layerInv(data)\
	L0(data)\
	L1Inv(data)\
	L2Inv(data)\
	L3(data)

void round_function(uint8_t *data,uint8_t *rkey,uint8_t mode){
	uint8_t i, temp[4];
	for(i=0;i<8;i++) data[i] ^= READ_ROUND_KEY_BYTE(rkey[i]);
	if(mode==ENC){
		S_layer(data)
		L_layer(data)
	}
	else if(mode==DEC){
		L_layerInv(data)
		S_layer(data)
	}
	else{//last-enc or first-dec round
	   S_layer(data)
	}
}

