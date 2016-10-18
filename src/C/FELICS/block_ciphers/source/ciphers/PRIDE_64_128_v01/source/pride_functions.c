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

void S_layer(uint8_t *data){
	uint8_t temp[4];
	temp[0] = data[0];//movw t0, s0
	temp[1] = data[1];
	temp[2] = data[2];//movw t2, s2
	temp[3] = data[3];
	data[0] &= data[2];//and s0, s2
	data[0] ^= data[4];//eor s0, s4
	data[2] &= data[4];//and s2, s4
	data[2] ^= data[6];//eor s2, s6
	data[1] &= data[3];//and s1, s3
	data[1] ^= data[5];//eor s1, s5
	data[3] &= data[5];//and s3, s5
	data[3] ^= data[7];//eor s3, s7
	data[4] = data[0];//movw s4, s0
	data[5] = data[1];
	data[6] = data[2];//movw s6, s2
	data[7] = data[3];
	data[4] &= data[6];//and s4, s6
	data[4] ^= temp[0];//eor s4, t0
	data[6] &= data[4];//and s6, s4
	data[6] ^= temp[2];//eor s6, t2
	data[5] &= data[7];//and s5, s7
	data[5] ^= temp[1];//eor s5, t1
	data[7] &= data[5];//and s7, s5
	data[7] ^= temp[3];//eor s7, t3
}

void L0(uint8_t *data)/*; Linear Layer and Inverse Linear Layer: L0*/
{
	uint8_t temp[2];
	temp[0] = data[0];//movw t0, s0
	temp[1] = data[1];//t1:t0 = s1:s0
	data[0] = SWAP(data[0]);//swap s0
	data[1] = SWAP(data[1]);//swap s1
	data[0] ^= data[1];//eor s0, s1
	temp[0] ^= data[0];//eor t0, s0
	data[1]  = temp[0];//mov s1, t0
	data[0] ^= temp[1];//eor s0, t1
}

void L1(uint8_t *data){//; Linear Layer: L1
	uint8_t temp[2];
	data[3]  = SWAP(data[3]);//swap s3
	//movw t0, s2; t1:t0 = s3:s2; movw t2, s2; t3:t2 = s3:s2 --> no need
	temp[0]  = ROTL(data[2]);//lsl t0 ; rol t2 --> t2 kees 1-bit left rotated value of s2
	temp[1]  = ROTR(data[3]);//lsr t1 ; ror t3 --> t3 kees 1-bit right rotated value of s3
	data[2] ^= temp[1];//eor s2, t3
	temp[1]  = data[2];//mov t0, s2
	data[2] ^= temp[0];//eor s2, t2
	data[3] ^= temp[1];//eor s3, t0
}

void L1Inv(uint8_t *data){//; Inverse Linear Layer: L1
	uint8_t temp[2];//movw t0, s2; t1:t0 = s3:s2; movw t2, s2; t3:t2 = s3:s2
	temp[0]  = ROTR(data[2]);//lsr t0//ror t2
	temp[1]  = ROTR(data[3]);//lsr t1//ror t3
	temp[1] ^= temp[0];//eor t3, t2
	data[3] ^= temp[1];//eor s3, t3
	data[3]  = SWAP(data[3]);//swap s3
	data[2]  = ROTR(temp[1]);//mov s2, t3; lsr t3; ror s2
	data[2] ^= temp[0];//eor s2, t2
}

void L2(uint8_t *data){//; Linear Layer: L2
	uint8_t temp[2];
	data[4]  = SWAP(data[4]);//swap s4
	//movw t0, s4//; t1:t0 = s5:s4//movw t2, s4//; t3:t2 = s5:s4
	temp[0]  = ROTL(data[4]);//lsl t0//rol t2
	temp[1]  = ROTR(data[5]);//lsr t1//ror t3
	data[4] ^= temp[1];//eor s4, t3
	temp[1]  = data[4];//mov t0, s4
	data[4] ^= temp[0];//eor s4, t2
	data[5] ^= temp[1];//eor s5, t0
}

void L2Inv(uint8_t *data){//; Inverse Linear Layer: L2
	uint8_t temp[2];//movw t0, s4//; t1:t0 = s5:s4//movw t2, s4//; t3:t2 = s5:s4
	temp[0]  = ROTR(data[4]);//lsr t0//ror t2
	temp[1]  = ROTR(data[5]);//lsr t1//ror t3
	temp[1] ^= temp[0];//eor t3, t2
	data[5] ^= temp[1];//eor s5, t3
	data[4]  = ROTR(temp[1]);//mov s4, t3//lsr t3//ror s4
	data[4] ^= temp[0];//eor s4, t2
	data[4]  = SWAP(data[4]);//swap s4
}

void L3(uint8_t *data){//; Linear Layer and Inverse Linear Layer: L3
	uint8_t temp[2];
	temp[0]  = data[6];//movw t0, s6
	temp[1]  = data[7];//; t1:t0 = s7:s6
	data[6]  = SWAP(data[6]);//swap s6
	data[7]  = SWAP(data[7]);//swap s7
	data[6] ^= data[7];//eor s6, s7
	temp[1] ^= data[6];//eor t1, s6
	data[7]  = temp[1];//mov s7, t1
	data[6] ^= temp[0];//eor s6, t0
}

void L_layer(uint8_t *data){
	L0(data);
	L1(data);
	L2(data);
	L3(data);
}

void L_layerInv(uint8_t *data){
	L0(data);
	L1Inv(data);
	L2Inv(data);
	L3(data);
}

void round_functionNoKS(uint8_t *data,uint8_t *rkey,uint8_t mode,uint8_t round){
	uint8_t i;
	if(mode==LST) S_layer(data);//last-enc or first-dec round
	else{
		for(i=0;i<4;i++){
			data[2*i] ^= READ_ROUND_KEY_BYTE(rkey[2*i]);
			if(mode==ENC) data[2*i+1] ^= (READ_ROUND_KEY_BYTE(rkey[2*i+1])+READ_ROUND_CONSTANT_BYTE(round_constants[round*4+i]));
			else data[2*i+1] ^= (READ_ROUND_KEY_BYTE(rkey[2*i+1])+READ_ROUND_CONSTANT_BYTE(round_constants[76-round*4+i]));
		}
		if(mode==ENC){
			S_layer(data);
			L_layer(data);
		}
		else if(mode==DEC){
			L_layerInv(data);
			S_layer(data);
		}
	}
}

