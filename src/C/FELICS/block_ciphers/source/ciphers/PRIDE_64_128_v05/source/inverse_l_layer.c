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

#include "inverse_l_layer.h"
#include "common_l_layer.h"
#include "pride_functions.h"


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

void L_layerInv(uint8_t *data){
	L0(data);
	L1Inv(data);
	L2Inv(data);
	L3(data);
}
