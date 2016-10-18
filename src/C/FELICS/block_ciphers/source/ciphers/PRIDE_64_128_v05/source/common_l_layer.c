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

#include "common_l_layer.h"
#include "pride_functions.h"


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
