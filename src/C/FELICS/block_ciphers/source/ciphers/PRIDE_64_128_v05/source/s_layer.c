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

#include "s_layer.h"


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
