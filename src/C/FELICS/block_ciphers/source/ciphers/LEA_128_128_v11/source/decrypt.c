/*
 *
 * National Security Research Institute
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 National Security Research Institute
 *
 * Written in 2015 by Ilwoong Jeong <iw98jeong@nsr.re.kr>
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
#include "rot32.h"

#define RK(x, y) READ_ROUND_KEY_DOUBLE_WORD(x[y])

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t* blk = (uint32_t*) block;
	uint32_t* rk = (uint32_t*) roundKeys;
	
	uint32_t b0 = blk[0];
	uint32_t b1 = blk[1];
	uint32_t b2 = blk[2];
	uint32_t b3 = blk[3];
	
	// Round 1
	rk += 92;	
	b0 = (rot32r9(b0) - (b3 ^ RK(rk, 0))) ^ RK(rk, 1);
	b1 = (rot32l5(b1) - (b0 ^ RK(rk, 2))) ^ RK(rk, 1);
	b2 = (rot32l3(b2) - (b1 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 2
	rk -= 4;
	b3 = (rot32r9(b3) - (b2 ^ RK(rk, 0))) ^ RK(rk, 1);
	b0 = (rot32l5(b0) - (b3 ^ RK(rk, 2))) ^ RK(rk, 1);
	b1 = (rot32l3(b1) - (b0 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 3
	rk -= 4;
	b2 = (rot32r9(b2) - (b1 ^ RK(rk, 0))) ^ RK(rk, 1);
	b3 = (rot32l5(b3) - (b2 ^ RK(rk, 2))) ^ RK(rk, 1);
	b0 = (rot32l3(b0) - (b3 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 4
	rk -= 4;
	b1 = (rot32r9(b1) - (b0 ^ RK(rk, 0))) ^ RK(rk, 1);
	b2 = (rot32l5(b2) - (b1 ^ RK(rk, 2))) ^ RK(rk, 1);
	b3 = (rot32l3(b3) - (b2 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 5
	rk -= 4;	
	b0 = (rot32r9(b0) - (b3 ^ RK(rk, 0))) ^ RK(rk, 1);
	b1 = (rot32l5(b1) - (b0 ^ RK(rk, 2))) ^ RK(rk, 1);
	b2 = (rot32l3(b2) - (b1 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 6
	rk -= 4;
	b3 = (rot32r9(b3) - (b2 ^ RK(rk, 0))) ^ RK(rk, 1);
	b0 = (rot32l5(b0) - (b3 ^ RK(rk, 2))) ^ RK(rk, 1);
	b1 = (rot32l3(b1) - (b0 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 7
	rk -= 4;
	b2 = (rot32r9(b2) - (b1 ^ RK(rk, 0))) ^ RK(rk, 1);
	b3 = (rot32l5(b3) - (b2 ^ RK(rk, 2))) ^ RK(rk, 1);
	b0 = (rot32l3(b0) - (b3 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 8
	rk -= 4;
	b1 = (rot32r9(b1) - (b0 ^ RK(rk, 0))) ^ RK(rk, 1);
	b2 = (rot32l5(b2) - (b1 ^ RK(rk, 2))) ^ RK(rk, 1);
	b3 = (rot32l3(b3) - (b2 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 9
	rk -= 4;	
	b0 = (rot32r9(b0) - (b3 ^ RK(rk, 0))) ^ RK(rk, 1);
	b1 = (rot32l5(b1) - (b0 ^ RK(rk, 2))) ^ RK(rk, 1);
	b2 = (rot32l3(b2) - (b1 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 10
	rk -= 4;
	b3 = (rot32r9(b3) - (b2 ^ RK(rk, 0))) ^ RK(rk, 1);
	b0 = (rot32l5(b0) - (b3 ^ RK(rk, 2))) ^ RK(rk, 1);
	b1 = (rot32l3(b1) - (b0 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 11
	rk -= 4;
	b2 = (rot32r9(b2) - (b1 ^ RK(rk, 0))) ^ RK(rk, 1);
	b3 = (rot32l5(b3) - (b2 ^ RK(rk, 2))) ^ RK(rk, 1);
	b0 = (rot32l3(b0) - (b3 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 12
	rk -= 4;
	b1 = (rot32r9(b1) - (b0 ^ RK(rk, 0))) ^ RK(rk, 1);
	b2 = (rot32l5(b2) - (b1 ^ RK(rk, 2))) ^ RK(rk, 1);
	b3 = (rot32l3(b3) - (b2 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 13
	rk -= 4;	
	b0 = (rot32r9(b0) - (b3 ^ RK(rk, 0))) ^ RK(rk, 1);
	b1 = (rot32l5(b1) - (b0 ^ RK(rk, 2))) ^ RK(rk, 1);
	b2 = (rot32l3(b2) - (b1 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 14
	rk -= 4;
	b3 = (rot32r9(b3) - (b2 ^ RK(rk, 0))) ^ RK(rk, 1);
	b0 = (rot32l5(b0) - (b3 ^ RK(rk, 2))) ^ RK(rk, 1);
	b1 = (rot32l3(b1) - (b0 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 15
	rk -= 4;
	b2 = (rot32r9(b2) - (b1 ^ RK(rk, 0))) ^ RK(rk, 1);
	b3 = (rot32l5(b3) - (b2 ^ RK(rk, 2))) ^ RK(rk, 1);
	b0 = (rot32l3(b0) - (b3 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 16
	rk -= 4;
	b1 = (rot32r9(b1) - (b0 ^ RK(rk, 0))) ^ RK(rk, 1);
	b2 = (rot32l5(b2) - (b1 ^ RK(rk, 2))) ^ RK(rk, 1);
	b3 = (rot32l3(b3) - (b2 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 17
	rk -= 4;	
	b0 = (rot32r9(b0) - (b3 ^ RK(rk, 0))) ^ RK(rk, 1);
	b1 = (rot32l5(b1) - (b0 ^ RK(rk, 2))) ^ RK(rk, 1);
	b2 = (rot32l3(b2) - (b1 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 18
	rk -= 4;
	b3 = (rot32r9(b3) - (b2 ^ RK(rk, 0))) ^ RK(rk, 1);
	b0 = (rot32l5(b0) - (b3 ^ RK(rk, 2))) ^ RK(rk, 1);
	b1 = (rot32l3(b1) - (b0 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 19
	rk -= 4;
	b2 = (rot32r9(b2) - (b1 ^ RK(rk, 0))) ^ RK(rk, 1);
	b3 = (rot32l5(b3) - (b2 ^ RK(rk, 2))) ^ RK(rk, 1);
	b0 = (rot32l3(b0) - (b3 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 20
	rk -= 4;
	b1 = (rot32r9(b1) - (b0 ^ RK(rk, 0))) ^ RK(rk, 1);
	b2 = (rot32l5(b2) - (b1 ^ RK(rk, 2))) ^ RK(rk, 1);
	b3 = (rot32l3(b3) - (b2 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 21
	rk -= 4;	
	b0 = (rot32r9(b0) - (b3 ^ RK(rk, 0))) ^ RK(rk, 1);
	b1 = (rot32l5(b1) - (b0 ^ RK(rk, 2))) ^ RK(rk, 1);
	b2 = (rot32l3(b2) - (b1 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 22
	rk -= 4;
	b3 = (rot32r9(b3) - (b2 ^ RK(rk, 0))) ^ RK(rk, 1);
	b0 = (rot32l5(b0) - (b3 ^ RK(rk, 2))) ^ RK(rk, 1);
	b1 = (rot32l3(b1) - (b0 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 23
	rk -= 4;
	b2 = (rot32r9(b2) - (b1 ^ RK(rk, 0))) ^ RK(rk, 1);
	b3 = (rot32l5(b3) - (b2 ^ RK(rk, 2))) ^ RK(rk, 1);
	b0 = (rot32l3(b0) - (b3 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	// Round 24
	rk -= 4;
	b1 = (rot32r9(b1) - (b0 ^ RK(rk, 0))) ^ RK(rk, 1);
	b2 = (rot32l5(b2) - (b1 ^ RK(rk, 2))) ^ RK(rk, 1);
	b3 = (rot32l3(b3) - (b2 ^ RK(rk, 3))) ^ RK(rk, 1);
	
	blk[0] = b0;
	blk[1] = b1;
	blk[2] = b2;
	blk[3] = b3;
}
