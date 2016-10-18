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
#include "primitives.h"

#define RK(x, y) READ_ROUND_KEY_DOUBLE_WORD(x[y])

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t* blk = (uint32_t*) block;
	uint32_t* rk = (uint32_t*) roundKeys;
	int8_t i;
	
	for (i = NUMBER_OF_ROUNDS - 1, rk += 92; i >= 0; i -= 4, rk -= 4) {
		blk[0] = (rotr(blk[0], 9) - (blk[3] ^ RK(rk, 0))) ^ RK(rk, 1);
		blk[1] = (rotl(blk[1], 5) - (blk[0] ^ RK(rk, 2))) ^ RK(rk, 1);
		blk[2] = (rotl(blk[2], 3) - (blk[1] ^ RK(rk, 3))) ^ RK(rk, 1);
				
		rk -= 4;
		blk[3] = (rotr(blk[3], 9) - (blk[2] ^ RK(rk, 0))) ^ RK(rk, 1);
		blk[0] = (rotl(blk[0], 5) - (blk[3] ^ RK(rk, 2))) ^ RK(rk, 1);
		blk[1] = (rotl(blk[1], 3) - (blk[0] ^ RK(rk, 3))) ^ RK(rk, 1);
		
		rk -= 4;
		blk[2] = (rotr(blk[2], 9) - (blk[1] ^ RK(rk, 0))) ^ RK(rk, 1);
		blk[3] = (rotl(blk[3], 5) - (blk[2] ^ RK(rk, 2))) ^ RK(rk, 1);
		blk[0] = (rotl(blk[0], 3) - (blk[3] ^ RK(rk, 3))) ^ RK(rk, 1);
		
		rk -= 4;
		blk[1] = (rotr(blk[1], 9) - (blk[0] ^ RK(rk, 0))) ^ RK(rk, 1);
		blk[2] = (rotl(blk[2], 5) - (blk[1] ^ RK(rk, 2))) ^ RK(rk, 1);
		blk[3] = (rotl(blk[3], 3) - (blk[2] ^ RK(rk, 3))) ^ RK(rk, 1);
	}
}
	