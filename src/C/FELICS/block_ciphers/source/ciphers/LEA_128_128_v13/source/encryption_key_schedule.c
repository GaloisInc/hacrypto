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

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint32_t* rk = (uint32_t*) roundKeys;
	uint32_t* t = (uint32_t*) key;
	uint32_t t0 = t[0];
	uint32_t t1 = t[1];
	uint32_t t2 = t[2];
	uint32_t t3 = t[3];	
	uint32_t ri = 0;
	
	int32_t i;
	uint32_t tdidx = 0;
	uint32_t tmp = 0;
	
	uint32_t td[4];
	td[0] = READ_RAM_DATA_DOUBLE_WORD(DELTA[0]);
	td[1] = rot32l1(READ_RAM_DATA_DOUBLE_WORD(DELTA[1]));
	td[2] = rot32l2(READ_RAM_DATA_DOUBLE_WORD(DELTA[2]));
	td[3] = rot32l3(READ_RAM_DATA_DOUBLE_WORD(DELTA[3]));

	
	for(i = 0; i < NUMBER_OF_ROUNDS; ++i) {
		tdidx = i & 3;
		tmp = td[tdidx];
		td[tdidx] = rot32l4(tmp);
		
		t0 = rot32l1(t0 + tmp);
		t1 = rot32l3(t1 + rot32l1(tmp));
		t2 = rot32l6(t2 + rot32l2(tmp));
		t3 = rot32l11(t3 + rot32l3(tmp));

		rk[ri++] = t0; // rk0
		rk[ri++] = t1; // rk1, rk3, rk5
		rk[ri++] = t2; // rk2
		rk[ri++] = t3; // rk4
	}
}
