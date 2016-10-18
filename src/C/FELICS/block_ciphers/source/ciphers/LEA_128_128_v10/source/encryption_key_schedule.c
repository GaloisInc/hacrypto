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

#include <string.h>

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint32_t ri = 0;
	int32_t i;
	uint32_t T[4];
    uint32_t* rk = (uint32_t*) roundKeys;
	memcpy(T, key, KEY_SIZE);

	for(i = 0; i < NUMBER_OF_ROUNDS; ++i) {
		uint32_t tmp = rotl(READ_RAM_DATA_DOUBLE_WORD(DELTA[i & 3]), i);
		
		T[0] = rotl(T[0] + tmp, 1);
		T[1] = rotl(T[1] + rotl(tmp, 1), 3);
		T[2] = rotl(T[2] + rotl(tmp, 2), 6);
		T[3] = rotl(T[3] + rotl(tmp, 3), 11);

		rk[ri++] = T[0]; // rk0
		rk[ri++] = T[1]; // rk1, rk3, rk5
		rk[ri++] = T[2]; // rk2
		rk[ri++] = T[3]; // rk4
	}
}
