/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu>,
 *                    Jason Smith <jksmit3@tycho.ncsc.mil>,
 *                    Bryan Weeks <beweeks@tycho.ncsc.mil>
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
#include "rot32.h"
#include "constants.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
  uint8_t i;
  uint8_t z_xor_3;
  uint32_t tmp;
  uint32_t *mk = (uint32_t *)key;
  uint32_t *rk = (uint32_t *)roundKeys;

  rk[0] = mk[0];
  rk[1] = mk[1];
  rk[2] = mk[2];

  for (i = 3; i < NUMBER_OF_ROUNDS; ++i) {

    tmp  = rot32r3(rk[i - 1]);
    tmp ^= rot32r1(tmp);

    z_xor_3 = READ_Z_BYTE(Z_XOR_3[(i - 3)]);

    rk[i] = ~(rk[i - 3]) ^ tmp ^ (uint32_t)z_xor_3;
  }
}
