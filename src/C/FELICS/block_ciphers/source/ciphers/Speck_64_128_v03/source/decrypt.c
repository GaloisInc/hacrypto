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
 *                    Jason Smith <jksmit3@tycho.ncsc.mil>
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

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
  uint32_t       *block32  = (uint32_t *)block;
  const uint32_t *rk       = (uint32_t *)roundKeys;

  uint32_t y = block32[0];
  uint32_t x = block32[1];

  uint8_t i = NUMBER_OF_ROUNDS;

  while (i > 0) {

    y = rot32r3(x ^ y);
    x = rot32l8((x ^ READ_ROUND_KEY_DOUBLE_WORD(rk[--i])) - y);

    y = rot32r3(x ^ y);
    x = rot32l8((x ^ READ_ROUND_KEY_DOUBLE_WORD(rk[--i])) - y);

    y = rot32r3(x ^ y);
    x = rot32l8((x ^ READ_ROUND_KEY_DOUBLE_WORD(rk[--i])) - y);

  }

  block32[0] = y;
  block32[1] = x;
}
