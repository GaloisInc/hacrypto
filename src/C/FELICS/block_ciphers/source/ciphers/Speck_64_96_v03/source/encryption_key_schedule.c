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


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
  uint32_t *key32       = (uint32_t *)key;
  uint32_t *roundKeys32 = (uint32_t *)roundKeys;

  uint32_t y    = key32[0];
  uint32_t x    = key32[1];
  uint32_t key2 = key32[2];
  uint32_t tmp;

  uint8_t i = 0;

  while(1) {

    roundKeys32[i] = y;

    if (i == NUMBER_OF_ROUNDS-1) break;

    x = (rot32r8(x) + y) ^ i++;
    y = rot32l3(y) ^ x;

    tmp  = x;
    x    = key2;
    key2 = tmp; 

  }
}
