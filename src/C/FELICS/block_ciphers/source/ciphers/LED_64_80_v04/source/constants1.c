/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Johann Großschädl <johann.groszschaedl@uni.lu>
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

#include "constants.h"


/*
 *
 * Cipher constants
 *
 */

ROUND_TABLE_WORD RndTab[4][16] = {
{ 0x5ADB, 0x7E1A, 0xB5FC, 0xA795, 0x24C1, 0x0000, 0xEF27, 0x1269, \
  0xCBE6, 0xD98F, 0x913D, 0x6C73, 0x36A8, 0xFD4E, 0x48B2, 0x8354 },
{ 0xCE4B, 0x5D3A, 0x672C, 0xBF85, 0x9371, 0x0000, 0xA967, 0xD8A9, \
  0x3A16, 0xE2BF, 0xF45D, 0x8593, 0x4BD8, 0x71CE, 0x16E2, 0x2CF4 },
{ 0xB918, 0xA246, 0xCD94, 0x5123, 0x1B5E, 0x0000, 0x748C, 0x9CB7, \
  0x6FD2, 0xF365, 0xD6CA, 0x3EF1, 0x87E9, 0xE83B, 0x25AF, 0x4A7D },
{ 0xBE6D, 0xADB1, 0xC73F, 0x5FC9, 0x13DC, 0x0000, 0x7952, 0x98F6, \
  0x6A8E, 0xF278, 0xD4E3, 0x3547, 0x8B2A, 0xE1A4, 0x269B, 0x4C15 }
};
