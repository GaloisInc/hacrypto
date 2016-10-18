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

INVERSE_SBOX_BYTE invSbox[16] = {5, 14, 15, 8, 12, 1, 2, 13, 11, 4, 6, 3, 0, 7, 9, 10};

INVERSE_ROUND_TABLE_WORD invRndTab[4][16] = {
{ 0x0000, 0xC37D, 0xB6E9, 0x7594, 0x5CF1, 0x9F8C, 0xEA18, 0x2965, \
  0xABD2, 0x68AF, 0x1D3B, 0xDE46, 0xF723, 0x345E, 0x41CA, 0x82B7 },
{ 0x0000, 0xC869, 0xB3C1, 0x7BA8, 0x56B2, 0x9EDB, 0xE573, 0x2D1A, \
  0xAC54, 0x643D, 0x1F95, 0xD7FC, 0xFAE6, 0x328F, 0x4927, 0x814E },
{ 0x0000, 0xD429, 0x9841, 0x4C68, 0x1382, 0xC7AB, 0x8BC3, 0x5FEA, \
  0x2634, 0xF21D, 0xBE75, 0x6A5C, 0x35B6, 0xE19F, 0xADF7, 0x79DE },
{ 0x0000, 0x45ED, 0x8AF9, 0xCF14, 0x37D1, 0x723C, 0xBD28, 0xF8C5, \
  0x6E92, 0x2B7F, 0xE46B, 0xA186, 0x5943, 0x1CAE, 0xD3BA, 0x9657 }
};
