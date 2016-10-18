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

#include "constants.h"


/*
 *
 * Cipher constants
 *
 */
SBOX_BYTE S0[16] = {0xB, 0xF, 0x3, 0x2, 0xA, 0xC, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xE, 0x5, 0xD, 0x4};

INVERSE_SBOX_BYTE S1[16] = {0xB, 0x7, 0x3, 0x2, 0xF, 0xD, 0x8, 0x9, 0xA, 0x6, 0x4, 0x0, 0x5, 0xE, 0xC, 0x1};

ROUND_CONSTANT_BYTE RC[96] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13,
		0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4,
		0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08,
		0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45,
		0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe,
		0xb1, 0x5c, 0x95, 0xfd, 0x78, 0x4f, 0xf8, 0x7e,
		0xaa, 0x43, 0xac, 0xf1, 0x51, 0x08, 0x84, 0x85,
		0x54, 0x3c, 0x32, 0x25, 0x2f, 0xd3, 0x82, 0xc8,
		0x0d, 0x61, 0xe3, 0xe0, 0x95, 0x11, 0xa5, 0x64,
		0x99, 0x23, 0x0c, 0xca, 0x99, 0xa3, 0xb5, 0xd3,
		0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0
	};
