/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu>
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

/****************************************************************************** 
 *
 * Constants used by encryption/decryption
 *
 ******************************************************************************/

#include <stdint.h>
#include "constants.h"

/* SBOX */
SBOX_BYTE SBOX[] =
{
    0x0e, 0x04, 0x0b, 0x02,
    0x03, 0x08, 0x00, 0x09,
    0x01, 0x0a, 0x07, 0x0f,
    0x06, 0x0c, 0x05, 0x0d
};

/* GF[2^4] multiplication by 2 */
GF16_MUL_BYTE GF16_MUL2[] =
{
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
	0x03, 0x01, 0x07, 0x05, 0x0b, 0x09, 0x0f, 0x0d
};

/* GF[2^4] multiplication by 3 */
GF16_MUL_BYTE GF16_MUL3[] =
{
	0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09,
	0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02
};
