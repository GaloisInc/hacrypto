/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 University of Luxembourg
 *
 * Written in 2016 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "data_types.h"


/*
 *
 * Cipher characteristics:
 * 	STATE_SIZE - the cipher state size in bytes
 * 	KEY_SIZE - the cipher key size in bytes
 *	IV_SIZE - the cipher round keys size in bytes
 *  TEST_STREAM_SIZE - the cipher test stream size in bytes
 *
 */
#define STATE_SIZE 64

#define KEY_SIZE 16
#define IV_SIZE 8

#define TEST_STREAM_SIZE 64


/*
 *
 * Cipher constants
 *
 */
extern CONSTANT_DOUBLE_WORD TAU[4];

#endif /* CONSTANTS_H */
