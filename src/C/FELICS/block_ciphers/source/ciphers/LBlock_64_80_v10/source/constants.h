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

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "data_types.h"


/*
 *
 * Cipher characteristics:
 * 	BLOCK_SIZE - the cipher block size in bytes
 * 	KEY_SIZE - the cipher key size in bytes
 *	ROUND_KEY_SIZE - the cipher round keys size in bytes
 * 	NUMBER_OF_ROUNDS - the cipher number of rounds
 *
 */
#define BLOCK_SIZE 8

#define KEY_SIZE 10
#define ROUND_KEYS_SIZE 128

#define NUMBER_OF_ROUNDS 32


/*
 *
 * Cipher S-boxes
 *
 */
extern SBOX_BYTE S0[16];
extern SBOX_BYTE S1[16];
extern SBOX_BYTE S2[16];
extern SBOX_BYTE S3[16];
extern SBOX_BYTE S4[16];
extern SBOX_BYTE S5[16];
extern SBOX_BYTE S6[16];
extern SBOX_BYTE S7[16];
extern SBOX_BYTE S8[16];
extern SBOX_BYTE S9[16];

#endif /* CONSTANTS_H */
