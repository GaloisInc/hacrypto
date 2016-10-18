/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu>
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
#define BLOCK_SIZE 16

#define KEY_SIZE 16
#define ROUND_KEYS_SIZE 176

#define NUMBER_OF_ROUNDS 10


/*
 *
 * Cipher constants
 *
 */
extern DATA_SBOX_BYTE Sbox[256];
extern DATA_SBOX_BYTE inv_Sbox[256];

extern DATA_KS_BYTE Rcon[31];

extern DATA_SBOX_DOUBLE_WORD T0[256];
extern DATA_SBOX_DOUBLE_WORD T1[256];
extern DATA_SBOX_DOUBLE_WORD T2[256];
extern DATA_SBOX_DOUBLE_WORD T3[256];

extern DATA_SBOX_DOUBLE_WORD inv_T0[256];
extern DATA_SBOX_DOUBLE_WORD inv_T1[256];
extern DATA_SBOX_DOUBLE_WORD inv_T2[256];
extern DATA_SBOX_DOUBLE_WORD inv_T3[256];

extern DATA_KS_DOUBLE_WORD inv_MC0[256];
extern DATA_KS_DOUBLE_WORD inv_MC1[256];
extern DATA_KS_DOUBLE_WORD inv_MC2[256];
extern DATA_KS_DOUBLE_WORD inv_MC3[256];

#endif /* CONSTANTS_H */
