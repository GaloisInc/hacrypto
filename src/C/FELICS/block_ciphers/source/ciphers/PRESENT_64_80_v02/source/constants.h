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
#define BLOCK_SIZE 8

#define KEY_SIZE 10
#define ROUND_KEYS_SIZE 256 

#define NUMBER_OF_ROUNDS 31


/*
 *
 * Cipher constants
 *
 */
extern DATA_SBOX_BYTE sBox4[];
extern DATA_SBOX_BYTE invsBox4[];

extern DATA_SBOX_DOUBLE_WORD spBox0_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox0_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox1_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox1_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox2_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox2_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox3_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox3_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox4_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox4_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox5_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox5_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox6_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox6_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox7_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox7_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox8_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox8_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox9_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox9_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox10_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox10_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox11_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox11_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox12_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox12_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox13_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox13_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox14_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox14_hi[16];
extern DATA_SBOX_DOUBLE_WORD spBox15_lo[16];
extern DATA_SBOX_DOUBLE_WORD spBox15_hi[16];


extern DATA_SBOX_DOUBLE_WORD ipBox0_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox0_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox1_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox1_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox2_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox2_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox3_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox3_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox4_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox4_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox5_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox5_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox6_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox6_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox7_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox7_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox8_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox8_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox9_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox9_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox10_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox10_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox11_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox11_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox12_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox12_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox13_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox13_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox14_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox14_hi[16];
extern DATA_SBOX_DOUBLE_WORD ipBox15_lo[16];
extern DATA_SBOX_DOUBLE_WORD ipBox15_hi[16];

#endif /* CONSTANTS_H */
