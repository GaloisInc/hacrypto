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

#include <stdint.h>

#include "cipher.h"
#include "constants.h"


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i, r;


	for (r = 35; r > 0; r--)
	{
		for (i = 0; i < 8; i++)
		{
			block[i] ^= READ_SBOX_BYTE(
							Sbox[
									block[i] & 0x0F ^ 
									0x0F & READ_ROUND_KEY_BYTE(
												roundKeys[r * 4 + i / 2]
											) >> (4 * (i % 2))
								]
						) << 4;
		}

		/* Output */
		i = block[0];

		/* 0 <-5 */
		block[0] &= 0xF0;
		block[0] ^= block[2] >> 4;

		/* 5 <-12 */
		block[2] &= 0x0F; 
		block[2] ^= block[6] << 4;

		/* 12 <-15 */
		block[6] &= 0xF0;
		block[6] ^= block[7] >> 4;

		/* 15 <-14  */
		block[7] &= 0xF;
		block[7] ^= block[7] << 4;

		/* 14 <-11 */
		block[7] &= 0xF0;
		block[7] ^= block[5] >> 4;

		/* 11 <-2 */
		block[5] &= 0x0F;
		block[5] ^= block[1] << 4;

		/* 2 <-1 */
		block[1] &= 0xF0;
		block[1] ^= block[0] >> 4;

		/* 1 <-0  */
		block[0] &= 0x0F;
		block[0] ^= i << 4;

		i = block[1];

		/* 3 <-4 */
		block[1] &= 0x0F;
		block[1] ^= block[2] << 4;
		
		/* 4 <-7 */
		block[2] &= 0xF0;
		block[2] ^= block[3] >> 4;

		/* 7 <-8 */
		block[3] &= 0x0F;
		block[3] ^= block[4] << 4;
		
		/* 8 <-13 */
		block[4] &= 0xF0;
		block[4] ^= block[6] >> 4;
		
		/* 13 <-10 */
		block[6] &= 0x0F;
		block[6] ^= block[5] << 4;
		
		/* 10 <-9 */
		block[5] &= 0xF0;
		block[5] ^= block[4] >> 4;
		
		/* 9 <-6 */
		block[4] &= 0x0F;
		block[4] ^= block[3] << 4;
	
		/* 6 <-3 */
		block[3] &= 0xF0;
		block[3] ^= i >> 4;

	}

	for (i = 0; i < 8; i++)
	{
		block[i] ^= READ_SBOX_BYTE(
						Sbox[
								block[i] & 0x0F ^ 
							0x0F & READ_ROUND_KEY_BYTE(
										roundKeys[i / 2]
									) >> (4 * (i % 2))
						]
					) << 4;
	}
}
