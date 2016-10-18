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

#include "cipher.h"
#include "constants.h"
#include "shared_functions.h"


void DecryptionPrinceCore(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i;


	AddRoundRoundKeyAndRoundConstant(block, roundKeys, &RC[88]);

	for(i = 10; i >=6; i--)
	{
		Round(block, roundKeys, &RC[8 * i]);
	}


	/* Middle layer - begin */

	/* S-Layer */
	SLayer(block);

	/* M-Layer */
	M0Multiplication(&block[6]);
	M1Multiplication(&block[4]);
	M1Multiplication(&block[2]);
	M0Multiplication(&block[0]);

	/* Inverse S-Layer */
	InverseSLayer(block);

	/* Middle layer - end */

	
	for(i = 5; i >= 1; i--)
	{
		InverseRound(block, roundKeys, &RC[8 * i]);
	}

	AddRoundRoundKeyAndRoundConstant(block, roundKeys, &RC[0]);
}

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	Whitening(block, &roundKeys[8]);
	DecryptionPrinceCore(block, &roundKeys[16]);
	Whitening(block, roundKeys);
}
