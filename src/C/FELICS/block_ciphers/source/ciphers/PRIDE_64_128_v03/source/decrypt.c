/*
 *
 * Kocaeli University Computer Engineering
 * TÜBİTAK BİLGEM, Turkey
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 Kocaeli University
 *
 * Written in 2015 by Adnan Baysal <adnan.baysal@tubitak.gov.tr>
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
#include "pride_functions.h"

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i;
	for(i=0;i<BLOCK_SIZE;i++) block[i] ^= READ_ROUND_KEY_BYTE(roundKeys[i]);
	round_functionNoKS(block,roundKeys+BLOCK_SIZE,LST,NUMBER_OF_ROUNDS-1);
	for(i=0;i<(NUMBER_OF_ROUNDS-1);i++) round_functionNoKS(block,roundKeys+BLOCK_SIZE,DEC,i);
	for(i=0;i<4;i++){
		block[2*i] ^= READ_ROUND_KEY_BYTE(roundKeys[2*i])^READ_ROUND_KEY_BYTE(roundKeys[8+2*i]);
		block[2*i+1] ^= READ_ROUND_KEY_BYTE(roundKeys[2*i+1])^(READ_ROUND_KEY_BYTE(roundKeys[8+2*i+1])+READ_ROUND_CONSTANT_BYTE(round_constants[i]));
	}
}

