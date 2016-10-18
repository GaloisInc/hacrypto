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

#include "rotate.h"


void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t *Block = (uint32_t *)block;
	uint32_t *RoundKeys = (uint32_t *)roundKeys;
	

	Block[0] = Block[0] + READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[0]);
	Block[1] = Block[1] + READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[1]);

	
	/* Round 1 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[2]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[3]);


	/* Round 2 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]); 


	/* Round 3 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[6]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[7]); 


	/* Round 4 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[8]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[9]); 


	/* Round 5 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[10]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[11]); 


	/* Round 6 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[12]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[13]); 


	/* Round 7 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[14]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[15]); 


	/* Round 8 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[16]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[17]); 


	/* Round 9 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[18]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[19]); 


	/* Round 10 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[20]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[21]); 


	/* Round 11 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[22]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[23]); 


	/* Round 12 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[24]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[25]); 


	/* Round 13 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[26]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[27]); 


	/* Round 14 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[28]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[29]); 


	/* Round 15 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[30]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[31]); 


	/* Round 16 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[32]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[33]); 


	/* Round 17 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[34]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[35]); 


	/* Round 18 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[36]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[37]); 


	/* Round 19 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[38]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[39]); 


	/* Round 20 */
	Block[0] = RC5_ROTL(Block[0] ^ Block[1], Block[1]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[40]); 
	Block[1] = RC5_ROTL(Block[1] ^ Block[0], Block[0]) + 
						READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[41]);
}
