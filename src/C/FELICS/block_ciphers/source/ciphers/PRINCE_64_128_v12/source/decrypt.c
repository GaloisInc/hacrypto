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


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t temp0;
	uint8_t temp1;


	uint32_t *Block = (uint32_t *)block;
	uint32_t *RoundKeys = (uint32_t *)roundKeys;
	uint32_t *RoundConstants = (uint32_t *)RC;

	
	/* Whitening, XOR with round constant and XOR with round key */
	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[2]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[3]);

	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[22]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[23]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);



	/* Forward Round 10 - Begin */

	/* S-Layer */
	block[0] = ((READ_SBOX_BYTE(S0[(block[0] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[0] & 0x0F)]));
	block[1] = ((READ_SBOX_BYTE(S0[(block[1] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[1] & 0x0F)]));
	block[2] = ((READ_SBOX_BYTE(S0[(block[2] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[2] & 0x0F)]));
	block[3] = ((READ_SBOX_BYTE(S0[(block[3] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[3] & 0x0F)]));
	block[4] = ((READ_SBOX_BYTE(S0[(block[4] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[4] & 0x0F)]));
	block[5] = ((READ_SBOX_BYTE(S0[(block[5] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[5] & 0x0F)]));
	block[6] = ((READ_SBOX_BYTE(S0[(block[6] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[6] & 0x0F)]));
	block[7] = ((READ_SBOX_BYTE(S0[(block[7] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[7] & 0x0F)]));

	
	/* M-Layer */
	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* SR - Begin */
	/* Shift left column 1 by 1 */
	temp0 = block[7];
	block[7] = (block[7] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[1] & 0x0F);
	block[1] = (block[1] & 0xF0) ^ (temp0 & 0x0F);


	/* Shift left column 2 by 2 and column 3 by 3 */
	temp0 = block[0];
	temp1 = block[2];

	block[0] = (block[4] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (block[6] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (temp0 & 0xF0) ^ (block[6] & 0x0F);
	block[6] = (temp1 & 0xF0) ^ (temp0 & 0x0F);
	/* SR - End */

	
	/* XOR K1, XOR RCi */
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[20]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[21]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	/* Forward Round 10 - End */


	/* Forward Round 9 - Begin */

	/* S-Layer */
	block[0] = ((READ_SBOX_BYTE(S0[(block[0] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[0] & 0x0F)]));
	block[1] = ((READ_SBOX_BYTE(S0[(block[1] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[1] & 0x0F)]));
	block[2] = ((READ_SBOX_BYTE(S0[(block[2] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[2] & 0x0F)]));
	block[3] = ((READ_SBOX_BYTE(S0[(block[3] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[3] & 0x0F)]));
	block[4] = ((READ_SBOX_BYTE(S0[(block[4] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[4] & 0x0F)]));
	block[5] = ((READ_SBOX_BYTE(S0[(block[5] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[5] & 0x0F)]));
	block[6] = ((READ_SBOX_BYTE(S0[(block[6] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[6] & 0x0F)]));
	block[7] = ((READ_SBOX_BYTE(S0[(block[7] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[7] & 0x0F)]));

	
	/* M-Layer */
	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* SR - Begin */
	/* Shift left column 1 by 1 */
	temp0 = block[7];
	block[7] = (block[7] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[1] & 0x0F);
	block[1] = (block[1] & 0xF0) ^ (temp0 & 0x0F);


	/* Shift left column 2 by 2 and column 3 by 3 */
	temp0 = block[0];
	temp1 = block[2];

	block[0] = (block[4] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (block[6] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (temp0 & 0xF0) ^ (block[6] & 0x0F);
	block[6] = (temp1 & 0xF0) ^ (temp0 & 0x0F);
	/* SR - End */

	
	/* XOR K1, XOR RCi */
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[18]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[19]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	/* Forward Round 9 - End */

	
	/* Forward Round 8 - Begin */

	/* S-Layer */
	block[0] = ((READ_SBOX_BYTE(S0[(block[0] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[0] & 0x0F)]));
	block[1] = ((READ_SBOX_BYTE(S0[(block[1] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[1] & 0x0F)]));
	block[2] = ((READ_SBOX_BYTE(S0[(block[2] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[2] & 0x0F)]));
	block[3] = ((READ_SBOX_BYTE(S0[(block[3] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[3] & 0x0F)]));
	block[4] = ((READ_SBOX_BYTE(S0[(block[4] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[4] & 0x0F)]));
	block[5] = ((READ_SBOX_BYTE(S0[(block[5] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[5] & 0x0F)]));
	block[6] = ((READ_SBOX_BYTE(S0[(block[6] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[6] & 0x0F)]));
	block[7] = ((READ_SBOX_BYTE(S0[(block[7] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[7] & 0x0F)]));

	
	/* M-Layer */
	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* SR - Begin */
	/* Shift left column 1 by 1 */
	temp0 = block[7];
	block[7] = (block[7] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[1] & 0x0F);
	block[1] = (block[1] & 0xF0) ^ (temp0 & 0x0F);


	/* Shift left column 2 by 2 and column 3 by 3 */
	temp0 = block[0];
	temp1 = block[2];

	block[0] = (block[4] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (block[6] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (temp0 & 0xF0) ^ (block[6] & 0x0F);
	block[6] = (temp1 & 0xF0) ^ (temp0 & 0x0F);
	/* SR - End */

	
	/* XOR K1, XOR RCi */
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[16]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[17]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	/* Forward Round 8 - End */


	/* Forward Round 7 - Begin */

	/* S-Layer */
	block[0] = ((READ_SBOX_BYTE(S0[(block[0] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[0] & 0x0F)]));
	block[1] = ((READ_SBOX_BYTE(S0[(block[1] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[1] & 0x0F)]));
	block[2] = ((READ_SBOX_BYTE(S0[(block[2] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[2] & 0x0F)]));
	block[3] = ((READ_SBOX_BYTE(S0[(block[3] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[3] & 0x0F)]));
	block[4] = ((READ_SBOX_BYTE(S0[(block[4] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[4] & 0x0F)]));
	block[5] = ((READ_SBOX_BYTE(S0[(block[5] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[5] & 0x0F)]));
	block[6] = ((READ_SBOX_BYTE(S0[(block[6] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[6] & 0x0F)]));
	block[7] = ((READ_SBOX_BYTE(S0[(block[7] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[7] & 0x0F)]));

	
	/* M-Layer */
	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* SR - Begin */
	/* Shift left column 1 by 1 */
	temp0 = block[7];
	block[7] = (block[7] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[1] & 0x0F);
	block[1] = (block[1] & 0xF0) ^ (temp0 & 0x0F);


	/* Shift left column 2 by 2 and column 3 by 3 */
	temp0 = block[0];
	temp1 = block[2];

	block[0] = (block[4] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (block[6] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (temp0 & 0xF0) ^ (block[6] & 0x0F);
	block[6] = (temp1 & 0xF0) ^ (temp0 & 0x0F);
	/* SR - End */

	
	/* XOR K1, XOR RCi */
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[14]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[15]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	/* Forward Round 7 - End */


	/* Forward Round 6 - Begin */

	/* S-Layer */
	block[0] = ((READ_SBOX_BYTE(S0[(block[0] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[0] & 0x0F)]));
	block[1] = ((READ_SBOX_BYTE(S0[(block[1] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[1] & 0x0F)]));
	block[2] = ((READ_SBOX_BYTE(S0[(block[2] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[2] & 0x0F)]));
	block[3] = ((READ_SBOX_BYTE(S0[(block[3] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[3] & 0x0F)]));
	block[4] = ((READ_SBOX_BYTE(S0[(block[4] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[4] & 0x0F)]));
	block[5] = ((READ_SBOX_BYTE(S0[(block[5] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[5] & 0x0F)]));
	block[6] = ((READ_SBOX_BYTE(S0[(block[6] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[6] & 0x0F)]));
	block[7] = ((READ_SBOX_BYTE(S0[(block[7] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[7] & 0x0F)]));

	
	/* M-Layer */
	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* SR - Begin */
	/* Shift left column 1 by 1 */
	temp0 = block[7];
	block[7] = (block[7] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[1] & 0x0F);
	block[1] = (block[1] & 0xF0) ^ (temp0 & 0x0F);


	/* Shift left column 2 by 2 and column 3 by 3 */
	temp0 = block[0];
	temp1 = block[2];

	block[0] = (block[4] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (block[6] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (temp0 & 0xF0) ^ (block[6] & 0x0F);
	block[6] = (temp1 & 0xF0) ^ (temp0 & 0x0F);
	/* SR - End */

	
	/* XOR K1, XOR RCi */
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[12]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[13]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	/* Forward Round 6 - End */



	/* Middle layer - begin */

	/* S-Layer */
	block[0] = ((READ_SBOX_BYTE(S0[(block[0] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[0] & 0x0F)]));
	block[1] = ((READ_SBOX_BYTE(S0[(block[1] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[1] & 0x0F)]));
	block[2] = ((READ_SBOX_BYTE(S0[(block[2] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[2] & 0x0F)]));
	block[3] = ((READ_SBOX_BYTE(S0[(block[3] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[3] & 0x0F)]));
	block[4] = ((READ_SBOX_BYTE(S0[(block[4] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[4] & 0x0F)]));
	block[5] = ((READ_SBOX_BYTE(S0[(block[5] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[5] & 0x0F)]));
	block[6] = ((READ_SBOX_BYTE(S0[(block[6] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[6] & 0x0F)]));
	block[7] = ((READ_SBOX_BYTE(S0[(block[7] >> 4)])) << 4) ^ (READ_SBOX_BYTE(S0[(block[7] & 0x0F)]));


	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* Inverse S-Layer */
	block[0] = ((READ_INVERSE_SBOX_BYTE(S1[(block[0] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[0] & 0x0F)]));
	block[1] = ((READ_INVERSE_SBOX_BYTE(S1[(block[1] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[1] & 0x0F)]));
	block[2] = ((READ_INVERSE_SBOX_BYTE(S1[(block[2] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[2] & 0x0F)]));
	block[3] = ((READ_INVERSE_SBOX_BYTE(S1[(block[3] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[3] & 0x0F)]));
	block[4] = ((READ_INVERSE_SBOX_BYTE(S1[(block[4] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[4] & 0x0F)]));
	block[5] = ((READ_INVERSE_SBOX_BYTE(S1[(block[5] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[5] & 0x0F)]));
	block[6] = ((READ_INVERSE_SBOX_BYTE(S1[(block[6] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[6] & 0x0F)]));
	block[7] = ((READ_INVERSE_SBOX_BYTE(S1[(block[7] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[7] & 0x0F)]));

	/* Middle layer - end */

	
	
	/* Forward Round 5 - Begin */

	/* XOR K1, XOR RCi */
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[10]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[11]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	
	/* Inverse SR */
	/* Shift right column 1 by 1 */
	temp0 = block[1];
	block[1] = (block[1] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[7] & 0x0F);
	block[7] = (block[7] & 0xF0) ^ (temp0 & 0x0F);

	
	/* Shift right column 2 by 2 and column 3 by 3 */
	temp0 = block[6];
	temp1 = block[4];

	block[6] = (block[2] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (block[0] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (temp0 & 0xF0) ^ (block[0] & 0x0F);
	block[0] = (temp1 & 0xF0) ^ (temp0 & 0x0F);


	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* Inverse S-Layer */
	block[0] = ((READ_INVERSE_SBOX_BYTE(S1[(block[0] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[0] & 0x0F)]));
	block[1] = ((READ_INVERSE_SBOX_BYTE(S1[(block[1] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[1] & 0x0F)]));
	block[2] = ((READ_INVERSE_SBOX_BYTE(S1[(block[2] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[2] & 0x0F)]));
	block[3] = ((READ_INVERSE_SBOX_BYTE(S1[(block[3] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[3] & 0x0F)]));
	block[4] = ((READ_INVERSE_SBOX_BYTE(S1[(block[4] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[4] & 0x0F)]));
	block[5] = ((READ_INVERSE_SBOX_BYTE(S1[(block[5] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[5] & 0x0F)]));
	block[6] = ((READ_INVERSE_SBOX_BYTE(S1[(block[6] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[6] & 0x0F)]));
	block[7] = ((READ_INVERSE_SBOX_BYTE(S1[(block[7] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[7] & 0x0F)]));

	/* Backward Round 5 - End */


	/* Forward Round 4 - Begin */

	/* XOR K1, XOR RCi */
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[8]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[9]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	
	/* Inverse SR */
	/* Shift right column 1 by 1 */
	temp0 = block[1];
	block[1] = (block[1] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[7] & 0x0F);
	block[7] = (block[7] & 0xF0) ^ (temp0 & 0x0F);

	
	/* Shift right column 2 by 2 and column 3 by 3 */
	temp0 = block[6];
	temp1 = block[4];

	block[6] = (block[2] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (block[0] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (temp0 & 0xF0) ^ (block[0] & 0x0F);
	block[0] = (temp1 & 0xF0) ^ (temp0 & 0x0F);


	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* Inverse S-Layer */
	block[0] = ((READ_INVERSE_SBOX_BYTE(S1[(block[0] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[0] & 0x0F)]));
	block[1] = ((READ_INVERSE_SBOX_BYTE(S1[(block[1] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[1] & 0x0F)]));
	block[2] = ((READ_INVERSE_SBOX_BYTE(S1[(block[2] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[2] & 0x0F)]));
	block[3] = ((READ_INVERSE_SBOX_BYTE(S1[(block[3] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[3] & 0x0F)]));
	block[4] = ((READ_INVERSE_SBOX_BYTE(S1[(block[4] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[4] & 0x0F)]));
	block[5] = ((READ_INVERSE_SBOX_BYTE(S1[(block[5] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[5] & 0x0F)]));
	block[6] = ((READ_INVERSE_SBOX_BYTE(S1[(block[6] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[6] & 0x0F)]));
	block[7] = ((READ_INVERSE_SBOX_BYTE(S1[(block[7] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[7] & 0x0F)]));

	/* Forward Round 4 - End */


	/* Forward Round 3 - Begin */

	/* XOR K1, XOR RCi */		
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[6]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[7]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	
	/* Inverse SR */
	/* Shift right column 1 by 1 */
	temp0 = block[1];
	block[1] = (block[1] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[7] & 0x0F);
	block[7] = (block[7] & 0xF0) ^ (temp0 & 0x0F);

	
	/* Shift right column 2 by 2 and column 3 by 3 */
	temp0 = block[6];
	temp1 = block[4];

	block[6] = (block[2] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (block[0] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (temp0 & 0xF0) ^ (block[0] & 0x0F);
	block[0] = (temp1 & 0xF0) ^ (temp0 & 0x0F);


	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* Inverse S-Layer */
	block[0] = ((READ_INVERSE_SBOX_BYTE(S1[(block[0] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[0] & 0x0F)]));
	block[1] = ((READ_INVERSE_SBOX_BYTE(S1[(block[1] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[1] & 0x0F)]));
	block[2] = ((READ_INVERSE_SBOX_BYTE(S1[(block[2] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[2] & 0x0F)]));
	block[3] = ((READ_INVERSE_SBOX_BYTE(S1[(block[3] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[3] & 0x0F)]));
	block[4] = ((READ_INVERSE_SBOX_BYTE(S1[(block[4] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[4] & 0x0F)]));
	block[5] = ((READ_INVERSE_SBOX_BYTE(S1[(block[5] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[5] & 0x0F)]));
	block[6] = ((READ_INVERSE_SBOX_BYTE(S1[(block[6] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[6] & 0x0F)]));
	block[7] = ((READ_INVERSE_SBOX_BYTE(S1[(block[7] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[7] & 0x0F)]));

	/* Forward Round 3 - End */


	/* Forward Round 2 - Begin */

	/* XOR K1, XOR RCi */
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[4]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[5]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	
	/* Inverse SR */
	/* Shift right column 1 by 1 */
	temp0 = block[1];
	block[1] = (block[1] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[7] & 0x0F);
	block[7] = (block[7] & 0xF0) ^ (temp0 & 0x0F);

	
	/* Shift right column 2 by 2 and column 3 by 3 */
	temp0 = block[6];
	temp1 = block[4];

	block[6] = (block[2] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (block[0] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (temp0 & 0xF0) ^ (block[0] & 0x0F);
	block[0] = (temp1 & 0xF0) ^ (temp0 & 0x0F);


	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* Inverse S-Layer */
	block[0] = ((READ_INVERSE_SBOX_BYTE(S1[(block[0] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[0] & 0x0F)]));
	block[1] = ((READ_INVERSE_SBOX_BYTE(S1[(block[1] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[1] & 0x0F)]));
	block[2] = ((READ_INVERSE_SBOX_BYTE(S1[(block[2] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[2] & 0x0F)]));
	block[3] = ((READ_INVERSE_SBOX_BYTE(S1[(block[3] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[3] & 0x0F)]));
	block[4] = ((READ_INVERSE_SBOX_BYTE(S1[(block[4] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[4] & 0x0F)]));
	block[5] = ((READ_INVERSE_SBOX_BYTE(S1[(block[5] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[5] & 0x0F)]));
	block[6] = ((READ_INVERSE_SBOX_BYTE(S1[(block[6] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[6] & 0x0F)]));
	block[7] = ((READ_INVERSE_SBOX_BYTE(S1[(block[7] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[7] & 0x0F)]));

	/* Forward Round 2 - End */


	/* Forward Round 1 - Begin */

	/* XOR K1, XOR RCi */
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[2]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[3]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	
	/* Inverse SR */
	/* Shift right column 1 by 1 */
	temp0 = block[1];
	block[1] = (block[1] & 0xF0) ^ (block[3] & 0x0F);
	block[3] = (block[3] & 0xF0) ^ (block[5] & 0x0F);
	block[5] = (block[5] & 0xF0) ^ (block[7] & 0x0F);
	block[7] = (block[7] & 0xF0) ^ (temp0 & 0x0F);

	
	/* Shift right column 2 by 2 and column 3 by 3 */
	temp0 = block[6];
	temp1 = block[4];

	block[6] = (block[2] & 0xF0) ^ (block[4] & 0x0F);
	block[4] = (block[0] & 0xF0) ^ (block[2] & 0x0F);
	block[2] = (temp0 & 0xF0) ^ (block[0] & 0x0F);
	block[0] = (temp1 & 0xF0) ^ (temp0 & 0x0F);


	/* M-Layer - begin */
	/* M0 multiplication */
	temp1 = (0x07 & (block[7] >> 4)) ^ (0x0B & block[7]) ^ (0x0D & (block[6] >> 4)) ^ (0x0E & block[6]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[7] >> 4)) ^ (0x0D & block[7]) ^ (0x0E & (block[6] >> 4)) ^ (0x07 & block[6]);
		
	temp0 = (0x0D & (block[7] >> 4)) ^ (0x0E & block[7]) ^ (0x07 & (block[6] >> 4)) ^ (0x0B & block[6]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[7] >> 4)) ^ (0x07 & block[7]) ^ (0x0B & (block[6] >> 4)) ^ (0x0D & block[6]);

	block[7] = temp1;
	block[6] = temp0;
	

	/* M1 multiplication */
	temp1 = (0x0B & (block[5] >> 4)) ^ (0x0D & block[5]) ^ (0x0E & (block[4] >> 4)) ^ (0x07 & block[4]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[5] >> 4)) ^ (0x0E & block[5]) ^ (0x07 & (block[4] >> 4)) ^ (0x0B & block[4]);
		
	temp0 = (0x0E & (block[5] >> 4)) ^ (0x07 & block[5]) ^ (0x0B & (block[4] >> 4)) ^ (0x0D & block[4]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[5] >> 4)) ^ (0x0B & block[5]) ^ (0x0D & (block[4] >> 4)) ^ (0x0E & block[4]);
	
	block[5] = temp1;
	block[4] = temp0;


	/* M1 multiplication */
	temp1 = (0x0B & (block[3] >> 4)) ^ (0x0D & block[3]) ^ (0x0E & (block[2] >> 4)) ^ (0x07 & block[2]);
	temp1 = (temp1 << 4) ^ (0x0D & (block[3] >> 4)) ^ (0x0E & block[3]) ^ (0x07 & (block[2] >> 4)) ^ (0x0B & block[2]);
		
	temp0 = (0x0E & (block[3] >> 4)) ^ (0x07 & block[3]) ^ (0x0B & (block[2] >> 4)) ^ (0x0D & block[2]);
	temp0 = (temp0 << 4) ^ (0x07 & (block[3] >> 4)) ^ (0x0B & block[3]) ^ (0x0D & (block[2] >> 4)) ^ (0x0E & block[2]);
	
	block[3] = temp1;
	block[2] = temp0;


	/* M0 multiplication */
	temp1 = (0x07 & (block[1] >> 4)) ^ (0x0B & block[1]) ^ (0x0D & (block[0] >> 4)) ^ (0x0E & block[0]);
	temp1 = (temp1 << 4) ^ (0x0B & (block[1] >> 4)) ^ (0x0D & block[1]) ^ (0x0E & (block[0] >> 4)) ^ (0x07 & block[0]);
		
	temp0 = (0x0D & (block[1] >> 4)) ^ (0x0E & block[1]) ^ (0x07 & (block[0] >> 4)) ^ (0x0B & block[0]);
	temp0 = (temp0 << 4) ^ (0x0E & (block[1] >> 4)) ^ (0x07 & block[1]) ^ (0x0B & (block[0] >> 4)) ^ (0x0D & block[0]);
	
	block[1] = temp1;
	block[0] = temp0;
	/* M-Layer - end */


	/* Inverse S-Layer */
	block[0] = ((READ_INVERSE_SBOX_BYTE(S1[(block[0] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[0] & 0x0F)]));
	block[1] = ((READ_INVERSE_SBOX_BYTE(S1[(block[1] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[1] & 0x0F)]));
	block[2] = ((READ_INVERSE_SBOX_BYTE(S1[(block[2] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[2] & 0x0F)]));
	block[3] = ((READ_INVERSE_SBOX_BYTE(S1[(block[3] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[3] & 0x0F)]));
	block[4] = ((READ_INVERSE_SBOX_BYTE(S1[(block[4] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[4] & 0x0F)]));
	block[5] = ((READ_INVERSE_SBOX_BYTE(S1[(block[5] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[5] & 0x0F)]));
	block[6] = ((READ_INVERSE_SBOX_BYTE(S1[(block[6] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[6] & 0x0F)]));
	block[7] = ((READ_INVERSE_SBOX_BYTE(S1[(block[7] >> 4)])) << 4) ^ (READ_INVERSE_SBOX_BYTE(S1[(block[7] & 0x0F)]));

	/* Forward Round 1 - End */

	

	/* XOR with round constant, XOR with round key and whitening */
	Block[0] = Block[0] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[0]);
	Block[1] = Block[1] ^ READ_ROUND_CONSTANT_DOUBLE_WORD(RoundConstants[1]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[4]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[5]);

	Block[0] = Block[0] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[0]);
	Block[1] = Block[1] ^ READ_ROUND_KEY_DOUBLE_WORD(RoundKeys[1]);
}
