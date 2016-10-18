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

	
	/* Whitening, XOR with round constant and XOR with round key */
	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[8]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[9]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[10]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[11]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[12]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[13]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[14]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[15]);
	
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[88]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[89]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[90]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[91]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[92]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[93]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[94]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[95]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);



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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[80]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[81]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[82]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[83]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[84]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[85]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[86]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[87]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[72]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[73]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[74]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[75]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[76]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[77]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[78]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[79]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[64]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[65]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[66]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[67]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[68]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[69]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[70]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[71]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[56]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[57]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[58]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[59]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[60]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[61]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[62]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[63]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[48]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[49]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[50]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[51]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[52]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[53]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[54]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[55]);
	
	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[40]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[41]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[42]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[43]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[44]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[45]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[46]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[47]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

	
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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[32]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[33]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[34]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[35]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[36]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[37]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[38]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[39]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

	
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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[24]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[25]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[26]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[27]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[28]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[29]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[30]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[31]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

	
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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[16]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[17]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[18]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[19]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[20]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[21]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[22]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[23]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

	
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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[8]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[9]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[10]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[11]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[12]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[13]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[14]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[15]);


	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

	
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
	block[0] = block[0] ^ READ_ROUND_CONSTANT_BYTE(RC[0]);
	block[1] = block[1] ^ READ_ROUND_CONSTANT_BYTE(RC[1]);
	block[2] = block[2] ^ READ_ROUND_CONSTANT_BYTE(RC[2]);
	block[3] = block[3] ^ READ_ROUND_CONSTANT_BYTE(RC[3]);
	block[4] = block[4] ^ READ_ROUND_CONSTANT_BYTE(RC[4]);
	block[5] = block[5] ^ READ_ROUND_CONSTANT_BYTE(RC[5]);
	block[6] = block[6] ^ READ_ROUND_CONSTANT_BYTE(RC[6]);
	block[7] = block[7] ^ READ_ROUND_CONSTANT_BYTE(RC[7]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[16]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[17]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[18]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[19]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[20]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[21]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[22]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[23]);

	block[0] = block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[0]);
	block[1] = block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[1]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[2]);
	block[3] = block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[3]);
	block[4] = block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[4]);
	block[5] = block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[5]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[6]);
	block[7] = block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[7]);
}
