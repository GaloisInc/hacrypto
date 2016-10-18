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


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t shiftedKey[4];
	uint8_t keyCopy[KEY_SIZE];

	
	keyCopy[9] = key[9];
	keyCopy[8] = key[8];
	keyCopy[7] = key[7];
	keyCopy[6] = key[6];
	keyCopy[5] = key[5];
	keyCopy[4] = key[4];
	keyCopy[3] = key[3];
	keyCopy[2] = key[2];
	keyCopy[1] = key[1];
	keyCopy[0] = key[0];

	
	/* Set round subkey K(1) */
	roundKeys[3] = keyCopy[9];
	roundKeys[2] = keyCopy[8];
	roundKeys[1] = keyCopy[7];
	roundKeys[0] = keyCopy[6];

	
	/* Set round subkey K(2) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x00;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[7] = keyCopy[9];
	roundKeys[6] = keyCopy[8];
	roundKeys[5] = keyCopy[7];
	roundKeys[4] = keyCopy[6];
	/* Set round subkey K(2) - End */


	/* Set round subkey K(3) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x00;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[11] = keyCopy[9];
	roundKeys[10] = keyCopy[8];
	roundKeys[9] = keyCopy[7];
	roundKeys[8] = keyCopy[6];
	/* Set round subkey K(3) - End */


	/* Set round subkey K(4) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x00;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[15] = keyCopy[9];
	roundKeys[14] = keyCopy[8];
	roundKeys[13] = keyCopy[7];
	roundKeys[12] = keyCopy[6];
	/* Set round subkey K(4) - End */


	/* Set round subkey K(5) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[19] = keyCopy[9];
	roundKeys[18] = keyCopy[8];
	roundKeys[17] = keyCopy[7];
	roundKeys[16] = keyCopy[6];
	/* Set round subkey K(5) - End */


	/* Set round subkey K(6) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[23] = keyCopy[9];
	roundKeys[22] = keyCopy[8];
	roundKeys[21] = keyCopy[7];
	roundKeys[20] = keyCopy[6];
	/* Set round subkey K(6) - End */


	/* Set round subkey K(7) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[27] = keyCopy[9];
	roundKeys[26] = keyCopy[8];
	roundKeys[25] = keyCopy[7];
	roundKeys[24] = keyCopy[6];
	/* Set round subkey K(7) - End */


	/* Set round subkey K(8) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[31] = keyCopy[9];
	roundKeys[30] = keyCopy[8];
	roundKeys[29] = keyCopy[7];
	roundKeys[28] = keyCopy[6];
	/* Set round subkey K(8) - End */


	/* Set round subkey K(9) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[35] = keyCopy[9];
	roundKeys[34] = keyCopy[8];
	roundKeys[33] = keyCopy[7];
	roundKeys[32] = keyCopy[6];
	/* Set round subkey K(9) - End */


	/* Set round subkey K(10) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[39] = keyCopy[9];
	roundKeys[38] = keyCopy[8];
	roundKeys[37] = keyCopy[7];
	roundKeys[36] = keyCopy[6];
	/* Set round subkey K(10) - End */


	/* Set round subkey K(11) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[43] = keyCopy[9];
	roundKeys[42] = keyCopy[8];
	roundKeys[41] = keyCopy[7];
	roundKeys[40] = keyCopy[6];
	/* Set round subkey K(11) - End */


	/* Set round subkey K(12) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[47] = keyCopy[9];
	roundKeys[46] = keyCopy[8];
	roundKeys[45] = keyCopy[7];
	roundKeys[44] = keyCopy[6];
	/* Set round subkey K(12) - End */


	/* Set round subkey K(13) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[51] = keyCopy[9];
	roundKeys[50] = keyCopy[8];
	roundKeys[49] = keyCopy[7];
	roundKeys[48] = keyCopy[6];
	/* Set round subkey K(13) - End */


	/* Set round subkey K(14) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[55] = keyCopy[9];
	roundKeys[54] = keyCopy[8];
	roundKeys[53] = keyCopy[7];
	roundKeys[52] = keyCopy[6];
	/* Set round subkey K(14) - End */


	/* Set round subkey K(15) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[59] = keyCopy[9];
	roundKeys[58] = keyCopy[8];
	roundKeys[57] = keyCopy[7];
	roundKeys[56] = keyCopy[6];
	/* Set round subkey K(15) - End */


	/* Set round subkey K(16) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[63] = keyCopy[9];
	roundKeys[62] = keyCopy[8];
	roundKeys[61] = keyCopy[7];
	roundKeys[60] = keyCopy[6];
	/* Set round subkey K(16) - End */


	/* Set round subkey K(17) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[67] = keyCopy[9];
	roundKeys[66] = keyCopy[8];
	roundKeys[65] = keyCopy[7];
	roundKeys[64] = keyCopy[6];
	/* Set round subkey K(17) - End */


	/* Set round subkey K(18) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[71] = keyCopy[9];
	roundKeys[70] = keyCopy[8];
	roundKeys[69] = keyCopy[7];
	roundKeys[68] = keyCopy[6];
	/* Set round subkey K(18) - End */


	/* Set round subkey K(19) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[75] = keyCopy[9];
	roundKeys[74] = keyCopy[8];
	roundKeys[73] = keyCopy[7];
	roundKeys[72] = keyCopy[6];
	/* Set round subkey K(19) - End */


	/* Set round subkey K(20) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[79] = keyCopy[9];
	roundKeys[78] = keyCopy[8];
	roundKeys[77] = keyCopy[7];
	roundKeys[76] = keyCopy[6];
	/* Set round subkey K(20) - End */

	
	/* Set round subkey K(21) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[83] = keyCopy[9];
	roundKeys[82] = keyCopy[8];
	roundKeys[81] = keyCopy[7];
	roundKeys[80] = keyCopy[6];
	/* Set round subkey K(21) - End */


	/* Set round subkey K(22) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[87] = keyCopy[9];
	roundKeys[86] = keyCopy[8];
	roundKeys[85] = keyCopy[7];
	roundKeys[84] = keyCopy[6];
	/* Set round subkey K(22) - End */


	/* Set round subkey K(23) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[91] = keyCopy[9];
	roundKeys[90] = keyCopy[8];
	roundKeys[89] = keyCopy[7];
	roundKeys[88] = keyCopy[6];
	/* Set round subkey K(23) - End */


	/* Set round subkey K(24) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[95] = keyCopy[9];
	roundKeys[94] = keyCopy[8];
	roundKeys[93] = keyCopy[7];
	roundKeys[92] = keyCopy[6];
	/* Set round subkey K(24) - End */


	/* Set round subkey K(25) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[99] = keyCopy[9];
	roundKeys[98] = keyCopy[8];
	roundKeys[97] = keyCopy[7];
	roundKeys[96] = keyCopy[6];
	/* Set round subkey K(25) - End */


	/* Set round subkey K(26) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[103] = keyCopy[9];
	roundKeys[102] = keyCopy[8];
	roundKeys[101] = keyCopy[7];
	roundKeys[100] = keyCopy[6];
	/* Set round subkey K(26) - End */


	/* Set round subkey K(27) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[107] = keyCopy[9];
	roundKeys[106] = keyCopy[8];
	roundKeys[105] = keyCopy[7];
	roundKeys[104] = keyCopy[6];
	/* Set round subkey K(27) - End */


	/* Set round subkey K(28) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[111] = keyCopy[9];
	roundKeys[110] = keyCopy[8];
	roundKeys[109] = keyCopy[7];
	roundKeys[108] = keyCopy[6];
	/* Set round subkey K(28) - End */


	/* Set round subkey K(29) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[115] = keyCopy[9];
	roundKeys[114] = keyCopy[8];
	roundKeys[113] = keyCopy[7];
	roundKeys[112] = keyCopy[6];
	/* Set round subkey K(29) - End */


	/* Set round subkey K(30) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[119] = keyCopy[9];
	roundKeys[118] = keyCopy[8];
	roundKeys[117] = keyCopy[7];
	roundKeys[116] = keyCopy[6];
	/* Set round subkey K(30) - End */


	/* Set round subkey K(31) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[123] = keyCopy[9];
	roundKeys[122] = keyCopy[8];
	roundKeys[121] = keyCopy[7];
	roundKeys[120] = keyCopy[6];
	/* Set round subkey K(31) - End */


	/* Set round subkey K(32) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[3] = keyCopy[9];
	shiftedKey[2] = keyCopy[8];
	shiftedKey[1] = keyCopy[7];     
	shiftedKey[0] = keyCopy[6];
	    

	keyCopy[9] = (keyCopy[6] << 5) ^ (keyCopy[5] >> 3);
	keyCopy[8] = (keyCopy[5] << 5) ^ (keyCopy[4] >> 3);
	keyCopy[7] = (keyCopy[4] << 5) ^ (keyCopy[3] >> 3);
	keyCopy[6] = (keyCopy[3] << 5) ^ (keyCopy[2] >> 3);
	keyCopy[5] = (keyCopy[2] << 5) ^ (keyCopy[1] >> 3);
	keyCopy[4] = (keyCopy[1] << 5) ^ (keyCopy[0] >> 3);
	keyCopy[3] = (keyCopy[0] << 5) ^ (shiftedKey[3] >> 3);
	keyCopy[2] = (shiftedKey[3]  << 5) ^ (shiftedKey[2] >> 3);
	keyCopy[1] = (shiftedKey[2]  << 5) ^ (shiftedKey[1] >> 3);
	keyCopy[0] = (shiftedKey[1]  << 5) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	roundKeys[127] = keyCopy[9];
	roundKeys[126] = keyCopy[8];
	roundKeys[125] = keyCopy[7];
	roundKeys[124] = keyCopy[6];
	/* Set round subkey K(32) - End */
}
