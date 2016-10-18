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
	uint16_t shiftedKey[2];
	uint8_t keyCopy[KEY_SIZE];


	uint16_t *Key = (uint16_t *)key;
	uint16_t *RoundKeys = (uint16_t *)roundKeys;


	uint16_t *KeyCopy = (uint16_t *)keyCopy;

	
	KeyCopy[4] = Key[4];
	KeyCopy[3] = Key[3];
	KeyCopy[2] = Key[2];
	KeyCopy[1] = Key[1];
	KeyCopy[0] = Key[0];

	
	/* Set round subkey K(1) */
	RoundKeys[1] = KeyCopy[4];
	RoundKeys[0] = KeyCopy[3];

	
	/* Set round subkey K(2) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x00;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[3] = KeyCopy[4];
	RoundKeys[2] = KeyCopy[3];
	/* Set round subkey K(2) - End */


	/* Set round subkey K(3) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x00;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[5] = KeyCopy[4];
	RoundKeys[4] = KeyCopy[3];
	/* Set round subkey K(3) - End */


	/* Set round subkey K(4) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x00;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[7] = KeyCopy[4];
	RoundKeys[6] = KeyCopy[3];
	/* Set round subkey K(4) - End */


	/* Set round subkey K(5) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[9] = KeyCopy[4];
	RoundKeys[8] = KeyCopy[3];
	/* Set round subkey K(5) - End */


	/* Set round subkey K(6) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[11] = KeyCopy[4];
	RoundKeys[10] = KeyCopy[3];
	/* Set round subkey K(6) - End */


	/* Set round subkey K(7) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[13] = KeyCopy[4];
	RoundKeys[12] = KeyCopy[3];
	/* Set round subkey K(7) - End */


	/* Set round subkey K(8) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x01;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[15] = KeyCopy[4];
	RoundKeys[14] = KeyCopy[3];
	/* Set round subkey K(8) - End */


	/* Set round subkey K(9) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];;
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[17] = KeyCopy[4];
	RoundKeys[16] = KeyCopy[3];
	/* Set round subkey K(9) - End */


	/* Set round subkey K(10) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[19] = KeyCopy[4];
	RoundKeys[18] = KeyCopy[3];
	/* Set round subkey K(10) - End */


	/* Set round subkey K(11) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[21] = KeyCopy[4];
	RoundKeys[20] = KeyCopy[3];
	/* Set round subkey K(11) - End */


	/* Set round subkey K(12) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x02;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[23] = KeyCopy[4];
	RoundKeys[22] = KeyCopy[3];
	/* Set round subkey K(12) - End */


	/* Set round subkey K(13) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[25] = KeyCopy[4];
	RoundKeys[24] = KeyCopy[3];
	/* Set round subkey K(13) - End */


	/* Set round subkey K(14) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[27] = KeyCopy[4];
	RoundKeys[26] = KeyCopy[3];
	/* Set round subkey K(14) - End */


	/* Set round subkey K(15) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[29] = KeyCopy[4];
	RoundKeys[28] = KeyCopy[3];
	/* Set round subkey K(15) - End */


	/* Set round subkey K(16) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x03;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[31] = KeyCopy[4];
	RoundKeys[30] = KeyCopy[3];
	/* Set round subkey K(16) - End */


	/* Set round subkey K(17) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[33] = KeyCopy[4];
	RoundKeys[32] = KeyCopy[3];
	/* Set round subkey K(17) - End */


	/* Set round subkey K(18) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[35] = KeyCopy[4];
	RoundKeys[34] = KeyCopy[3];
	/* Set round subkey K(18) - End */


	/* Set round subkey K(19) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[37] = KeyCopy[4];
	RoundKeys[36] = KeyCopy[3];
	/* Set round subkey K(19) - End */


	/* Set round subkey K(20) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x04;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[39] = KeyCopy[4];
	RoundKeys[38] = KeyCopy[3];
	/* Set round subkey K(20) - End */

	
	/* Set round subkey K(21) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[41] = KeyCopy[4];
	RoundKeys[40] = KeyCopy[3];
	/* Set round subkey K(21) - End */


	/* Set round subkey K(22) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[43] = KeyCopy[4];
	RoundKeys[42] = KeyCopy[3];
	/* Set round subkey K(22) - End */


	/* Set round subkey K(23) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[45] = KeyCopy[4];
	RoundKeys[44] = KeyCopy[3];
	/* Set round subkey K(23) - End */


	/* Set round subkey K(24) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x05;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[47] = KeyCopy[4];
	RoundKeys[46] = KeyCopy[3];
	/* Set round subkey K(24) - End */


	/* Set round subkey K(25) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[49] = KeyCopy[4];
	RoundKeys[48] = KeyCopy[3];
	/* Set round subkey K(25) - End */


	/* Set round subkey K(26) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[51] = KeyCopy[4];
	RoundKeys[50] = KeyCopy[3];
	/* Set round subkey K(26) - End */


	/* Set round subkey K(27) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[53] = KeyCopy[4];
	RoundKeys[52] = KeyCopy[3];
	/* Set round subkey K(27) - End */


	/* Set round subkey K(28) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x06;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[55] = KeyCopy[4];
	RoundKeys[54] = KeyCopy[3];
	/* Set round subkey K(28) - End */


	/* Set round subkey K(29) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0x00;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[57] = KeyCopy[4];
	RoundKeys[56] = KeyCopy[3];
	/* Set round subkey K(29) - End */


	/* Set round subkey K(30) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0x40;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[59] = KeyCopy[4];
	RoundKeys[58] = KeyCopy[3];
	/* Set round subkey K(30) - End */


	/* Set round subkey K(31) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0x80;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[61] = KeyCopy[4];
	RoundKeys[60] = KeyCopy[3];
	/* Set round subkey K(31) - End */


	/* Set round subkey K(32) - Begin */
	/* (a) K <<< 29 */
	shiftedKey[1] = KeyCopy[4];     
	shiftedKey[0] = KeyCopy[3];
	    

	KeyCopy[4] = (KeyCopy[3] << 13) ^ (KeyCopy[2] >> 3);
	KeyCopy[3] = (KeyCopy[2] << 13) ^ (KeyCopy[1] >> 3);
	KeyCopy[2] = (KeyCopy[1] << 13) ^ (KeyCopy[0] >> 3);
	KeyCopy[1] = (KeyCopy[0] << 13) ^ (shiftedKey[1] >> 3);
	KeyCopy[0] = (shiftedKey[1] << 13) ^ (shiftedKey[0] >> 3);

	
	/* (b) S-boxes */
	keyCopy[9] = (READ_SBOX_BYTE(S9[keyCopy[9] >> 4]) << 4) ^ READ_SBOX_BYTE(S8[(keyCopy[9] & 0x0F)]);

	
	/* (c) XOR */
	keyCopy[6] = keyCopy[6] ^ 0x07;
	keyCopy[5] = keyCopy[5] ^ 0xC0;

	
	/* (d) Set the round subkey K(i+1) */
	RoundKeys[63] = KeyCopy[4];
	RoundKeys[62] = KeyCopy[3];
	/* Set round subkey K(32) - End */
}
