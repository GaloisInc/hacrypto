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
#include "round_function.h"


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	int8_t temp0;
	
	
	/* Final Transformation */
	temp0 = block[7];
	block[7] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[7]); 
	block[6] = block[5]; 
	block[5] = block[4] - READ_ROUND_KEY_BYTE(roundKeys[6]);
	block[4] = block[3]; 
	block[3] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[5]);
	block[2] = block[1]; 
	block[1] = block[0] - READ_ROUND_KEY_BYTE(roundKeys[4]);
	block[0] = temp0;
	

	/* Round 32 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[132]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[133]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[134]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[135]));
	/* Round 32 - End */



	/* Round 31 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[128]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[129]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[130]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[131]));
	/* Round 31 - End */


	/* Round 30 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[124]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[125]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[126]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[127]));
	/* Round 30 - End */


	/* Round 29 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[120]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[121]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[122]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[123]));
	/* Round 29 - End */


	/* Round 28 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[116]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[117]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[118]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[119]));
	/* Round 28 - End */


	/* Round 27 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[112]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[113]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[114]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[115]));
	/* Round 27 - End */


	/* Round 26 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[108]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[109]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[110]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[111]));
	/* Round 26 - End */


	/* Round 25 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[104]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[105]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[106]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[107]));
	/* Round 25 - End */


	/* Round 24 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[100]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[101]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[102]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[103]));
	/* Round 24 - End */


	/* Round 23 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[96]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[97]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[98]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[99]));
	/* Round 23 - End */


	/* Round 22 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[92]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[93]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[94]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[95]));
	/* Round 22 - End */


	/* Round 21 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[88]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[89]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[90]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[91]));
	/* Round 21 - End */


	/* Round 20 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[84]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[85]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[86]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[87]));
	/* Round 20 - End */


	/* Round 19 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[80]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[81]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[82]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[83]));
	/* Round 19 - End */


	/* Round 18 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[76]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[77]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[78]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[79]));
	/* Round 18 - End */


	/* Round 17 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[72]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[73]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[74]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[75]));
	/* Round 17 - End */


	/* Round 16 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[68]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[69]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[70]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[71]));
	/* Round 16 - End */


	/* Round 15 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[64]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[65]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[66]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[67]));
	/* Round 15 - End */


	/* Round 14 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[60]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[61]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[62]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[63]));
	/* Round 14 - End */


	/* Round 13 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[56]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[57]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[58]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[59]));
	/* Round 13 - End */


	/* Round 12 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[52]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[53]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[54]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[55]));
	/* Round 12 - End */


	/* Round 11 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[48]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[49]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[50]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[51]));
	/* Round 11 - End */


	/* Round 10 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[44]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[45]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[46]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[47]));
	/* Round 10 - End */


	/* Round 9 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[40]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[41]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[42]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[43]));
	/* Round 9 - End */


	/* Round 8 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[36]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[37]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[38]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[39]));
	/* Round 8 - End */
	

	/* Round 7 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[32]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[33]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[34]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[35]));
	/* Round 7 - End */


	/* Round 6 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[28]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[29]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[30]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[31]));
	/* Round 6 - End */


	/* Round 5 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[24]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[25]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[26]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[27]));
	/* Round 5 - End */


	/* Round 4 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[20]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[21]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[22]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[23]));
	/* Round 4 - End */
	

	/* Round 3 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[16]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[17]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[18]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[19]));
	/* Round 3 - End */


	/* Round 2 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[12]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[13]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[14]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[15]));
	/* Round 2 - End */


	/* Round 1 - Begin */
	temp0 = block[0];

	block[0] = block[1];
	block[1] = block[2] - (F1(block[0]) ^ READ_ROUND_KEY_BYTE(roundKeys[8]));
	block[2] = block[3];
	block[3] = block[4] ^ (F0(block[2]) + READ_ROUND_KEY_BYTE(roundKeys[9]));	
	block[4] = block[5];
	block[5] = block[6] - (F1(block[4]) ^ READ_ROUND_KEY_BYTE(roundKeys[10]));
	block[6] = block[7];	
	block[7] = temp0 ^ (F0(block[6]) + READ_ROUND_KEY_BYTE(roundKeys[11]));
	/* Round 1 - End */


	/* Initial Transformation */
	block[0] = block[0] - READ_ROUND_KEY_BYTE(roundKeys[0]);
	block[2] = block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[1]); 
	block[4] = block[4] - READ_ROUND_KEY_BYTE(roundKeys[2]);
	block[6] = block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[3]);
}
