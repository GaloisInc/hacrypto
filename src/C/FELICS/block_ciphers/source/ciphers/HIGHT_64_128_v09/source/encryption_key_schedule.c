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
	/* Whitening Key Generation */
	roundKeys[0] = key[12];
	roundKeys[1] = key[13];
	roundKeys[2] = key[14];
	roundKeys[3] = key[15];

	roundKeys[4] = key[0];
	roundKeys[5] = key[1];
	roundKeys[6] = key[2];
	roundKeys[7] = key[3];


	/* Subkey Generation */
	roundKeys[8] = key[0] + READ_DELTA_BYTE(delta[0]);
	roundKeys[16] = key[8] + READ_DELTA_BYTE(delta[8]);

	roundKeys[9] = key[1] + READ_DELTA_BYTE(delta[1]);
	roundKeys[17] = key[9] + READ_DELTA_BYTE(delta[9]);

	roundKeys[10] = key[2] + READ_DELTA_BYTE(delta[2]);
	roundKeys[18] = key[10] + READ_DELTA_BYTE(delta[10]);

	roundKeys[11] = key[3] + READ_DELTA_BYTE(delta[3]);
	roundKeys[19] = key[11] + READ_DELTA_BYTE(delta[11]);

	roundKeys[12] = key[4] + READ_DELTA_BYTE(delta[4]);
	roundKeys[20] = key[12] + READ_DELTA_BYTE(delta[12]);

	roundKeys[13] = key[5] + READ_DELTA_BYTE(delta[5]);
	roundKeys[21] = key[13] + READ_DELTA_BYTE(delta[13]);

	roundKeys[14] = key[6] + READ_DELTA_BYTE(delta[6]);
	roundKeys[22] = key[14] + READ_DELTA_BYTE(delta[14]);

	roundKeys[15] = key[7] + READ_DELTA_BYTE(delta[7]);
	roundKeys[23] = key[15] + READ_DELTA_BYTE(delta[15]);

	
	roundKeys[24] = key[7] + READ_DELTA_BYTE(delta[16]);
	roundKeys[32] = key[15] + READ_DELTA_BYTE(delta[24]);

	roundKeys[25] = key[0] + READ_DELTA_BYTE(delta[17]);
	roundKeys[33] = key[8] + READ_DELTA_BYTE(delta[25]);

	roundKeys[26] = key[1] + READ_DELTA_BYTE(delta[18]);
	roundKeys[34] = key[9] + READ_DELTA_BYTE(delta[26]);

	roundKeys[27] = key[2] + READ_DELTA_BYTE(delta[19]);
	roundKeys[35] = key[10] + READ_DELTA_BYTE(delta[27]);

	roundKeys[28] = key[3] + READ_DELTA_BYTE(delta[20]);
	roundKeys[36] = key[11] + READ_DELTA_BYTE(delta[28]);

	roundKeys[29] = key[4] + READ_DELTA_BYTE(delta[21]);
	roundKeys[37] = key[12] + READ_DELTA_BYTE(delta[29]);

	roundKeys[30] = key[5] + READ_DELTA_BYTE(delta[22]);
	roundKeys[38] = key[13] + READ_DELTA_BYTE(delta[30]);

	roundKeys[31] = key[6] + READ_DELTA_BYTE(delta[23]);
	roundKeys[39] = key[14] + READ_DELTA_BYTE(delta[31]);


	roundKeys[40] = key[6] + READ_DELTA_BYTE(delta[32]);
	roundKeys[48] = key[14] + READ_DELTA_BYTE(delta[40]);

	roundKeys[41] = key[7] + READ_DELTA_BYTE(delta[33]);
	roundKeys[49] = key[15] + READ_DELTA_BYTE(delta[41]);

	roundKeys[42] = key[0] + READ_DELTA_BYTE(delta[34]);
	roundKeys[50] = key[8] + READ_DELTA_BYTE(delta[42]);

	roundKeys[43] = key[1] + READ_DELTA_BYTE(delta[35]);
	roundKeys[51] = key[9] + READ_DELTA_BYTE(delta[43]);

	roundKeys[44] = key[2] + READ_DELTA_BYTE(delta[36]);
	roundKeys[52] = key[10] + READ_DELTA_BYTE(delta[44]);

	roundKeys[45] = key[3] + READ_DELTA_BYTE(delta[37]);
	roundKeys[53] = key[11] + READ_DELTA_BYTE(delta[45]);

	roundKeys[46] = key[4] + READ_DELTA_BYTE(delta[38]);
	roundKeys[54] = key[12] + READ_DELTA_BYTE(delta[46]);

	roundKeys[47] = key[5] + READ_DELTA_BYTE(delta[39]);
	roundKeys[55] = key[13] + READ_DELTA_BYTE(delta[47]);


	roundKeys[56] = key[5] + READ_DELTA_BYTE(delta[48]);
	roundKeys[64] = key[13] + READ_DELTA_BYTE(delta[56]);

	roundKeys[57] = key[6] + READ_DELTA_BYTE(delta[49]);
	roundKeys[65] = key[14] + READ_DELTA_BYTE(delta[57]);

	roundKeys[58] = key[7] + READ_DELTA_BYTE(delta[50]);
	roundKeys[66] = key[15] + READ_DELTA_BYTE(delta[58]);

	roundKeys[59] = key[0] + READ_DELTA_BYTE(delta[51]);
	roundKeys[67] = key[8] + READ_DELTA_BYTE(delta[59]);

	roundKeys[60] = key[1] + READ_DELTA_BYTE(delta[52]);
	roundKeys[68] = key[9] + READ_DELTA_BYTE(delta[60]);

	roundKeys[61] = key[2] + READ_DELTA_BYTE(delta[53]);
	roundKeys[69] = key[10] + READ_DELTA_BYTE(delta[61]);

	roundKeys[62] = key[3] + READ_DELTA_BYTE(delta[54]);
	roundKeys[70] = key[11] + READ_DELTA_BYTE(delta[62]);

	roundKeys[63] = key[4] + READ_DELTA_BYTE(delta[55]);
	roundKeys[71] = key[12] + READ_DELTA_BYTE(delta[63]);


	roundKeys[72] = key[4] + READ_DELTA_BYTE(delta[64]);
	roundKeys[80] = key[12] + READ_DELTA_BYTE(delta[72]);

	roundKeys[73] = key[5] + READ_DELTA_BYTE(delta[65]);
	roundKeys[81] = key[13] + READ_DELTA_BYTE(delta[73]);

	roundKeys[74] = key[6] + READ_DELTA_BYTE(delta[66]);
	roundKeys[82] = key[14] + READ_DELTA_BYTE(delta[74]);

	roundKeys[75] = key[7] + READ_DELTA_BYTE(delta[67]);
	roundKeys[83] = key[15] + READ_DELTA_BYTE(delta[75]);

	roundKeys[76] = key[0] + READ_DELTA_BYTE(delta[68]);
	roundKeys[84] = key[8] + READ_DELTA_BYTE(delta[76]);

	roundKeys[77] = key[1] + READ_DELTA_BYTE(delta[69]);
	roundKeys[85] = key[9] + READ_DELTA_BYTE(delta[77]);

	roundKeys[78] = key[2] + READ_DELTA_BYTE(delta[70]);
	roundKeys[86] = key[10] + READ_DELTA_BYTE(delta[78]);

	roundKeys[79] = key[3] + READ_DELTA_BYTE(delta[71]);
	roundKeys[87] = key[11] + READ_DELTA_BYTE(delta[79]);


	roundKeys[88] = key[3] + READ_DELTA_BYTE(delta[80]);
	roundKeys[96] = key[11] + READ_DELTA_BYTE(delta[88]);

	roundKeys[89] = key[4] + READ_DELTA_BYTE(delta[81]);
	roundKeys[97] = key[12] + READ_DELTA_BYTE(delta[89]);

	roundKeys[90] = key[5] + READ_DELTA_BYTE(delta[82]);
	roundKeys[98] = key[13] + READ_DELTA_BYTE(delta[90]);

	roundKeys[91] = key[6] + READ_DELTA_BYTE(delta[83]);
	roundKeys[99] = key[14] + READ_DELTA_BYTE(delta[91]);

	roundKeys[92] = key[7] + READ_DELTA_BYTE(delta[84]);
	roundKeys[100] = key[15] + READ_DELTA_BYTE(delta[92]);

	roundKeys[93] = key[0] + READ_DELTA_BYTE(delta[85]);
	roundKeys[101] = key[8] + READ_DELTA_BYTE(delta[93]);

	roundKeys[94] = key[1] + READ_DELTA_BYTE(delta[86]);
	roundKeys[102] = key[9] + READ_DELTA_BYTE(delta[94]);

	roundKeys[95] = key[2] + READ_DELTA_BYTE(delta[87]);
	roundKeys[103] = key[10] + READ_DELTA_BYTE(delta[95]);


	roundKeys[104] = key[2] + READ_DELTA_BYTE(delta[96]);
	roundKeys[112] = key[10] + READ_DELTA_BYTE(delta[104]);

	roundKeys[105] = key[3] + READ_DELTA_BYTE(delta[97]);
	roundKeys[113] = key[11] + READ_DELTA_BYTE(delta[105]);

	roundKeys[106] = key[4] + READ_DELTA_BYTE(delta[98]);
	roundKeys[114] = key[12] + READ_DELTA_BYTE(delta[106]);

	roundKeys[107] = key[5] + READ_DELTA_BYTE(delta[99]);
	roundKeys[115] = key[13] + READ_DELTA_BYTE(delta[107]);

	roundKeys[108] = key[6] + READ_DELTA_BYTE(delta[100]);
	roundKeys[116] = key[14] + READ_DELTA_BYTE(delta[108]);

	roundKeys[109] = key[7] + READ_DELTA_BYTE(delta[101]);
	roundKeys[117] = key[15] + READ_DELTA_BYTE(delta[109]);

	roundKeys[110] = key[0] + READ_DELTA_BYTE(delta[102]);
	roundKeys[118] = key[8] + READ_DELTA_BYTE(delta[110]);

	roundKeys[111] = key[1] + READ_DELTA_BYTE(delta[103]);
	roundKeys[119] = key[9] + READ_DELTA_BYTE(delta[111]);


	roundKeys[120] = key[1] + READ_DELTA_BYTE(delta[112]);
	roundKeys[128] = key[9] + READ_DELTA_BYTE(delta[120]);

	roundKeys[121] = key[2] + READ_DELTA_BYTE(delta[113]);
	roundKeys[129] = key[10] + READ_DELTA_BYTE(delta[121]);

	roundKeys[122] = key[3] + READ_DELTA_BYTE(delta[114]);
	roundKeys[130] = key[11] + READ_DELTA_BYTE(delta[122]);

	roundKeys[123] = key[4] + READ_DELTA_BYTE(delta[115]);
	roundKeys[131] = key[12] + READ_DELTA_BYTE(delta[123]);

	roundKeys[124] = key[5] + READ_DELTA_BYTE(delta[116]);
	roundKeys[132] = key[13] + READ_DELTA_BYTE(delta[124]);

	roundKeys[125] = key[6] + READ_DELTA_BYTE(delta[117]);
	roundKeys[133] = key[14] + READ_DELTA_BYTE(delta[125]);

	roundKeys[126] = key[7] + READ_DELTA_BYTE(delta[118]);
	roundKeys[134] = key[15] + READ_DELTA_BYTE(delta[126]);

	roundKeys[127] = key[0] + READ_DELTA_BYTE(delta[119]);
	roundKeys[135] = key[8] + READ_DELTA_BYTE(delta[127]);
}
