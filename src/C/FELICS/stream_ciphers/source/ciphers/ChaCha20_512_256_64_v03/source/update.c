/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 University of Luxembourg
 *
 * Written in 2016 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#include "update.h"
#include "constants.h"
#include "rot32.h"


void Update(uint8_t *state, uint8_t *keyStream)
{
	uint32_t *State = (uint32_t *)state;
	uint32_t *KeyStream = (uint32_t *)keyStream;
	

	KeyStream[0] = State[0];
	KeyStream[1] = State[1];
	KeyStream[2] = State[2];
	KeyStream[3] = State[3];

	KeyStream[4] = State[4];
	KeyStream[5] = State[5];
	KeyStream[6] = State[6];
	KeyStream[7] = State[7];

	KeyStream[8] = State[8];
	KeyStream[9] = State[9];
	KeyStream[10] = State[10];
	KeyStream[11] = State[11];

	KeyStream[12] = State[12];
	KeyStream[13] = State[13];
	KeyStream[14] = State[14];
	KeyStream[15] = State[15];
	

	/* Round 1 - begin */
	
	/* Quarter round - 1 */
	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l16(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l12(State[4]);

	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l8(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l7(State[4]);

	/* Quarter round - 2 */
	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l16(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l12(State[5]);

	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l8(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 3 */
	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l16(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l12(State[6]);

	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l8(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 4 */
	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l16(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l12(State[7]);

	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l8(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l7(State[7]);

	/* Round 1 - end */


	/* Round 2 - begin */

	/* Quarter round - 1 */
	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l16(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l12(State[5]);

	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l8(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 2 */
	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l16(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l12(State[6]);

	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l8(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 3 */
	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l16(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l12(State[7]);

	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l8(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l7(State[7]);

	/* Quarter round - 4 */
	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l16(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l12(State[4]);

	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l8(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l7(State[4]);

	/* Round 2 - end */


	/* Round 3 - begin */
	
	/* Quarter round - 1 */
	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l16(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l12(State[4]);

	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l8(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l7(State[4]);

	/* Quarter round - 2 */
	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l16(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l12(State[5]);

	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l8(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 3 */
	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l16(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l12(State[6]);

	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l8(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 4 */
	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l16(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l12(State[7]);

	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l8(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l7(State[7]);

	/* Round 3 - end */


	/* Round 4 - begin */

	/* Quarter round - 1 */
	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l16(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l12(State[5]);

	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l8(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 2 */
	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l16(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l12(State[6]);

	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l8(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 3 */
	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l16(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l12(State[7]);

	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l8(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l7(State[7]);

	/* Quarter round - 4 */
	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l16(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l12(State[4]);

	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l8(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l7(State[4]);

	/* Round 4 - end */


	/* Round 5 - begin */
	
	/* Quarter round - 1 */
	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l16(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l12(State[4]);

	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l8(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l7(State[4]);

	/* Quarter round - 2 */
	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l16(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l12(State[5]);

	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l8(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 3 */
	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l16(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l12(State[6]);

	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l8(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 4 */
	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l16(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l12(State[7]);

	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l8(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l7(State[7]);

	/* Round 5 - end */


	/* Round 6 - begin */

	/* Quarter round - 1 */
	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l16(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l12(State[5]);

	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l8(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 2 */
	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l16(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l12(State[6]);

	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l8(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 3 */
	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l16(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l12(State[7]);

	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l8(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l7(State[7]);

	/* Quarter round - 4 */
	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l16(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l12(State[4]);

	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l8(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l7(State[4]);

	/* Round 6 - end */


	/* Round 7 - begin */
	
	/* Quarter round - 1 */
	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l16(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l12(State[4]);

	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l8(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l7(State[4]);

	/* Quarter round - 2 */
	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l16(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l12(State[5]);

	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l8(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 3 */
	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l16(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l12(State[6]);

	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l8(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 4 */
	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l16(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l12(State[7]);

	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l8(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l7(State[7]);

	/* Round 7 - end */


	/* Round 8 - begin */

	/* Quarter round - 1 */
	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l16(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l12(State[5]);

	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l8(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 2 */
	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l16(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l12(State[6]);

	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l8(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 3 */
	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l16(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l12(State[7]);

	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l8(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l7(State[7]);

	/* Quarter round - 4 */
	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l16(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l12(State[4]);

	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l8(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l7(State[4]);

	/* Round 8 - end */


	/* Round 9 - begin */
	
	/* Quarter round - 1 */
	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l16(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l12(State[4]);

	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l8(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l7(State[4]);

	/* Quarter round - 2 */
	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l16(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l12(State[5]);

	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l8(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 3 */
	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l16(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l12(State[6]);

	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l8(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 4 */
	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l16(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l12(State[7]);

	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l8(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l7(State[7]);

	/* Round 9 - end */


	/* Round 10 - begin */

	/* Quarter round - 1 */
	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l16(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l12(State[5]);

	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l8(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 2 */
	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l16(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l12(State[6]);

	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l8(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 3 */
	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l16(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l12(State[7]);

	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l8(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l7(State[7]);

	/* Quarter round - 4 */
	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l16(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l12(State[4]);

	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l8(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l7(State[4]);

	/* Round 10 - end */


	/* Round 11 - begin */
	
	/* Quarter round - 1 */
	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l16(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l12(State[4]);

	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l8(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l7(State[4]);

	/* Quarter round - 2 */
	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l16(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l12(State[5]);

	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l8(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 3 */
	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l16(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l12(State[6]);

	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l8(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 4 */
	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l16(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l12(State[7]);

	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l8(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l7(State[7]);

	/* Round 11 - end */


	/* Round 12 - begin */

	/* Quarter round - 1 */
	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l16(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l12(State[5]);

	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l8(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 2 */
	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l16(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l12(State[6]);

	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l8(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 3 */
	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l16(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l12(State[7]);

	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l8(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l7(State[7]);

	/* Quarter round - 4 */
	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l16(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l12(State[4]);

	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l8(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l7(State[4]);

	/* Round 12 - end */


	/* Round 13 - begin */
	
	/* Quarter round - 1 */
	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l16(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l12(State[4]);

	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l8(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l7(State[4]);

	/* Quarter round - 2 */
	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l16(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l12(State[5]);

	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l8(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 3 */
	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l16(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l12(State[6]);

	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l8(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 4 */
	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l16(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l12(State[7]);

	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l8(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l7(State[7]);

	/* Round 13 - end */


	/* Round 14 - begin */

	/* Quarter round - 1 */
	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l16(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l12(State[5]);

	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l8(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 2 */
	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l16(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l12(State[6]);

	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l8(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 3 */
	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l16(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l12(State[7]);

	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l8(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l7(State[7]);

	/* Quarter round - 4 */
	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l16(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l12(State[4]);

	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l8(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l7(State[4]);

	/* Round 14 - end */


	/* Round 15 - begin */
	
	/* Quarter round - 1 */
	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l16(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l12(State[4]);

	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l8(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l7(State[4]);

	/* Quarter round - 2 */
	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l16(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l12(State[5]);

	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l8(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 3 */
	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l16(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l12(State[6]);

	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l8(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 4 */
	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l16(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l12(State[7]);

	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l8(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l7(State[7]);

	/* Round 15 - end */


	/* Round 16 - begin */

	/* Quarter round - 1 */
	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l16(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l12(State[5]);

	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l8(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 2 */
	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l16(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l12(State[6]);

	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l8(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 3 */
	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l16(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l12(State[7]);

	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l8(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l7(State[7]);

	/* Quarter round - 4 */
	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l16(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l12(State[4]);

	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l8(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l7(State[4]);

	/* Round 16 - end */


	/* Round 17 - begin */
	
	/* Quarter round - 1 */
	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l16(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l12(State[4]);

	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l8(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l7(State[4]);

	/* Quarter round - 2 */
	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l16(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l12(State[5]);

	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l8(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 3 */
	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l16(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l12(State[6]);

	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l8(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 4 */
	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l16(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l12(State[7]);

	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l8(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l7(State[7]);

	/* Round 17 - end */


	/* Round 18 - begin */

	/* Quarter round - 1 */
	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l16(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l12(State[5]);

	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l8(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 2 */
	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l16(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l12(State[6]);

	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l8(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 3 */
	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l16(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l12(State[7]);

	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l8(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l7(State[7]);

	/* Quarter round - 4 */
	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l16(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l12(State[4]);

	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l8(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l7(State[4]);

	/* Round 18 - end */


	/* Round 19 - begin */
	
	/* Quarter round - 1 */
	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l16(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l12(State[4]);

	State[0] += State[4];
	State[12] ^= State[0];
	State[12] = rot32l8(State[12]);

	State[8] += State[12];
	State[4] ^= State[8];
	State[4] = rot32l7(State[4]);

	/* Quarter round - 2 */
	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l16(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l12(State[5]);

	State[1] += State[5];
	State[13] ^= State[1];
	State[13] = rot32l8(State[13]);

	State[9] += State[13];
	State[5] ^= State[9];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 3 */
	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l16(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l12(State[6]);

	State[2] += State[6];
	State[14] ^= State[2];
	State[14] = rot32l8(State[14]);

	State[10] += State[14];
	State[6] ^= State[10];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 4 */
	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l16(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l12(State[7]);

	State[3] += State[7];
	State[15] ^= State[3];
	State[15] = rot32l8(State[15]);

	State[11] += State[15];
	State[7] ^= State[11];
	State[7] = rot32l7(State[7]);

	/* Round 19 - end */


	/* Round 20 - begin */

	/* Quarter round - 1 */
	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l16(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l12(State[5]);

	State[0] += State[5];
	State[15] ^= State[0];
	State[15] = rot32l8(State[15]);

	State[10] += State[15];
	State[5] ^= State[10];
	State[5] = rot32l7(State[5]);

	/* Quarter round - 2 */
	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l16(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l12(State[6]);

	State[1] += State[6];
	State[12] ^= State[1];
	State[12] = rot32l8(State[12]);

	State[11] += State[12];
	State[6] ^= State[11];
	State[6] = rot32l7(State[6]);

	/* Quarter round - 3 */
	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l16(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l12(State[7]);

	State[2] += State[7];
	State[13] ^= State[2];
	State[13] = rot32l8(State[13]);

	State[8] += State[13];
	State[7] ^= State[8];
	State[7] = rot32l7(State[7]);

	/* Quarter round - 4 */
	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l16(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l12(State[4]);

	State[3] += State[4];
	State[14] ^= State[3];
	State[14] = rot32l8(State[14]);

	State[9] += State[14];
	State[4] ^= State[9];
	State[4] = rot32l7(State[4]);

	/* Round 20 - end */


	KeyStream[0] += State[0];
	KeyStream[1] += State[1];
	KeyStream[2] += State[2];
	KeyStream[3] += State[3];

	KeyStream[4] += State[4];
	KeyStream[5] += State[5];
	KeyStream[6] += State[6];
	KeyStream[7] += State[7];

	KeyStream[8] += State[8];
	KeyStream[9] += State[9];
	KeyStream[10] += State[10];
	KeyStream[11] += State[11];

	KeyStream[12] += State[12];
	KeyStream[13] += State[13];
	KeyStream[14] += State[14];
	KeyStream[15] += State[15];


	State[12] += 1;
    if(!State[12]) 
	{
		State[13] += 1;
	}
}
