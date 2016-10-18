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
	uint8_t temp[4];
	uint8_t p[4];


	uint8_t *x = block;
	uint8_t *k = roundKeys;
	

	/* Save a copy of the left half of X */
	temp[3] = x[7];
	temp[2] = x[6];
	temp[1] = x[5];
	temp[0] = x[4];


	/* Round 1 - Begin */
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[127]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[126]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[125]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[124]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 1 - End */

	/* Round 2 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	

	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[123]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[122]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[121]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[120]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 2 - End */


	/* Round 3 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[119]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[118]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[117]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[116]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 3 - End */

	/* Round 4 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[115]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[114]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[113]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[112]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 4 - End */


	/* Round 5 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[111]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[110]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[109]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[108]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 5 - End */

	/* Round 6 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[107]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[106]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[105]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[104]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 6 - End */


	/* Round 7 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[103]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[102]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[101]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[100]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 7 - End */

	/* Round 8 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[99]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[98]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[97]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[96]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 8 - End */


	/* Round 9 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[95]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[94]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[93]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[92]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 9 - End */

	/* Round 10 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[91]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[90]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[89]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[88]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 10 - End */


	/* Round 11 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[87]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[86]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[85]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[84]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 11 - End */

	/* Round 12 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[83]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[82]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[81]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[80]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 12 - End */


	/* Round 13 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[79]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[78]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[77]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[76]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 13 - End */

	/* Round 14 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[75]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[74]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[73]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[72]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 14 - End */

	
	/* Round 15 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[71]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[70]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[69]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[68]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 15 - End */

	/* Round 16 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[67]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[66]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[65]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[64]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 16 - End */

	
	/* Round 17 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[63]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[62]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[61]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[60]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 17 - End */

	/* Round 18 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[59]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[58]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[57]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[56]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 18 - End */


	/* Round 19 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[55]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[54]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[53]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[52]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 19 - End */

	/* Round 20 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[51]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[50]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[49]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[48]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 20 - End */


	/* Round 21 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[47]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[46]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[45]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[44]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 21 - End */

	/* Round 22 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[43]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[42]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[41]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[40]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 22 - End */


	/* Round 23 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[39]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[38]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[37]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[36]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 23 - End */

	/* Round 24 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[35]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[34]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[33]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[32]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 24 - End */

	
	/* Round 25 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[31]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[30]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[29]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[28]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 25 - End */

	/* Round 26 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[27]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[26]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[25]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[24]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 26 - End */


	/* Round 27 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[23]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[22]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[21]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[20]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 27 - End */

	/* Round 28 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[19]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[18]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[17]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[16]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 28 - End */
	
	
	/* Round 29 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[15]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[14]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[13]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[12]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 29 - End */

	/* Round 30 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[11]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[10]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[9]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[8]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 30 - End */


	/* Round 31 - Begin */
	/* Save a copy of the left half of X */
	x[7] = temp[3];
	x[6] = temp[2];
	x[5] = temp[1];
	x[4] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[7]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[6]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[5]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[4]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[0] ^ p[0];
	temp[2] = x[3] ^ p[3]; 
	temp[1] = x[2] ^ p[2];
	temp[0] = x[1] ^ p[1];
	/* Round 31 - End */

	/* Round 32 - Begin */
	/* Save a copy of the left half of X */
	x[3] = temp[3];
	x[2] = temp[2];
	x[1] = temp[1];
	x[0] = temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	temp[3] = temp[3] ^ READ_ROUND_KEY_BYTE(k[3]); 
	temp[2] = temp[2] ^ READ_ROUND_KEY_BYTE(k[2]); 
	temp[1] = temp[1] ^ READ_ROUND_KEY_BYTE(k[1]); 
	temp[0] = temp[0] ^ READ_ROUND_KEY_BYTE(k[0]);  


	/* (2) Confusion function S: S(X XOR K(j)) */
	temp[3] = (READ_SBOX_BYTE(S7[temp[3] >> 4]) << 4) ^ READ_SBOX_BYTE(S6[temp[3] & 0x0F]); 
	temp[2] = (READ_SBOX_BYTE(S5[temp[2] >> 4]) << 4) ^ READ_SBOX_BYTE(S4[temp[2] & 0x0F]);
	temp[1] = (READ_SBOX_BYTE(S3[temp[1] >> 4]) << 4) ^ READ_SBOX_BYTE(S2[temp[1] & 0x0F]);
	temp[0] = (READ_SBOX_BYTE(S1[temp[0] >> 4]) << 4) ^ READ_SBOX_BYTE(S0[temp[0] & 0x0F]);
	 
	
	/* (3) Diffusion function P: P(S(X XOR K(j))) */
	p[3] = (temp[3] << 4) ^ (temp[2] & 0x0F);
	p[2] = (temp[3] & 0xF0) ^ (temp[2] >> 4);
	p[1] = (temp[1] << 4) ^ (temp[0] & 0x0F);
	p[0] = (temp[1] & 0xF0) ^ (temp[0] >> 4);
	

	/* F(X(j+1), K(j+1)) XOR X(j+2)) >>> 8) */  
	temp[3] = x[4] ^ p[0];
	temp[2] = x[7] ^ p[3]; 
	temp[1] = x[6] ^ p[2];
	temp[0] = x[5] ^ p[1];
	/* Round 32 - End */


	block[7] = x[3];
	block[6] = x[2];
	block[5] = x[1];
	block[4] = x[0];

	block[3] = temp[3];
	block[2] = temp[2];
	block[1] = temp[1];
	block[0] = temp[0];
}
