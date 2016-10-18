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
	

	uint32_t *X = (uint32_t *)x;
	uint32_t *K = (uint32_t *)k;

	uint32_t *Temp = (uint32_t *)temp;


	/* Save a copy of the left half of X */
	Temp[0] = X[1];


	/* Round 1 - Begin */
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[31]);  


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
	X[0] = Temp[0];
	

	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[30]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */ 
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[29]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[28]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[27]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */ 
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[26]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[25]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[24]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[23]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[22]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */ 
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[21]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[20]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[19]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[18]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[17]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[16]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */ 
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[15]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */ 
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[14]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[13]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[12]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[11]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */ 
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[10]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[9]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[8]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[7]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[6]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */ 
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[5]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[4]);  


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
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[3]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[2]);  


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
	/* Save a copy of the left half of X */;
	X[1] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[1]);  


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
	X[0] = Temp[0];
	
	
	/* XOR X left half with the round key: X XOR K(j) */
	Temp[0] = Temp[0] ^ READ_ROUND_KEY_DOUBLE_WORD(K[0]);  


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

	
	X[1] = X[0];
	
	X[0] = Temp[0];
}
