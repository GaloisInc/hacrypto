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

#ifndef SHARED_FUNCTIONS_H
#define SHARED_FUNCTIONS_H


/* 
 * 
 * S-Layer
 * ... block - the data block to be processed
 *
 */
void SLayer(uint8_t *block);

/* 
 * 
 * Inverse S-Layer 
 * ... block - the data block to be processed
 *
 */
void InverseSLayer(uint8_t *block);

/* 
 * 
 * Multiplication with the (16 bits, 16 bits) matrix M0 
 * ... block - the data block to be processed
 *
 */
void M0Multiplication(uint8_t *block);

/* 
 * 
 * Multiplication with the (16 bits, 16 bits) matrix M1 
 * ... block - the data block to be processed
 *
 */
void M1Multiplication(uint8_t *block);

/* 
 * 
 * Application of matrix SR (shift rows) 
 * ... block - the data block to be processed
 *
 */
void SR(uint8_t *block);

/* 
 * 
 * Inverse application of matrix SR (shift rows)  
 * ... block - the data block to be processed
 *
 */
void InverseSR(uint8_t *block);

/* 
 * 
 * Add round key and round constant the data block (state) 
 * ... block - the data block to be processed
 * ... roundKey - the round key to be added to the state
 * ... roundConstant - the round constant to be added to the state
 *
 */
void AddRoundRoundKeyAndRoundConstant(uint8_t *block, uint8_t *roundKey, const uint8_t *roundConstant);

/* 
 * 
 * Cipher forward round 
 * ... block - the data block to be processed
 * ... roundKey - the round key to be used in the forward round
 * ... roundConstant - the round constant to be used in the forward round
 *
 */
void Round(uint8_t *block, uint8_t *roundKey, const uint8_t *roundConstant);

/* 
 * 
 * Cipher backward round 
 * ... block - the data block to be processed
 * ... roundKey - the round key to be used in the backward round
 * ... roundConstant - the round constant to be used backward in the round
 *
 */
void InverseRound(uint8_t *block, uint8_t *roundKey, const uint8_t *roundConstant);

/* 
 * 
 * Cipher whitening 
 * ... block - the data block to be processed
 * ... roundKey - the round key to be added to the state
 *
 */
void Whitening(uint8_t *block, uint8_t *roundKey);

#endif /* SHARED_FUNCTIONS_H */
