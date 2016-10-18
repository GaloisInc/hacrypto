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

#ifndef ROUND_FUNCTION_H
#define ROUND_FUNCTION_H


/*
 *
 * Cipher round function F
 * ... x - round function input
 * ... k - round key
 * ... y - round function output
 *
 */
void F(uint8_t *x, uint8_t *k, uint8_t *y);


/*
 *
 * Swap the 4 left bytes of the block with the 4 right bytes of the data block 
 * ... block - the data block to be processed
 *
 */
void Swap(uint8_t *block);

#endif /* ROUND_FUNCTION_H */
