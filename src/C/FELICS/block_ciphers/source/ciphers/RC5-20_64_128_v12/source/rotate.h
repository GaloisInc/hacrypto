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

#ifndef ROTATE_H
#define ROTATE_H


#define WORD_SIZE 32

/*
#define RC5_ROTL(x, y) ( ( (x) << (y & (WORD_SIZE - 1) ) ) | \
	( (x) >> (WORD_SIZE - (y & (WORD_SIZE - 1))) ) )


#define RC5_ROTR(x, y) ( ( (x) >> (y & (WORD_SIZE - 1) ) ) | \
	( (x) << (WORD_SIZE - (y & (WORD_SIZE - 1))) ) )
*/


static inline uint32_t ROL(uint32_t x)
{
	return ((x << 1) | (x >> (WORD_SIZE - 1)));
}

static inline uint32_t ROR(uint32_t x)
{
	return ((x >> 1) | (x << (WORD_SIZE - 1)));
}

uint32_t RC5_ROTL(uint32_t x, uint32_t n);

uint32_t RC5_ROTR(uint32_t x, uint32_t n);

#endif /* ROTATE_H */
