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

static inline uint8_t rol(uint8_t x)
{
	return ((x << 1) & 0xFF) ^ ((x >> 7) & 0xFF);
}

static inline uint8_t ror(uint8_t x)
{
	return ((x >> 1) & 0xFF) ^ ((x << 7) & 0xFF);
}


/* 
 * 
 * Auxiliary round function F0 
 * ... x - the input data byte
 * Returns: the auxiliary round function F0 result byte
 *
 */
static inline uint8_t F0(uint8_t x)
{
	uint8_t temp1, temp2, temp3;
	

	temp1 = rol(x);
	temp2 = rol(temp1);
	temp3 = ror(x);

	return temp1 ^ temp2 ^ temp3;
}

/* 
 * 
 * Auxiliary round function F1
 * ... x - the input data byte
 * Returns: the auxiliary round function F1 result byte
 *
 */
static inline uint8_t F1(uint8_t x)
{
	uint8_t temp1, temp2, temp3;

	
	temp1 = ror(x);
	temp1 =	ror(temp1);

	temp2 = ror(temp1);
	temp2 = ror(temp2);

	temp3 = ror(temp2);


	return temp1 ^ temp2 ^ temp3;
}

#endif /* ROUND_FUNCTION_H */
