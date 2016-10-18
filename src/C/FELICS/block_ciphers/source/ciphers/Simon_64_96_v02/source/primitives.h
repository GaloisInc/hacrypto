/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu>
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

/****************************************************************************** 
 *
 * common macro and inline functions for simon cipher
 *
 ******************************************************************************/

static inline uint32_t rol1(uint32_t x)
{
    return (x << 1) | (x >> 31);
}

static inline uint32_t rol8(uint32_t x)
{
    return (x << 8) | (x >> 24);
}

static inline uint32_t ror1(uint32_t x)
{
    return (x >> 1) | (x << 31);
}

static inline uint32_t f(uint32_t x)
{
	uint32_t x_rol1 = rol1(x);
    return x_rol1 & rol8(x) ^ rol1(x_rol1);
}

static inline void doubleRound(uint32_t *left, uint32_t *right, uint32_t rk0, uint32_t rk1)
{
    *right = f(*left) ^ *right ^ rk0;
    *left = f(*right) ^ *left ^ rk1;
}
