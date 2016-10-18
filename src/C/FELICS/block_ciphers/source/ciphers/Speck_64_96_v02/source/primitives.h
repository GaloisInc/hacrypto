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

/* Note: ALPHA is 8, BETA is 3 */

static inline uint32_t rol1(uint32_t x)
{
    return (x << 1) | (x >> 31);
}

static inline uint32_t rolBeta(uint32_t x)
{
	uint32_t tmp;

	tmp = rol1(x);
	tmp = rol1(tmp);
	tmp = rol1(tmp);
    return tmp;
}


static inline uint32_t rolAlpha(uint32_t x)
{
    return (x << 8) | (x >> 24);
}

static inline uint32_t ror1(uint32_t x)
{
    return (x >> 1) | (x << 31);
}

static inline uint32_t rorBeta(uint32_t x)
{
	uint32_t tmp;

	tmp = ror1(x);
	tmp = ror1(tmp);
	tmp = ror1(tmp);
    return tmp;
}

static inline uint32_t rorAlpha(uint32_t x)
{
    return (x >> 8) | (x << 24);
}
