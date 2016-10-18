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

/*
 *
 * Cycle count on PC
 *
 */


#ifndef __CYCLE_COUNT_H__
#define __CYCLE_COUNT_H__


uint64_t __cycleCountStart;
uint64_t __cycleCountStop;

static inline uint64_t __cpucycles()
{
	uint64_t result;
	asm volatile(".byte 15;.byte 49" : "=A" (result));

	return result;
}

#define CYCLE_COUNT_START \
	__cycleCountStart = __cpucycles();

#define CYCLE_COUNT_STOP \
	__cycleCountStop = __cpucycles();

#define CYCLE_COUNT_ELAPSED (__cycleCountStop - __cycleCountStart)


#endif /* __CYCLE_COUNT_H__ */
