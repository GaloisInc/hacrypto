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
#include "rotate.h"


uint32_t RC5_ROTL(uint32_t x, uint32_t n)
{
	n &= WORD_SIZE - 1;

	switch(n)
	{
		case 17:
			x = ROR(x);
		case 18:
			x = ROR(x);
		case 19:
			x = ROR(x);
		case 20:
			x = ROR(x);
		case 21:
			x = ROR(x);
		case 22:
			x = ROR(x);
		case 23:
			x = ROR(x);
		case 24:
			x = ROR(x);
		case 25:
			x = ROR(x);
		case 26:
			x = ROR(x);
		case 27:
			x = ROR(x);
		case 28:
			x = ROR(x);
		case 29:
			x = ROR(x);
		case 30:
			x = ROR(x);
		case 31:
			x = ROR(x);
			return x;
	}

	switch(n)
	{
		case 16:
			x = ROL(x);
		case 15:
			x = ROL(x);
		case 14:
			x = ROL(x);
		case 13:
			x = ROL(x);
		case 12:
			x = ROL(x);
		case 11:
			x = ROL(x);
		case 10:
			x = ROL(x);
		case 9:
			x = ROL(x);
		case 8:
			x = ROL(x);
		case 7:
			x = ROL(x);
		case 6:
			x = ROL(x);			
		case 5:
			x = ROL(x);
		case 4:
			x = ROL(x);
		case 3:
			x = ROL(x);
		case 2:
			x = ROL(x);
		case 1:
			x = ROL(x);
		case 0:
			break;
	}

	return x;
}
