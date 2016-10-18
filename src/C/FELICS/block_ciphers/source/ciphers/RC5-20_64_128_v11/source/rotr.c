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


uint32_t RC5_ROTR(uint32_t x, uint32_t n)
{
	n &= WORD_SIZE - 1;

	switch(n)
	{
		case 17:
			x = ROL(x);
		case 18:
			x = ROL(x);
		case 19:
			x = ROL(x);
		case 20:
			x = ROL(x);
		case 21:
			x = ROL(x);
		case 22:
			x = ROL(x);
		case 23:
			x = ROL(x);
		case 24:
			x = ROL(x);
		case 25:
			x = ROL(x);
		case 26:
			x = ROL(x);			
		case 27:
			x = ROL(x);
		case 28:
			x = ROL(x);
		case 29:
			x = ROL(x);
		case 30:
			x = ROL(x);
		case 31:
			x = ROL(x);
			return x;
	}

	switch(n)
	{
		case 16:
			x = ROR(x);
		case 15:
			x = ROR(x);
		case 14:
			x = ROR(x);
		case 13:
			x = ROR(x);
		case 12:
			x = ROR(x);
		case 11:
			x = ROR(x);
		case 10:
			x = ROR(x);
		case 9:
			x = ROR(x);
		case 8:
			x = ROR(x);
		case 7:
			x = ROR(x);
		case 6:
			x = ROR(x);
		case 5:
			x = ROR(x);
		case 4:
			x = ROR(x);
		case 3:
			x = ROR(x);
		case 2:
			x = ROR(x);
		case 1:
			x = ROR(x);
		case 0:
			break;
	}

	return x;
}
