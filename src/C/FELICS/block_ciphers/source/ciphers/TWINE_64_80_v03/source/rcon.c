/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu>
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

#include "constants.h"


DATA_KS_BYTE RCON[35] = 
	{ 
		0x01, 0x02, 0x04, 0x08,
		0x10, 0x20, 0x03, 0x06,
		0x0c, 0x18, 0x30, 0x23,
		0x05, 0x0a, 0x14, 0x28,
		0x13, 0x26, 0x0f, 0x1e,
		0x3c, 0x3b, 0x35, 0x29,
		0x11, 0x22, 0x07, 0x0e,
		0x1c, 0x38, 0x33, 0x25,
		0x09, 0x12, 0x24
	};
