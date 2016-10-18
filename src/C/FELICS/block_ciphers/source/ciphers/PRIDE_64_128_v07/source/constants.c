/*
 *
 * Kocaeli University Computer Engineering
 * TÜBİTAK BİLGEM, Turkey
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 Kocaeli University
 *
 * Written in 2015 by Adnan Baysal <adnan.baysal@tubitak.gov.tr>
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
#include "constants.h"

/*
 *
 * Cipher constants
 *
 */
 
ROUND_CONSTANT_BYTE round_constants[80] = {
	0xC1,0xA5,0x51,0xC5,0x82,0x4A,0xA2,0x8A,
	0x43,0xEF,0xF3,0x4F,0x04,0x94,0x44,0x14,
	0xC5,0x39,0x95,0xD9,0x86,0xDE,0xE6,0x9E,
	0x47,0x83,0x37,0x63,0x08,0x28,0x88,0x28,
	0xC9,0xCD,0xD9,0xED,0x8A,0x72,0x2A,0xB2,
	0x4B,0x17,0x7B,0x77,0x0C,0xBC,0xCC,0x3C,
	0xCD,0x61,0x1D,0x01,0x8E,0x06,0x6E,0xC6,
	0x4F,0xAB,0xBF,0x8B,0x10,0x50,0x10,0x50,
	0xD1,0xF5,0x61,0x15,0x92,0x9A,0xB2,0xDA,
	0x53,0x3F,0x03,0x9F,0x14,0xE4,0x54,0x64
};
