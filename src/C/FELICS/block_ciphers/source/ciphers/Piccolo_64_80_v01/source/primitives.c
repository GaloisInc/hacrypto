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
 * Piccolo common functions
 *
 ******************************************************************************/

#include <stdint.h>
#include "constants.h"

/* calculate p0 + p1 + 2*p2 + 3*p3 in GF[2^4] with caract. poly = x^4 + x + 1 */
uint8_t polyEval(uint8_t p0, uint8_t p1, uint8_t p2, uint8_t p3)
{
	/* uint8_t y = p0 ^ p1 ^ gf16_mul2(p2) ^ gf16_mul3(p3); */
	uint8_t y = p0 ^ p1 ^ READ_GF16_MUL_BYTE(GF16_MUL2[p2]) ^ READ_GF16_MUL_BYTE(GF16_MUL3[p3]);
	
	return y;
}

uint16_t F(uint16_t x)
{
    uint8_t x0;
    uint8_t x1;
    uint8_t x2;
    uint8_t x3;
    uint8_t y0;
    uint8_t y1;
    uint8_t y2;
    uint8_t y3;
	

    x3 = (x >>  0) & 0x0f;
    x2 = (x >>  4) & 0x0f;
    x1 = (x >>  8) & 0x0f;
    x0 = (x >> 12) & 0x0f;

    x3 = READ_SBOX_BYTE(SBOX[x3]);
    x2 = READ_SBOX_BYTE(SBOX[x2]);
    x1 = READ_SBOX_BYTE(SBOX[x1]);
    x0 = READ_SBOX_BYTE(SBOX[x0]);

    y0 = polyEval(x2, x3, x0, x1);
    y1 = polyEval(x3, x0, x1, x2);
    y2 = polyEval(x0, x1, x2, x3);
    y3 = polyEval(x1, x2, x3, x0);
    y0 = READ_SBOX_BYTE(SBOX[y0]);
    y1 = READ_SBOX_BYTE(SBOX[y1]);
    y2 = READ_SBOX_BYTE(SBOX[y2]);
    y3 = READ_SBOX_BYTE(SBOX[y3]);

	return (y0 << 12) | (y1 << 8) | (y2 << 4) | y3;
}

void RP(uint16_t *x0, uint16_t *x1, uint16_t *x2, uint16_t *x3)
{
    uint16_t y0;
    uint16_t y1;
    uint16_t y2;
    uint16_t y3;
	

    y0 = (*x1 & 0xff00) | (*x3 & 0x00ff);
    y1 = (*x2 & 0xff00) | (*x0 & 0x00ff);
    y2 = (*x3 & 0xff00) | (*x1 & 0x00ff);
    y3 = (*x0 & 0xff00) | (*x2 & 0x00ff);
	
    *x0 = y0;
    *x1 = y1;
    *x2 = y2;
    *x3 = y3;
}
