/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Johann Großschädl <johann.groszschaedl@uni.lu>
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

#ifndef SHARED_FUNCTIONS_H
#define SHARED_FUNCTIONS_H


/* 
 *
 * If half & 1 == 0 then use first half of the key
 * else use the second half of the key
 * 
 * The key bytes are added row wise, i.e., first row , then second row etc.
 * 
 */
void AddKey(uint8_t state[4][4], uint8_t* keyBytes, uint8_t half);

void AddConstants(uint8_t state[4][4], uint8_t r);


#endif /* SHARED_FUNCTIONS_H */
