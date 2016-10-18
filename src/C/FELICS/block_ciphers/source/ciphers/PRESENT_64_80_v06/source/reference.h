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

#ifndef __REFERENCE_H__
#define __REFERENCE_H__

#include <stdint.h>
#include <stdio.h>

void pLayerRef(uint8_t *block);
void invpLayerRef(uint8_t *block);
void sboxLayerRef(uint8_t *block);
void invSboxLayerRef(uint8_t *block);
void addRoundKeyLayerRef(uint8_t *block, uint8_t *roundKey);
void printBlock(uint8_t *block);
void eksRef(uint8_t *key, uint8_t *roundKeys);

#endif  /* __REFERENCE_H__ */
