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


#ifndef PRIDE_FUNCTIONS_H
#define PRIDE_FUNCTIONS_H

#define SWAP(x) (((x)>>4)^((x)<<4))
#define ROTL(x) (((x)<<1)^(x>>7))
#define ROTR(x) (((x)>>1)^(x<<7))
#define ENC		0
#define DEC		1
#define LST		2

void S_layer(uint8_t *data);
void L0(uint8_t *data);
void L1(uint8_t *data);
void L1Inv(uint8_t *data);
void L2(uint8_t *data);
void L2Inv(uint8_t *data);
void L3(uint8_t *data);
void L_layer(uint8_t *data);
void L_layerInv(uint8_t *data);
void round_function(uint8_t *data,uint8_t *rkey,uint8_t mode);

#endif /* PRIDE_FUNCTIONS_H */

