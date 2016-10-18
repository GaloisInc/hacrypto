/*
 *
 * Kocaeli University Computer Engineering
 * TÜBİTAK BİLGEM, Turkey
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 Kocaeli University
 *
 * Written in 2016 by Adnan Baysal <adnan.baysal@tubitak.gov.tr>
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
#include "s_layer.h"


void S_layer(uint16_t *data){
   uint16_t  temp[5];
   temp[0] = data[1]^0xffff;
   temp[1] = data[0]&temp[0];
   temp[2] = data[2]^data[3];
   temp[3] = temp[1]^temp[2];
   temp[1] = data[3]|temp[0];
   temp[0] = data[0]^temp[1];
   temp[1] = data[2]^temp[0];
   temp[4] = data[1]^data[2];
   data[3] = temp[2]&temp[0];
   data[3] = data[3]^temp[4];
   data[2] = temp[3]|temp[4];
   data[2] = data[2]^temp[0];
   data[0] = temp[3];
   data[1] = temp[1];
}
