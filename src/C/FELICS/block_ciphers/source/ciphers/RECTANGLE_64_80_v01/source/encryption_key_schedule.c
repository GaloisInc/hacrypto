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

#include "cipher.h"
#include "constants.h"
#include "s_layer.h"
#include "rot.h"


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
   uint8_t i, j, key_state[10] = {0}, temp[8];
   uint16_t temp16;
   for(i=0;i<10;i++) key_state[i] = key[i];
   for(i=0;i<NUMBER_OF_ROUNDS;i++){
      for(j=0;j<8;j++) roundKeys[i*8+j] = key_state[j];
      for(j=0;j<4;j++) temp[2*j+1] = key_state[2*j+1];
      S_layer((uint16_t*)temp);
      for(j=0;j<4;j++){
         key_state[2*j+1] &= 0xF0;
         key_state[2*j+1] ^= temp[2*j+1]&0x0F;
      }
      temp[0] = key_state[0];
      temp[1] = key_state[1];
      key_state[0] = key_state[1]^key_state[2];
      key_state[1] = temp[0]^key_state[3];
      key_state[2] = key_state[4];
      key_state[3] = key_state[5];
      key_state[4] = key_state[6];
      key_state[5] = key_state[7];
      temp16 = key_state[6];
      temp16 = (temp16<<8)^key_state[7];
      temp16 = ROTL12(temp16);
      key_state[6] = (temp16>>8)^key_state[8];
      key_state[7] = (temp16&255)^key_state[9];
      key_state[8] = temp[0];
      key_state[9] = temp[1];
      key_state[1] ^= READ_ROUND_CONSTANT_BYTE(round_constants[i]);
   }
   for(j=0;j<8;j++) roundKeys[NUMBER_OF_ROUNDS*8+j] = key_state[j];
}
