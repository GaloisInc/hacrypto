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


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
   uint8_t i, j, key_state[16] = {0}, temp[8];
   for(i=0;i<16;i++) key_state[i] = key[i];
   for(i=0;i<NUMBER_OF_ROUNDS;i++){
      for(j=0;j<4;j++){
         roundKeys[i*8+2*j] = key_state[j*4+2];
         roundKeys[i*8+2*j+1] = key_state[j*4+3];
      }
      for(j=0;j<4;j++) temp[2*j+1] = key_state[4*j+3];
      S_layer((uint16_t*)temp);
      for(j=0;j<4;j++) key_state[4*j+3] = temp[2*j+1];
      for(j=0;j<4;j++) temp[j] = key_state[j];
      key_state[0] = key_state[1]^key_state[4];
      key_state[1] = key_state[2]^key_state[5];
      key_state[2] = key_state[3]^key_state[6];
      key_state[3] = temp[0]^key_state[7];
      for(j=0;j<4;j++) key_state[4+j] = key_state[8+j];
      temp[4] = key_state[8];
      temp[5] = key_state[9];
      key_state[8] = key_state[10]^key_state[12];
      key_state[9] = key_state[11]^key_state[13];
      key_state[10] = temp[4]^key_state[14];
      key_state[11] = temp[5]^key_state[15];
      for(j=0;j<4;j++) key_state[12+j] = temp[j];
      key_state[3] ^= READ_ROUND_CONSTANT_BYTE(round_constants[i]);
   }
   for(j=0;j<4;j++){
      roundKeys[NUMBER_OF_ROUNDS*8+2*j] = key_state[j*4+2];
      roundKeys[NUMBER_OF_ROUNDS*8+2*j+1] = key_state[j*4+3];
   }

}
