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
#include "rot.h"


void IS_layer(uint16_t *data){
   uint16_t  temp[5];
   temp[0] = data[0]|data[3]; 
   temp[1] = data[0]^data[3]; 
   temp[2] = data[0]&(data[2]^0xFFFF); 
   temp[3] = data[2]^temp[0]; 
   data[2] = data[1]^temp[3]; 
   temp[4] = temp[3]^0xffff; 
   temp[0] = data[3]^data[2]; 
   data[1] = temp[2]^temp[0]; 
   temp[2] = temp[4]|temp[0]; 
   data[3] = temp[1]^temp[2]; 
   temp[0] = data[1]&(data[3]^0xffff);   
   data[0] = temp[4]^temp[0];
}

void IP_layer(uint16_t *data){
   data[1] = ROTR1(data[1]);
   data[2] = ROTR12(data[2]);
   data[3] = ROTR13(data[3]);
}

void Iround_function(uint16_t *data,uint16_t *rkey){
   uint8_t i;
   for(i=0;i<4;i++) data[i] ^= READ_ROUND_KEY_WORD(rkey[i]);
   IP_layer(data);
   IS_layer(data);
}


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
        uint8_t i;
        for(i=NUMBER_OF_ROUNDS;i!=0;i--) Iround_function((uint16_t*)block,(uint16_t*)(roundKeys+8*i));
        for(i=0;i<8;i++) block[i] ^= READ_ROUND_KEY_BYTE(roundKeys[i]);
}
