/*
 *
 * Katholieke Universiteit Leuven
 * Computer Security and Industrial Cryptography (COSIC)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 Katholieke Universiteit Leuven
 *
 * Written in 2015 by Nicky Mouha <nicky.mouha@esat.kuleuven.be>,
 *                    Jason Smith <jksmit3@tycho.ncsc.mil>
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
#include "rot32.h"
#include "constants.h"

void Decrypt(uint8_t *block, uint8_t *keyBytes)
{
  uint32_t *v = (uint32_t *)block;
  uint32_t *k = (uint32_t *)keyBytes;
  uint8_t i;

  /* Whitening */
  v[0] ^= READ_ROUND_KEY_DOUBLE_WORD(k[0]); 
  v[1] ^= READ_ROUND_KEY_DOUBLE_WORD(k[1]); 
  v[2] ^= READ_ROUND_KEY_DOUBLE_WORD(k[2]); 
  v[3] ^= READ_ROUND_KEY_DOUBLE_WORD(k[3]);
  
  /* Chaskey permutation */
  for (i = 0; i < NUMBER_OF_ROUNDS; ++i)
  {
    v[2]=rot32r16(v[2]); v[1] ^= v[2]; v[1]=rot32r7(v[1]);  v[2] -= v[1];
                         v[3] ^= v[0]; v[3]=rot32r13(v[3]); v[0] -= v[3];
                         v[3] ^= v[2]; v[3]=rot32r8(v[3]);  v[2] -= v[3];
    v[0]=rot32r16(v[0]); v[1] ^= v[0]; v[1]=rot32r5(v[1]);  v[0] -= v[1];
  }
  
  /* Whitening */
  v[0] ^= READ_ROUND_KEY_DOUBLE_WORD(k[0]); 
  v[1] ^= READ_ROUND_KEY_DOUBLE_WORD(k[1]); 
  v[2] ^= READ_ROUND_KEY_DOUBLE_WORD(k[2]); 
  v[3] ^= READ_ROUND_KEY_DOUBLE_WORD(k[3]);
}
