/*
 *
 * National Security Research Institute
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 National Security Research Institute
 *
 * Written in 2015 by Youngjoo Shin <yjshin@nsr.re.kr>
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

#if defined(MSP)
void RunDecryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
  uint32_t td[4];
  td[0] = READ_RAM_DATA_DOUBLE_WORD(DELTA[0]);
  td[1] = READ_RAM_DATA_DOUBLE_WORD(DELTA[1]);
  td[2] = READ_RAM_DATA_DOUBLE_WORD(DELTA[2]);
  td[3] = READ_RAM_DATA_DOUBLE_WORD(DELTA[3]);

  asm volatile (\
      ".include \"./../source/msp_rotate.s\"            \n"
    
      ".macro ROUND                                     \n"
      /* load delta */
      " mov  @r14+, r13                                 \n"   /* low */
      " mov  @r14+, r12                                 \n"   /* high */
      /* rotate delta */
      " ROL1 r12, r13                                   \n"   
      /* addition to T0 */
      " add  r13, r5                                    \n"   
      " addc r12, r4                                    \n"
      /* rotate T0 */
      " ROL1 r4, r5                                     \n"   
      /* rotate delta */
      " ROL1 r12, r13                                   \n"   
      /* addition to T1 */
      " add  r13, r7                                    \n"   
      " addc r12, r6                                    \n"
      /* rotate T1 */
      " ROL3 r6, r7                                     \n" 
      /* rotate delta */
      " ROL1 r12, r13                                   \n"
      /* addition to T2 */
      " add  r13, r9                                    \n" 
      " addc r12, r8                                    \n"
      /* rotate T2 */
      " ROL6 r8, r9                                     \n"
      /* rotate delta */
      " ROL1 r12, r13                                   \n" 
      /* addition to T3 */
      " add  r13, r11                                   \n" 
      " addc r12, r10                                   \n"
      /* rotate T3 */
      " ROL11 r10, r11                                \n" 

      /* store round keys */
      " mov  r5, 0(r15)                                 \n"   // T0
      " mov  r4, 2(r15)                                 \n"   // T0
      " mov  r7, 4(r15)                                 \n"   // T1
      " mov  r6, 6(r15)                                 \n"   // T1
      " mov  r9, 8(r15)                                 \n"   // T2
      " mov  r8, 10(r15)                                \n"   // T2
      " mov  r7, 12(r15)                                \n"   // T1
      " mov  r6, 14(r15)                                \n"   // T1
      " mov  r11, 16(r15)                               \n"   // T3
      " mov  r10, 18(r15)                               \n"   // T3
      " mov  r7, 20(r15)                                \n"   // T1
      " mov  r6, 22(r15)                                \n"   // T1
  
      " sub #24, r15                                    \n"

      /* store delta */
      " mov  r12, -2(r14)                               \n"
      " mov  r13, -4(r14)                               \n"
      ".endm                                            \n"

      " mov  %[key], r14                                \n"
      " mov  %[roundKeys], r15                          \n"
    
      /* load key */
      " mov  @r14+, r5                                  \n"
      " mov  @r14+, r4                                  \n"
      " mov  @r14+, r7                                  \n"
      " mov  @r14+, r6                                  \n"
      " mov  @r14+, r9                                  \n"
      " mov  @r14+, r8                                  \n"
      " mov  @r14+, r11                                 \n"
      " mov  @r14+, r10                                 \n"
    
      " mov  %[delta], r14                              \n"

      /* point to %[roundKeys]+552 */
      " add #552, r15                                   \n"
    
      /* begin the rounds */
      " .rept 6                                         \n"
      " ROUND                                           \n"
      " ROUND                                           \n"
      " ROUND                                           \n"
      " ROUND                                           \n"
      " sub  #16, r14                                   \n"
      " .endr                                           \n"
      :
      : [key] "m" (key), [roundKeys] "m" (roundKeys), [delta] "" (td)
      );
}
#else
void RunDecryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
}

#endif
