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
#include "constants.h"

/*
 *
 * Cipher constants
 *
 */
#if defined(MSP)
/*
 *
 * DELTA values are used after bit rotations. According to the characteristics
 * ... of each architecture, using pre-rotated DELTA values reduces execution
 * ... time for key schedule.
 * For the original DELTA values {d1, d2, d3, d4} in the cipher specifications,
 * ... the pre-rotated delta values for MSP ASM implementation are
 * ... {rotr(d1, 1), d2, rotl(d3, 1), rotl(d4, 2)}.
 *
 */
RAM_DATA_DOUBLE_WORD DELTA[4]= {0xe1f7f4ed, 0x44626b02, 0xf3c4f914, 0xe37cc3b1};

#else
RAM_DATA_DOUBLE_WORD DELTA[4]= {0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec};

#endif
