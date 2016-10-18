/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu> and 
 * Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

/******************************************************************************* 
 *
 * Cycle count on ARM cortex M3 (hardware)
 *
 ******************************************************************************/

#include <sam3x8e.h>

#ifndef __CYCLE_COUNT_H__
#define __CYCLE_COUNT_H__


extern uint32_t __cycleCountStart;
extern uint32_t __cycleCountStop;

#define CYCLE_COUNT_START \
	SysTick->VAL = 0x00000000; \
	asm("nop"); \
	__cycleCountStart = SysTick->VAL

#define CYCLE_COUNT_STOP \
	__cycleCountStop =  SysTick->VAL

#define CYCLE_COUNT_ELAPSED (__cycleCountStart - __cycleCountStop - 19)

#define CYCLE_COUNT_INIT \
	SysTick->LOAD = 0x00ffffff; \
    SysTick->VAL = 0; \
    SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk; \
	asm("nop"); \
    __cycleCountStart = 0; \
    __cycleCountStop = 0;


#endif /* __CYCLE_COUNT_H__ */
