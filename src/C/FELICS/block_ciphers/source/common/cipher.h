/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu> and 
 * Yann Le Corre <yann.lecorre@uni.lu>
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

#ifndef CIPHER_H
#define CIPHER_H


#ifdef AVR /* AVR */
#include <avr/pgmspace.h>
#endif /* AVR */


/*
 *
 * Optimization levels
 * ... OPTIMIZATION_LEVEL_0 - O0
 * ... OPTIMIZATION_LEVEL_1 - O1
 * ... OPTIMIZATION_LEVEL_2 - O2
 * ... OPTIMIZATION_LEVEL_3 - O3 = defualt
 *
 */
#define OPTIMIZATION_LEVEL_0 __attribute__((optimize("O0")))
#define OPTIMIZATION_LEVEL_1 __attribute__((optimize("O1")))
#define OPTIMIZATION_LEVEL_2 __attribute__((optimize("O2")))
#define OPTIMIZATION_LEVEL_3 __attribute__((optimize("O3")))


/*
 * 
 * SCENARIO values:
 * ... SCENARIO_0 0 - cipher operation: encrypt & decrypt one data block
 * ... SCENARIO_1 1 - scenario 1: encrypt & decrypt data in CBC mode
 * ... SCENARIO_2 2 - scenario 2: encrypt & decrypt data in CTR mode
 *
 */
#define SCENARIO_0 0
#define SCENARIO_1 1
#define SCENARIO_2 2

#ifndef SCENARIO
#define SCENARIO SCENARIO_0
#endif


/*
 *
 * MEASURE_CYCLE_COUNT values:
 * ... MEASURE_CYCLE_COUNT_DISABLED 0 - measure cycle count is disabled
 * ... MEASURE_CYCLE_COUNT_ENABLED 1 - measure cycle count is enabled
 *
 */
#define MEASURE_CYCLE_COUNT_DISABLED 0
#define MEASURE_CYCLE_COUNT_ENABLED 1

#ifndef MEASURE_CYCLE_COUNT
#define MEASURE_CYCLE_COUNT MEASURE_CYCLE_COUNT_DISABLED
#endif


/*
 *
 * Align memory boundaries in bytes
 *
 */
#define ALIGN_PC_BOUNDRY 64
#define ALIGN_AVR_BOUNDRY 2
#define ALIGN_MSP_BOUNDRY 2
#define ALIGN_ARM_BOUNDRY 8

#if defined(PC) && !defined(ALIGNED) /* PC ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_PC_BOUNDRY)))
#endif /* PC ALIGNED */

#if defined(AVR) && !defined(ALIGNED) /* AVR ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_AVR_BOUNDRY)))
#endif /* AVR ALIGNED */

#if defined(MSP) && !defined(ALIGNED) /* MSP ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_MSP_BOUNDRY)))
#endif /* MSP ALIGNED */

#if defined(ARM) && !defined(ALIGNED) /* ARM ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_ARM_BOUNDRY)))
#endif /* ARM ALIGNED */


/* 
 *
 * RAM data types 
 *
 */
#define RAM_DATA_BYTE uint8_t ALIGNED
#define RAM_DATA_WORD uint16_t ALIGNED
#define RAM_DATA_DOUBLE_WORD uint32_t ALIGNED

#define READ_RAM_DATA_BYTE(x) x
#define READ_RAM_DATA_WORD(x) x
#define READ_RAM_DATA_DOUBLE_WORD(x) x


/* 
 *
 * Flash/ROM data types 
 *
 */
#if defined(AVR) /* AVR */
#define ROM_DATA_BYTE const uint8_t PROGMEM ALIGNED
#define ROM_DATA_WORD const uint16_t PROGMEM ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t PROGMEM ALIGNED

#define READ_ROM_DATA_BYTE(x) pgm_read_byte(&x)
#define READ_ROM_DATA_WORD(x) pgm_read_word(&x)
#define READ_ROM_DATA_DOUBLE_WORD(x) pgm_read_dword(&x)
#else /* AVR */
#define ROM_DATA_BYTE const uint8_t ALIGNED
#define ROM_DATA_WORD const uint16_t ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t ALIGNED

#define READ_ROM_DATA_BYTE(x) x
#define READ_ROM_DATA_WORD(x) x
#define READ_ROM_DATA_DOUBLE_WORD(x) x
#endif /* AVR */


/*
 *
 * Scenario 2 round keys are stored in Flash/ROM
 *
 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define READ_ROUND_KEY_BYTE(x) READ_ROM_DATA_BYTE(x)
#define READ_ROUND_KEY_WORD(x) READ_ROM_DATA_WORD(x)
#define READ_ROUND_KEY_DOUBLE_WORD(x) READ_ROM_DATA_DOUBLE_WORD(x)
#else
#define READ_ROUND_KEY_BYTE(x) READ_RAM_DATA_BYTE(x)
#define READ_ROUND_KEY_WORD(x) READ_RAM_DATA_WORD(x)
#define READ_ROUND_KEY_DOUBLE_WORD(x) READ_RAM_DATA_DOUBLE_WORD(x)
#endif


/*
 *
 * Run the encryption key schedule
 * ... key - the cipher key
 * ... roundKeys - the encryption round keys
 *
 */
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys);

/*
 *
 * Run the decryption key schedule
 * ... key - the cipher key
 * ... roundKeys - the decryption round keys
 *
 */
void RunDecryptionKeySchedule(uint8_t *key, uint8_t *roundKeys);


/*
 *
 * Encrypt the given block using the given round keys
 * ... block - the block to encrypt
 * ... roundKeys - the round keys to be used during encryption
 *
 */
void Encrypt(uint8_t *block, uint8_t *roundKeys);

/*
 *
 * Decrypt the given block using the given round keys
 * ... block - the block to decrypt
 * ... roundKeys - the round keys to be used during decryption
 *
 */
void Decrypt(uint8_t *block, uint8_t *roundKeys);

#endif /* CIPHER_H */
