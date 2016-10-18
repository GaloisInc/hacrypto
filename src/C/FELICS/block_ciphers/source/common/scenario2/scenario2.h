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

#ifndef SCENARIO2_H
#define SCENARIO2_H

#include "constants.h"


/*
 * 
 * Scenario characteristics: 
 * 		RAW_DATA_SIZE - the raw data size in bytes
 *		DATA_SIZE - the cipher data size in bytes
 *
 */
#define RAW_DATA_SIZE 16
#define DATA_SIZE RAW_DATA_SIZE


/*
 *
 * Encrypt the given data using CTR mode of the cipher
 * ... data - the data to be encrypted
 * ... roundKeys - the encryption round keys
 * ... counter - the counter block
 *
 */
void EncryptScenario2(uint8_t *data, const uint8_t *roundKeys, uint8_t *counter);

/*
 *
 * Decrypt the given data using the CTR mode of the cipher
 * ... data - the data to be decrypted
 * ... roundKeys - the encryption round keys
 * ... counter - the counter block
 *
 */
void DecryptScenario2(uint8_t *data, const uint8_t *roundKeys, uint8_t *counter);

#endif /* SCENARIO2_H */
