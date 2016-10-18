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

#include "scenario2.h"
#include "round_keys.h"
#include "cipher.h"
#include "common.h"
#include "constants.h"

#if defined(PC) && defined(MEASURE_CYCLE_COUNT) && \
	(MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT)
#include <stdio.h>
#include <inttypes.h>
#include "cycleCount.h"
#endif /* PC & MEASURE_CYCLE_COUNT */

#if defined(ARM) && defined(MEASURE_CYCLE_COUNT) && \
	(MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT)
#include <sam3x8e.h>
#include <stdio.h>
#include <unistd.h>
#include "cycleCount.h"
#endif /* ARM & MEASURE_CYCLE_COUNT */

#if defined(ARM) && defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
#include <stdio.h>
#endif /* ARM & DEBUG */


/*
 *
 * Entry point into program
 *
 */
int main()
{
	RAM_DATA_BYTE data[DATA_SIZE];
	RAM_DATA_BYTE counter[BLOCK_SIZE];

	
	InitializeDevice();


	InitializeData(data, DATA_SIZE);

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	DisplayData(data, DATA_SIZE, PLAINTEXT_NAME);
#endif


#if defined(DEBUG) && (DEBUG_MEDIUM == (DEBUG_MEDIUM & DEBUG))
	DisplayData((uint8_t *)roundKeys, ROUND_KEYS_SIZE, ROUND_KEYS_NAME);
#endif


	InitializeCounter(counter);


#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	DisplayData(data, DATA_SIZE, PLAINTEXT_NAME);
#endif

	BEGIN_ENCRYPTION();
	EncryptScenario2(data, roundKeys, counter);
	END_ENCRYPTION();

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	DisplayData(data, DATA_SIZE, CIPHERTEXT_NAME);
#endif


	InitializeCounter(counter);


#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	DisplayData(data, DATA_SIZE, CIPHERTEXT_NAME);
#endif

	BEGIN_DECRYPTION();
	DecryptScenario2(data, roundKeys, counter);
	END_DECRYPTION();

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	DisplayData(data, DATA_SIZE, PLAINTEXT_NAME);
#endif
	
	
	DONE();
		
	
	StopDevice();


	return 0;
}
