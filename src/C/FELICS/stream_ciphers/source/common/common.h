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

#ifndef COMMON_H
#define COMMON_H


/*
 *
 * Debug levels:
 * ... DEBUG_NO 0 - do not debug
 * ... DEBUG_LOW 1 - minimum debug level
 * ... DEBUG_MEDIUM 3 - medium debug level
 * ... DEBUG_HIGHT 7 - maximum debug level
 *
 */
#define DEBUG_NO 0
#define DEBUG_LOW 1
#define DEBUG_MEDIUM 3
#define DEBUG_HIGH 7


#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG)) /* DEBUG */

extern const char *STATE_NAME;
extern const char *KEY_NAME;
extern const char *IV_NAME;
extern const char *PLAINTEXT_NAME;
extern const char *CIPHERTEXT_NAME;

/*
 *
 * Display the given data arrray in hexadecimal
 * ... data - the data array to be displayed
 * ... length - the length in bytes of the data array
 * ... name - the name of the data array
 *
 */
void DisplayData(uint8_t *data, uint16_t length, const char *name);

/*
 *
 * Display and verify the given data arrray in hexadecimal
 * ... data - the data array to be displayed
 * ... length - the length in bytes of the data array
 * ... name - the name of the data array
 *
 */
void DisplayVerifyData(uint8_t *data, uint16_t length, const char *name);

/*
 *
 * Verify if the given data is the same with the expected data
 * ... data - the data array to check
 * ... name - the name of the data array
 *
 */
void VerifyData(uint8_t *data, const char *name);

#endif /* DEBUG */



#ifdef ARM /* ARM */

#if defined(MEASURE_CYCLE_COUNT) && \
	(MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT) /* MEASURE_CYCLE_COUNT */

#define BEGIN_SETUP() CYCLE_COUNT_START
#define END_SETUP() \
	CYCLE_COUNT_STOP; \
	printf("SetupCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_ENCRYPTION() CYCLE_COUNT_START
#define END_ENCRYPTION() \
	CYCLE_COUNT_STOP; \
	printf("EncryptCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define DONE() printf("Done\n")

#else /* MEASURE_CYCLE_COUNT */

#define BEGIN_SETUP() BeginSetup()
#define END_SETUP() EndSetup()

#define BEGIN_ENCRYPTION() BeginEncryption()
#define END_ENCRYPTION() EndEncryption()

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
#define DONE() printf("Done\n");
#else
#define DONE()
#endif

#endif /* MEASURE_CYCLE_COUNT */

#else /* ARM */

#ifdef PC /* PC */

#if defined(MEASURE_CYCLE_COUNT) && \
	(MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT) /* MEASURE_CYCLE_COUNT */

#define BEGIN_SETUP() CYCLE_COUNT_START
#define END_SETUP() \
	CYCLE_COUNT_STOP; \
	printf("SetupCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_ENCRYPTION() CYCLE_COUNT_START
#define END_ENCRYPTION() \
	CYCLE_COUNT_STOP; \
	printf("EncryptCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define DONE()

#else /* MEASURE_CYCLE_COUNT */

#define BEGIN_SETUP() BeginSetup()
#define END_SETUP() EndSetup()

#define BEGIN_ENCRYPTION() BeginEncryption()
#define END_ENCRYPTION() EndEncryption()

#define DONE()

#endif /* MEASURE_CYCLE_COUNT */

#else /* PC */

#define BEGIN_SETUP() BeginSetup()
#define END_SETUP() EndSetup()

#define BEGIN_ENCRYPTION() BeginEncryption()
#define END_ENCRYPTION() EndEncryption()

#define DONE()

#endif /* PC */

#endif /* ARM */



/*
 *
 * Mark the begin of the stream cipher setup
 *
 */
void BeginSetup();

/*
 *
 * Mark the end of the stream cipher setup
 *
 */
void EndSetup();


/*
 *
 * Mark the begin of the encryption
 *
 */
void BeginEncryption();

/*
 *
 * Mark the end of the encryption
 *
 */
void EndEncryption();


/*
 *
 * Initialize the device (architecture dependent)
 *
 */
void InitializeDevice();

/*
 *
 * Stop the device (architecture dependent)
 *
 */
void StopDevice();


/*
 *
 * Initialize the cipher key
 * ... key - the key to be initialized
 *
 */
void InitializeKey(uint8_t *key);


/*
 *
 * Initialize the cipher IV (initialization vector)
 * ... iv - the IV (initialization vector) to be initialized
 *
 */
void InitializeIV(uint8_t *iv);


/*
 *
 * Initialize the cipher stream
 * ... stream - the cipher stream
 *
 */
void InitializeStream(uint8_t *stream);


/*
 *
 * Initialize the data
 * ... data - the data array to be initialized
 * ... length - the length of the data array to be initialized
 *
 */
void InitializeData(uint8_t *data, int length);


#endif /* COMMON_H */
