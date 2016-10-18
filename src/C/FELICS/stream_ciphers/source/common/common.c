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

#include <stdint.h>


#include <string.h>


#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG)) /* DEBUG */

#include <stdio.h>

#ifdef AVR /* AVR */
#include <avr/io.h>
#include <avr/sleep.h>

#include "avr_mcu_section.h"

#ifndef F_CPU
#define F_CPU (8000000UL)
#endif

#endif /* AVR */

#endif /* DEBUG */


#ifdef MSP /* MSP */
#include <msp430.h>
#endif /* MSP */


#include "cipher.h"
#include "common.h"
#include "constants.h"
#include "test_vectors.h"


#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))

const char *STATE_NAME = "State";
const char *KEY_NAME = "Key";
const char *IV_NAME = "IV";
const char *PLAINTEXT_NAME = "Plaintext";
const char *CIPHERTEXT_NAME = "Ciphertext";

void DisplayData(uint8_t *data, uint16_t length, const char *name)
{
	uint16_t i;

	printf("%s:\n", name);
	for (i = 0; i < length; i++) 
	{
		printf("%02x ", data[i]);
	}
	printf("\n");
}

void DisplayVerifyData(uint8_t *data, uint16_t length, const char *name)
{
	DisplayData(data, length, name);
	VerifyData(data, name);
}

void VerifyData(uint8_t *data, const char *name)
{
	uint8_t correct = 1;
	uint16_t length = 0;
	uint16_t i;

	const uint8_t *expectedData;

	
	if(0 == strcmp(name, PLAINTEXT_NAME))
	{
		expectedData = expectedPlaintext;
		length = TEST_STREAM_SIZE;
	}
	
	if(0 == strcmp(name, CIPHERTEXT_NAME))
	{
		expectedData = expectedCiphertext;
		length = TEST_STREAM_SIZE;
	}

	if(0 == strcmp(name, KEY_NAME))
	{
		expectedData = expectedKey;
		length = KEY_SIZE;
	}

	if(0 == strcmp(name, IV_NAME))
	{
		expectedData = expectedIV;
		length = IV_SIZE;
	}

	if(0 == length)
	{
		return;
	}
	
	
	printf("Expected %s:\n", name);
	for(i = 0; i < length; i++)
	{
		printf("%02x ", expectedData[i]);
		if(expectedData[i] != data[i]) 
		{
			correct = 0;
		}
	}
	printf("\n");
	
	if(correct)
	{
		printf("CORRECT!\n");
	}
	else
	{
		printf("WRONG!\n");
	}
}

#endif


void BeginSetup()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	printf("->Setup begin\n");
#endif
}

void EndSetup()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	printf("->Setup end\n");
#endif
}

void BeginEncryption()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	printf("->Encryption begin\n");
#endif
}

void EndEncryption()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	printf("->Encryption end\n");
#endif
}


#ifdef PC /* PC */

void InitializeDevice()
{

}

void StopDevice()
{
	
}

#endif /* PC */


#ifdef AVR /* AVR */

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG)) /* DEBUG */

AVR_MCU(F_CPU, "atmega128");

static int uart_putchar(char c, FILE *stream)
{
	if ('\n' == c)
	{
		uart_putchar('\r', stream);
	}
	
	loop_until_bit_is_set(UCSR0A, UDRE0);
	UDR0 = c;

	return 0;
}

static FILE mystdout = FDEV_SETUP_STREAM(uart_putchar, NULL, _FDEV_SETUP_WRITE);
AVR_MCU_SIMAVR_CONSOLE(&UDR0);

#endif /* DEBUG */

void InitializeDevice()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	stdout = &mystdout;
#endif
}

void StopDevice()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
	sleep_cpu();
#endif
}

#endif /* AVR */


#ifdef MSP /* MSP */

void InitializeDevice()
{

}

void StopDevice()
{
	
}

#endif /* MSP */


#ifdef ARM /* ARM */

/*
 *
 * init() is defined in the sam3x8e library, so we only need a declaration here
 *
 */
extern void init(void);

void InitializeDevice()
{
	init();
}

void StopDevice()
{
	
}

#endif /* ARM */


void InitializeKey(uint8_t *key)
{
	uint8_t i;
	
	for(i = 0; i < KEY_SIZE; i++)
	{
		key[i] = expectedKey[i];
	}
}


void InitializeIV(uint8_t *iv)
{
	uint8_t i;
	
	for(i = 0; i < IV_SIZE; i++)
	{
		iv[i] = expectedIV[i];
	}
}


void InitializeStream(uint8_t *stream)
{

	uint8_t i;
	
	for(i = 0; i < TEST_STREAM_SIZE; i++)
	{
		stream[i] = expectedPlaintext[i];
	}
}


void InitializeData(uint8_t *data, int length)
{
	uint8_t i;
	
	for(i = 0; i < length; i++)
	{
		data[i] = length - i;
	}
}
