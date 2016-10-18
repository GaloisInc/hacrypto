/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 University of Luxembourg
 *
 * Written in 2016 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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
 * GCC compiler for MSP (msp430-gcc) does not generate optimal code for
 * ... rotations of 8-bit values. Teach the compilers how to efficiently rotate
 * ... 8-bit values.
 *
 */


#ifndef ROT8_H
#define ROT8_H


/*
 *
 * Enable ASM rotations
 *
 */
#define ENABLE_ASM_ROT


/*
 *
 * Rotate the given 8-bit value to the left by 1 bit
 * ... x - the 8-bit value to be rotated
 * Return: the rotated 8-bit value
 *
 */
static inline uint8_t rot8l1(uint8_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint8_t result = x;

    __asm__(
        "rla.b    %A0"    "\n\t"
        "adc.b    %A0"    "\n\t"

        : "+r" (result)
    );

    return result;
#else
    return (x << 1) | (x >> 7);
#endif
}

/*
 *
 * Rotate the given 8-bit value to the right by 1 bit
 * ... x - the 8-bit value to be rotated
 * Return: the rotated 8-bit value
 *
 */
static inline uint8_t rot8r1(uint8_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint8_t result = x;

    __asm__(
        "bit       #1,    %A0"    "\n\t"
        "rrc.b    %A0        "    "\n\t"

        : "+r" (result)
    );

    return result;
#else
    return (x >> 1) | (x << 7);
#endif
}


/*
 *
 * Rotate the given 8-bit value to the left by 2 bits
 * ... x - the 8-bit value to be rotated
 * Return: the rotated 8-bit value
 *
 */
static inline uint8_t rot8l2(uint8_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    return rot8l1(rot8l1(x));
#else
    return (x << 2) | (x >> 6);
#endif
}

/*
 *
 * Rotate the given 8-bit value to the right by 2 bits
 * ... x - the 8-bit value to be rotated
 * Return: the rotated 8-bit value
 *
 */
static inline uint8_t rot8r2(uint8_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    return rot8r1(rot8r1(x));
#else
    return (x >> 2) | (x << 6);
#endif
}


/*
 *
 * Rotate the given 8-bit value to the left by 3 bits
 * ... x - the 8-bit value to be rotated
 * Return: the rotated 8-bit value
 *
 */
static inline uint8_t rot8l3(uint8_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    return rot8l1(rot8l1(rot8l1(x)));
#else
    return (x << 3) | (x >> 5);
#endif
}

/*
 *
 * Rotate the given 8-bit value to the right by 3 bits
 * ... x - the 8-bit value to be rotated
 * Return: the rotated 8-bit value
 *
 */
static inline uint8_t rot8r3(uint8_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    return rot8r1(rot8r1(rot8r1(x)));
#else
    return (x >> 3) | (x << 5);
#endif
}


/*
 *
 * Rotate the given 8-bit value to the left by 4 bits
 * ... x - the 8-bit value to be rotated
 * Return: the rotated 8-bit value
 *
 */
static inline uint8_t rot8l4(uint8_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    return rot8l1(rot8l1(rot8l1(rot8l1(x))));
#else
    return (x << 4) | (x >> 4);
#endif
}

/*
 *
 * Rotate the given 8-bit value to the right by 4 bits
 * ... x - the 8-bit value to be rotated
 * Return: the rotated 8-bit value
 *
 */
static inline uint8_t rot8r4(uint8_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    return rot8r1(rot8r1(rot8r1(rot8r1(x))));
#else
    return (x >> 4) | (x << 4);
#endif
}


#endif /* ROT8_H */
