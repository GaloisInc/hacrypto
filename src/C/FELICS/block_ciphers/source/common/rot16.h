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
 * GCC compilers for AVR (avr-gcc) and MSP (msp430-gcc) do not generate optimal
 * ... code for rotations of 16-bit values. Teach the compilers how to
 * ... efficiently rotate 16-bit values.
 *
 */


#ifndef ROT16_H
#define ROT16_H


/*
 *
 * Enable ASM rotations
 *
 */
#define ENABLE_ASM_ROT


/*
 *
 * Rotate the given 16-bit value to the left by 1 bit
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16l1(uint16_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint16_t result = x;

    __asm__(
        "rla    %A0"    "\n\t"
        "adc    %A0"    "\n\t"

        : "+r" (result)
    );

    return result;
#else
    return (x << 1) | (x >> 15);
#endif
}

/*
 *
 * Rotate the given 16-bit value to the right by 1 bit
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16r1(uint16_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint16_t result = x;

    __asm__(
        "bit     #1,    %A0"    "\n\t"
        "rrc    %A0        "    "\n\t"

        : "+r" (result)
    );

    return result;
#else
    return (x >> 1) | (x << 15);
#endif
}


/*
 *
 * Rotate the given 16-bit value to the left by 8 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16l8(uint16_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint16_t result = x;

    __asm__(
        "swpb    %A0"    "\n\t"

        : "+r" (result)
    );

    return result;
#else
    return (x << 8) | (x >> 8);
#endif
}

/*
 *
 * Rotate the given 16-bit value to the right by 8 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16r8(uint16_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint16_t result = x;

    __asm__(
        "swpb    %A0"    "\n\t"

        : "+r" (result)
    );

    return result;
#else
    return (x >> 8) | (x << 8);
#endif
}


/*
 *
 * Rotate the given 16-bit value to the left by 4 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16l4(uint16_t x)
{
#if defined(AVR) && defined(ENABLE_ASM_ROT)
    uint16_t result = x;
    uint8_t tmp;

    __asm__(
        "swap    %A0         "    "\n\t"
        "swap    %B0         "    "\n\t"

        "mov      %1,     %A0"    "\n\t"
        "eor      %1,     %B0"    "\n\t"
        "andi     %1,    0x0F"    "\n\t"

        "eor     %A0,      %1"    "\n\t"
        "eor     %B0,      %1"    "\n\t"

        : "+r" (result), "=r" (tmp)
    );

    return result;
#elif defined(AVR)
    return rot16l1(rot16l1(rot16l1(rot16l1(x))));
#elif defined(MSP) && defined(ENABLE_ASM_ROT)
    /*
     * Options:
     *  1) rotate 4 times to the left by 1:
     *      rot16l1(rot16l1(rot16l1(rot16l1(x))))
     *
     *  2) rotate to the left by 8 and then rotate 4 times to the right by 1:
     *      rot16r1(rot16r1(rot16r1(rot16r1(rot16l8(x)))))
     *
     * Results:
     *  - MSP: 1) is 1 cycle faster than 2)
     */
     return rot16l1(rot16l1(rot16l1(rot16l1(x))));
#else
    return (x << 4) | (x >> 12);
#endif
}

/*
 *
 * Rotate the given 16-bit value to the right by 4 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16r4(uint16_t x)
{
#if defined(AVR) && defined(ENABLE_ASM_ROT)
    uint16_t result = x;
    uint8_t tmp;

    __asm__(
        "swap    %A0         "    "\n\t"
        "swap    %B0         "    "\n\t"

        "mov      %1,     %A0"    "\n\t"
        "eor      %1,     %B0"    "\n\t"
        "andi     %1,    0xF0"    "\n\t"

        "eor     %A0,      %1"    "\n\t"
        "eor     %B0,      %1"    "\n\t"

        : "+r" (result), "=r" (tmp)
    );

    return result;
#elif defined(AVR)
    /*
     * Options:
     *  1) rotate 4 times to the right by 1:
     *      rot16r1(rot16r1(rot16r1(rot16r1(x))))
     *
     *  2) rotate to the right by 8 and then rotate 4 times to the left by 1:
     *      rot16l1(rot16l1(rot16l1(rot16l1(rot16r8(x)))))
     *
     * Results:
     *  - AVR: 1) is 1 cycle slower than 2)
     */
    return rot16l1(rot16l1(rot16l1(rot16l1(rot16r8(x)))));
#elif defined(MSP) && defined(ENABLE_ASM_ROT)
    /*
     * Options:
     *  1) rotate 4 times to the right by 1:
     *      rot16r1(rot16r1(rot16r1(rot16r1(x))))
     *
     *  2) rotate to the right by 8 and then rotate 4 times to the left by 1:
     *      rot16l1(rot16l1(rot16l1(rot16l1(rot16r8(x)))))
     *
     * Results:
     *  - MSP: 1) is 1 cycle faster than 2)
     */
    return rot16r1(rot16r1(rot16r1(rot16r1(x))));
#else
    return (x >> 4) | (x << 12);
#endif
}


/*
 *
 * Rotate the given 16-bit value to the left by 2 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16l2(uint16_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot16l1(rot16l1(x));
#else
    return (x << 2) | (x >> 14);
#endif
}

/*
 *
 * Rotate the given 16-bit value to the right by 2 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16r2(uint16_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot16r1(rot16r1(x));
#else
    return (x >> 2) | (x << 14);
#endif
}


/*
 *
 * Rotate the given 16-bit value to the left by 3 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16l3(uint16_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot16l1(rot16l1(rot16l1(x)));
#else
    return (x << 3) | (x >> 13);
#endif
}

/*
 *
 * Rotate the given 16-bit value to the right by 3 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16r3(uint16_t x)
{
#if (defined(AVR) && defined(ENABLE_ASM_ROT))
    return rot16l1(rot16r4(x));
#elif (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot16r1(rot16r1(rot16r1(x)));
#else
    return (x >> 3) | (x << 13);
#endif
}


/*
 *
 * Rotate the given 16-bit value to the left by 5 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16l5(uint16_t x)
{
#if (defined(AVR) && defined(ENABLE_ASM_ROT))
    /*
     * Options:
     *  1) rotate to the left by 4 and then rotate to the left by 1:
     *      rot16l1(rot16l4(x))
     * 
     *  2) rotate to the left by 8 and then rotate 3 times to the right by 1:
     *      rot16r1(rot16r1(rot16r1(rot16l8(x))))
     *
     * Results:
     *  - AVR: 1) is 5 cycles faster than 2)
     */
    return rot16l1(rot16l4(x));
#elif (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    /*
     * Options:
     *  1) rotate 5 times to the left by 1:
     *      rot16l1(rot16l1(rot16l1(rot16l1(rot16l1(x)))))
     * 
     *  2) rotate to the left by 8 and then rotate 3 times to the right by 1:
     *      rot16r1(rot16r1(rot16r1(rot16l8(x))))
     *
     * Results:
     *  - AVR: same exectution time for 1) and 2)
     *  - MSP: 1) is 3 cycles slower than 2)
     */
    return rot16r1(rot16r1(rot16r1(rot16l8(x))));
#else
    return (x << 5) | (x >> 11);
#endif
}

/*
 *
 * Rotate the given 16-bit value to the right by 5 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16r5(uint16_t x)
{
#if (defined(AVR) && defined(ENABLE_ASM_ROT))
    /*
     * Options:
     *  1) rotate to the right by 4 and then rotate to the right by 1:
     *      rot16r1(rot16r4(x))
     * 
     *  2) rotate to the right by 8 and then rotate 3 times to the left by 1:
     *      rot16l1(rot16l1(rot16l1(rot16r8(x))))
     *
     * Results:
     *  - AVR: 1) is 1 cycle faster than 2)
     */
     return rot16r1(rot16r4(x));
#elif (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    /*
     * Options:
     *  1) rotate 5 times to the right by 1:
     *      rot16r1(rot16r1(rot16r1(rot16r1(rot16r1(x)))))
     * 
     *  2) rotate to the right by 8 and then rotate 3 times to the left by 1:
     *      rot16l1(rot16l1(rot16l1(rot16r8(x))))
     *
     * Results:
     *  - AVR: 1) is 8 cycles slower than 2)
     *  - MSP: 1) is 3 cycle slower than 2)
     */
    return rot16l1(rot16l1(rot16l1(rot16r8(x))));
#else
    return (x >> 5) | (x << 11);
#endif
}


/*
 *
 * Rotate the given 16-bit value to the left by 6 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16l6(uint16_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot16r1(rot16r1(rot16l8(x)));
#else
    return (x << 6) | (x >> 10);
#endif
}

/*
 *
 * Rotate the given 16-bit value to the right by 6 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16r6(uint16_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot16l1(rot16l1(rot16r8(x)));
#else
    return (x >> 6) | (x << 10);
#endif
}


/*
 *
 * Rotate the given 16-bit value to the left by 7 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16l7(uint16_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot16r1(rot16l8(x));
#else
    return (x << 7) | (x >> 9);
#endif
}

/*
 *
 * Rotate the given 16-bit value to the right by 7 bits
 * ... x - the 16-bit value to be rotated
 * Return: the rotated 16-bit value
 *
 */
static inline uint16_t rot16r7(uint16_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot16l1(rot16r8(x));
#else
    return (x >> 7) | (x << 9);
#endif
}


#endif /* ROT16_H */
