/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>,
 *                    Jason Smith <jksmit3@tycho.ncsc.mil>
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
 * ... code for rotations of 32-bit values. Teach the compilers how to
 * ... efficiently rotate 32-bit values.
 *
 */


#ifndef ROT32_H
#define ROT32_H


/*
 *
 * Enable ASM rotations
 *
 */
#define ENABLE_ASM_ROT


/*
 *
 * Rotate the given 32-bit value to the left by 1 bit
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l1(uint32_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint32_t result = x;

    /* Shift a zero into the least significant bit, then correct by
     * adding in the carry */

    __asm__(
        "rla    %A0"    "\n\t"
        "rlc    %B0"    "\n\t"
        "adc    %A0"    "\n\t"

        : "+r" (result)
    );

    return result;
#else
    return (x << 1) | (x >> 31);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 1 bit
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r1(uint32_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint32_t result = x;

    /*
     * The easiest way to get the least significant bit into the carry
     * would be the following:
     *
     * bit #1, x0
     *
     * This should use the constant generator and therefore take one cycle
     * and one word of code. It appears the mspdebug simulator before
     * version 0.23 doesn't count this correctly and counts three
     * cycles. The following alternative uses two words of code and a
     * temporary register, but only two cycles:
     *
     * mov x0, tmp
     * rrc tmp
     *
     */

    __asm__(
        "bit     #1,    %A0"    "\n\t"
        "rrc    %B0        "    "\n\t"
        "rrc    %A0        "    "\n\t"

        : "+r" (result)
    );

    return result;
#else
    return (x >> 1) | (x << 31);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 8 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l8(uint32_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint32_t result = x;
    uint16_t tmp;

    /*
    * Start with the following bytes:
     *
     * x_3 x_2 x_1 x_0
     *
     * Swap the bytes and then use an xor swap to exchange x_3 and x_1
     */

    __asm__(
        "swpb     %B0        "    "\n\t"
        "swpb     %A0        "    "\n\t"

        "mov.b    %B0,     %1"    "\n\t"
        "xor.b    %A0,     %1"    "\n\t"

        "xor       %1,    %B0"    "\n\t"
        "xor       %1,    %A0"    "\n\t"

        : "+r" (result), "=r" (tmp)
    );

    return result;
#else
    return (x << 8) | (x >> 24);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 8 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r8(uint32_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint32_t result = x;
    uint16_t tmp;

    /*
     * Start with the following bytes:
     *
     * x_3 x_2 x_1 x_0
     *
     * Save the least significant byte in a temp register
     *
     * Swap the bytes in the two least significant words, giving
     *
     * x_2 x_3 x_0 x_1
     *
     * Get the bytes in the right word with a pair of xors:
     *
     * xor.b gives:
     *
     * x_2 x_3 0 x_1^x_3
     *
     * xor gives:
     * x_2 x_3 x_2 x_1
     *
     * Swap the temp variable and perform the pair of xors again to
     * get the following:
     *
     * 0   x_3 ...
     * x_0 x_3
     *
     */

    __asm__(
        "mov.b    %A0,    %1"    "\n\t"
        "xor.b    %B0,    %1"    "\n\t"

        "swpb     %A0       "    "\n\t"
        "swpb     %B0       "    "\n\t"
        "swpb      %1       "    "\n\t"

        "xor       %1,   %A0"    "\n\t"
        "xor       %1,   %B0"    "\n\t"

        : "+r" (result), "=r" (tmp)
    );

    return result;
#else
    return (x >> 8) | (x << 24);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 16 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l16(uint32_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint32_t result = x;

    __asm__(
        "xor    %A0,    %B0"    "\n\t"
        "xor    %B0,    %A0"    "\n\t"
        "xor    %A0,    %B0"    "\n\t"

        : "+r" (result)
    );

    return result;
#else
    return (x << 16) | ( x >> 16);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 16 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r16(uint32_t x)
{
#if defined(MSP) && defined(ENABLE_ASM_ROT)
    uint32_t result = x;

    __asm__(
        "xor    %A0,    %B0"    "\n\t"
        "xor    %B0,    %A0"    "\n\t"
        "xor    %A0,    %B0"    "\n\t"

        : "+r" (result)
    );

    return result;
#else
    return (x << 16) | ( x >> 16);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 2 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l2(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32l1(rot32l1(x));
#else
    return (x << 2) | (x >> 30);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 2 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r2(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32r1(rot32r1(x));
#else
    return (x >> 2) | (x << 30);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 3 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l3(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32l1(rot32l1(rot32l1(x)));
#else
    return (x << 3) | (x >> 29);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 3 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r3(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32r1(rot32r1(rot32r1(x)));
#else
    return (x >> 3) | (x << 29);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 4 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l4(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32l1(rot32l1(rot32l1(rot32l1(x))));
#else
    return (x << 4) | (x >> 28);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 4 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r4(uint32_t x)
{
#if (defined(AVR) && defined(ENABLE_ASM_ROT))
    uint32_t result = x;
    uint8_t tmp1, tmp2;

    __asm__(
        "swap    %A0         "    "\n\t"
        "swap    %B0         "    "\n\t"
        "swap    %C0         "    "\n\t"
        "swap    %D0         "    "\n\t"

        "mov      %1,     %A0"    "\n\t"
        "andi     %1,    0xF0"    "\n\t"

        "andi    %A0,    0x0F"    "\n\t"
        "mov      %2,     %B0"    "\n\t"
        "andi     %2,    0xF0"    "\n\t"
        "eor     %A0,      %2"    "\n\t"

        "andi    %B0,    0x0F"    "\n\t"
        "mov      %2,     %C0"    "\n\t"
        "andi     %2,    0xF0"    "\n\t"
        "eor     %B0,      %2"    "\n\t"

        "andi    %C0,    0x0F"    "\n\t"
        "mov      %2,     %D0"    "\n\t"
        "andi     %2,    0xF0"    "\n\t"
        "eor     %C0,      %2"    "\n\t"

        "andi    %D0,    0x0F"    "\n\t"
        "eor     %D0,      %1"    "\n\t"

        : "+r" (result), "=r" (tmp1), "=r" (tmp2)
    );

    return result;
#elif (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32r1(rot32r1(rot32r1(rot32r1(x))));
#else
    return (x >> 4) | (x << 28);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 5 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l5(uint32_t x)
{
#if defined(AVR)
    uint32_t result = x;
    uint8_t t0, t1, t2;

    __asm__(
        "push r1" "\n\t"

        "ldi %1, 32"      "\n\t"

        "mov %2, %B0"     "\n\t"
        "mov %3, %D0"     "\n\t"

        "mul %A0, %1"     "\n\t"
        "movw %A0, r0"    "\n\t"

        "mul %C0, %1"     "\n\t"
        "movw %C0, r0"    "\n\t"

        "mul %2, %1"      "\n\t"
        "eor %B0, r0"     "\n\t"
        "eor %C0, r1"     "\n\t"

        "mul %3, %1"      "\n\t"
        "eor %D0, r0"     "\n\t"
        "eor %A0, r1"     "\n\t"

        "pop r1"          "\n\t"

        : "+r" (result), "=a" (t0), "=r" (t1), "=r" (t2)
    );

    return result;
#elif (defined(MSP) && defined(ENABLE_ASM_ROT))
    /* 
     * Options:
     *  1) rotate 5 times to the left by 1:
     *      rot32l1(rot32l1(rot32l1(rot32l1(rot32l1(x)))))
     * 
     *  2) rotate to the left by 8 and then rotate 3 times to the right by 1:
     *      rot32r1(rot32r1(rot32r1(rot32l8(x))))
     *
     * Results:
     *  - MSP: same exectution time for 1) and 2); but 2) uses auxiliary 
     *           register
     */
    return rot32l1(rot32l1(rot32l1(rot32l1(rot32l1(x)))));
#else
    return (x << 5) | (x >> 27);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 5 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r5(uint32_t x)
{
#if defined(AVR)
    /* 
     * Options:
     *  1) rotate 5 times to the right by 1
     *      rot32r1(rot32r1(rot32r1(rot32r1(rot32r1(x)))))
     *
     *  2) rotate to the right by 8 and then rotate 3 times to the left by 1:
     *      rot32l1(rot32l1(rot32l1(rot32r8(x))))
     *
     * Results:
     *  - AVR: 1) is 9 cycles slower than 2)
     */
    return rot32l1(rot32l1(rot32l1(rot32r8(x))));
#elif defined(MSP) && defined(ENABLE_ASM_ROT)
    /* 
     * Options:
     *  1) rotate 5 times to the right by 1
     *      rot32r1(rot32r1(rot32r1(rot32r1(rot32r1(x)))))
     *
     *  2) rotate to the right by 8 and then rotate 3 times to the left by 1:
     *      rot32l1(rot32l1(rot32l1(rot32r8(x))))
     *
     * Results:
     *  - MSP: 1) is 1 cycle faster than 2)
     */
    return rot32r1(rot32r1(rot32r1(rot32r1(rot32r1(x)))));
#else
    return (x >> 5) | (x << 27);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 6 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l6(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32r1(rot32r1(rot32l8(x)));
#else
    return (x << 6) | (x >> 26);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 6 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r6(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32l1(rot32l1(rot32r8(x)));
#else
    return (x >> 6) | (x << 26);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 7 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l7(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32r1(rot32l8(x));
#else
    return (x << 7) | (x >> 25);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 7 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r7(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32l1(rot32r8(x));
#else
    return (x >> 7) | (x << 25);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 9 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l9(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32l1(rot32l8(x));
#else
    return (x << 9) | (x >> 23);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 9 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r9(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32r1(rot32r8(x));
#else
    return (x >> 9) | (x << 23);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 10 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l10(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32l1(rot32l1(rot32l8(x)));
#else
    return (x << 10) | (x >> 22);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 10 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r10(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32r1(rot32r1(rot32r8(x)));
#else
    return (x >> 10) | (x << 22);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 11 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l11(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    /* 
     * Options:
     *  1) rotate to the left by 8 and then rotate 3 times to the left by 1:
     *      rot32l1(rot32l1(rot32l1(rot32l8(x))))
     * 
     *  2) rotate left by 16 and then rotate 5 times to the right by 1:
     *      rot32r1(rot32r1(rot32r1(rot32r1(rot32r1(rot32l16(x))))))
     * Results:
     *  - AVR: 1) is 12 cycles faster than 2)
     *  - MSP: 1) is 3 cycles faster than 2)
     */
    return rot32l1(rot32l1(rot32l1(rot32l8(x))));
#else
    return (x << 11) | (x >> 21);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 11 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r11(uint32_t x)
{
#if defined(AVR)
    /*
     * Options:
     *  1) rotate to the right by 16 and then rotate 5 times to the left by 1:
     *      rot32l1(rot32l1(rot32l1(rot32l1(rot32l1(rot32r16(x))))))
     *
     *  2) rotate to the right by 8 and then rotate 3 times to the right by 1:
     *      rot32r1(rot32r1(rot32r1(rot32r8(x))))
     *
     * Results:
     *  - AVR: 1) is 4 cycles slower than 2)
     */
    return rot32r1(rot32r1(rot32r1(rot32r8(x))));
#elif defined(MSP) && defined(ENABLE_ASM_ROT)
    /*
     * Options:
     *  1) rotate to the right by 16 and then rotate 5 times to the left by 1:
     *      rot32l1(rot32l1(rot32l1(rot32l1(rot32l1(rot32r16(x))))))
     *
     *  2) rotate to the right by 8 and then rotate 3 times to the right by 1:
     *      rot32r1(rot32r1(rot32r1(rot32r8(x))))
     *
     * Results:
     *  - MSP: 1) is 2 cycles slower than 2)
     */
    return  rot32r1(rot32r1(rot32r1(rot32r8(x))));
#else
    return (x >> 11) | (x << 21);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 12 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l12(uint32_t x)
{
#if defined(AVR)
    /*
     * Options:
     *  1) rotate to the left by 8 and then rotate 4 times to the left by 1:
     *      rot32l1(rot32l1(rot32l1(rot32l1(rot32l8(x)))))
     *
     *  2) rotate to the left by 16 and then rotate 4 times to the right by 1:
     *      rot32r1(rot32r1(rot32r1(rot32r1(rot32l16(x)))))
     *
     * Results:
     *  - AVR: 1) is 1 cycle faster than 2)
     */
    return rot32l1(rot32l1(rot32l1(rot32l1(rot32l8(x)))));
#elif defined(MSP) && defined(ENABLE_ASM_ROT)
    /*
     * Options:
     *  1) rotate to the left by 8 and then rotate 4 times to the left by 1:
     *      rot32l1(rot32l1(rot32l1(rot32l1(rot32l8(x)))))
     *
     *  2) rotate to the left by 16 and then rotate 4 times to the right by 1:
     *      rot32r1(rot32r1(rot32r1(rot32r1(rot32l16(x)))))
     *
     * Results:
     *  - MSP: 1) is 3 cycles slower than 2)
     */
    return rot32r1(rot32r1(rot32r1(rot32r1(rot32l16(x)))));
#else
    return (x << 12) | (x >> 20);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 12 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r12(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    /*
     * Options:
     *  1) rotate to the right by 8 and then rotate 4 times to the right by 1:
     *      rot32r1(rot32r1(rot32r1(rot32r1(rot32r8(x)))))
     *
     *  2) rotate to the right by 16 and then rotate 4 times to the left by 1:
     *      rot32l1(rot32l1(rot32l1(rot32l1(rot32r16(x)))))
     *
     * Results:
     *  - AVR: 1) is 7 cycles slower than 2)
     *  - MSP: 1) is 4 cycles slower than 2)
     */
    return rot32l1(rot32l1(rot32l1(rot32l1(rot32r16(x)))));
#else
    return (x >> 12) | (x << 20);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 13 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l13(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32r1(rot32r1(rot32r1(rot32l16(x))));
#else
    return (x << 13) | (x >> 19);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 13 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r13(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32l1(rot32l1(rot32l1(rot32r16(x))));
#else
    return (x >> 13) | (x << 19);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 14 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l14(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32r1(rot32r1(rot32l16(x)));
#else
    return (x << 14) | (x >> 18);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 14 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r14(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32l1(rot32l1(rot32r16(x)));
#else
    return (x >> 14) | (x << 18);
#endif
}


/*
 *
 * Rotate the given 32-bit value to the left by 15 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32l15(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32r1(rot32l16(x));
#else
    return (x << 15) | (x >> 17);
#endif
}

/*
 *
 * Rotate the given 32-bit value to the right by 15 bits
 * ... x - the 32-bit value to be rotated
 * Return: the rotated 32-bit value
 *
 */
static inline uint32_t rot32r15(uint32_t x)
{
#if (defined(AVR)) || (defined(MSP) && defined(ENABLE_ASM_ROT))
    return rot32l1(rot32r16(x));
#else
    return (x >> 15) | (x << 17);
#endif
}


#endif /* ROT32_H */
