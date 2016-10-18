/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu> and 
 * André Stemper <andre.stemper@uni.lu>
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

#ifdef AVR
/*----------------------------------------------------------------------------*/
/* Optimized for AVR                                                          */
/* rc_tab and sbox are assumed to be aligned on a 256 byte boundary.          */
/* __attribute__ ((aligned (256)))                                            */
/*----------------------------------------------------------------------------*/
#include "constants.h"
/*----------------------------------------------------------------------------*/
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
   asm volatile (\
        /*--------------------------------------------------*/
        /* Registers allocation:                            */
        /* r0-r3   : r0,r1,r2,r3                            */
        /* r4-r15  :                                        */
        /* r16     : byte_counter                           */
        /* r17     : round_constant_table_index             */
        /* r18     :                                        */
        /* r19     :                                        */
        /* r20     :                                        */
        /* r21     :                                        */
        /* r22     :                                        */
        /* r23     :                                        */
        /* r24     :                                        */
        /* r25     : temporary                              */
        /* r26:r27 : X Key                                  */
        /* r28:r29 : Y roundKeys (must support ldd y+q)     */
        /* r30:r31 : Z sbox (must support lpm)              */
        /*--------------------------------------------------*/
        /* Store all modified registers */
        /*--------------------------------------------------*/
        "push  r0;       \n"
        "push  r2;       \n"
        "push  r3;       \n"
        "push r16;       \n"
        "push r17;       \n"
        "push r25;       \n"
        "push r26;       \n" 
        "push r27;       \n" 
        "push r28;       \n"
        "push r29;       \n"
        "push r30;       \n"
        "push r31;       \n"
        /*--------------------------------------------------*/
        "clr  r16;       \n" /* byte_counter = 0            */ 
        "clr  r17;       \n" /* round_constant_table_index=0*/ 
        "movw r28,   r30;\n" /* pointer_y = pointer_z       */
        /*--------------------------------------------------*/
        "ld   r25,    x+;\n" /* memcpy(pointer_z, 
                                            pointer_x, 16); */
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        "ld   r25,    x+;\n"
        "st   z+,    r25;\n"
        /*--------------------------------------------------*/
        "movw r26,   r28;\n"  /* pointer_x = pointer_y      */
        "adiw r28,    12;\n"  /* pointer_y += 12;           */
        /*--------------------------------------------------*/
        "ldi  r16,    10;\n"
"key_schedule_round:     \n"       
        /*--------------------------------------------------*/
        "ld   r3,     y+;\n" /*   r3 = *(pointer_y++);      */
        "ld   r0,     y+;\n" /*   r0 = *(pointer_y++);      */
        "ld   r1,     y+;\n" /*   r1 = *(pointer_y++);      */
        "ld   r2,     y+;\n" /*   r2 = *(pointer_y++);      */
        /*--------------------------------------------------*/
        "ldi  r31,   hi8(sbox);\n" 
        "mov  r30,   r0; \n" /* r0=READ_SBOX_BYTE(sbox[r0]);*/
        "lpm  r0,    z;  \n"
        "mov  r30,   r1; \n" /* r1=READ_SBOX_BYTE(sbox[r1]);*/ 
        "lpm  r1,    z;  \n"
        "mov  r30,   r2; \n" /* r2=READ_SBOX_BYTE(sbox[r2]);*/
        "lpm  r2,    z;  \n"
        "mov  r30,   r3; \n" /* r3=READ_SBOX_BYTE(sbox[r3]);*/
        "lpm  r3,    z;  \n"
        /*--------------------------------------------------*/
        /* r0 ^= READ_KS_BYTE(rc_tab[round_constant_table_index]); */
        "ldi  r31,   hi8(rc_tab);\n"
        "mov  r30,   r17;\n"    
        "lpm  r25,     z;\n"
        "eor   r0,   r25;\n"   
        /*--------------------------------------------------*/
        "inc  r17;       \n" /*round_constant_table_index++;*/
        /*--------------------------------------------------*/
        "ld   r25,    x+;\n"  /* *(pointer_y+0) = 
                                       *(pointer_x++) ^ r0; */
        "eor  r25,    r0;\n"
        "st   y,     r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+1) = 
                                       *(pointer_x++) ^ r1; */
        "eor  r25,    r1;\n"
        "std  y+1,   r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+2) = 
                                       *(pointer_x++) ^ r2; */
        "eor  r25,    r2;\n"
        "std  y+2,   r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+3) = 
                                       *(pointer_x++) ^ r3; */
        "eor  r25,    r3;\n"
        "std  y+3,   r25;\n"
        /*--------------------------------------------------*/
        "ld   r0,     y+;\n"  /* r0 = *(pointer_y++);       */
        "ld   r1,     y+;\n"  /* r1 = *(pointer_y++);       */
        "ld   r2,     y+;\n"  /* r2 = *(pointer_y++);       */
        "ld   r3,     y+;\n"  /* r3 = *(pointer_y++);       */
        /*--------------------------------------------------*/
        "ld   r25,    x+;\n"  /* *(pointer_y+0) = 
                                       *(pointer_x++) ^ r0; */
        "eor  r25,    r0;\n"
        "st   y,     r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+1) = 
                                       *(pointer_x++) ^ r1; */
        "eor  r25,    r1;\n"
        "std  y+1,   r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+2) = 
                                       *(pointer_x++) ^ r2; */
        "eor  r25,    r2;\n"
        "std  y+2,   r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+3) = 
                                       *(pointer_x++) ^ r3; */
        "eor  r25,    r3;\n"
        "std  y+3,   r25;\n"
        /*--------------------------------------------------*/
        "ld   r0,     y+;\n"  /* r0 = *(pointer_y++);       */
        "ld   r1,     y+;\n"  /* r1 = *(pointer_y++);       */
        "ld   r2,     y+;\n"  /* r2 = *(pointer_y++);       */
        "ld   r3,     y+;\n"  /* r3 = *(pointer_y++);       */
        /*--------------------------------------------------*/
        "ld   r25,    x+;\n"  /* *(pointer_y+0) = 
                                       *(pointer_x++) ^ r0; */
        "eor  r25,    r0;\n"
        "st   y,     r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+1) = 
                                       *(pointer_x++) ^ r1; */
        "eor  r25,    r1;\n"
        "std  y+1,   r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+2) = 
                                       *(pointer_x++) ^ r2; */
        "eor  r25,    r2;\n"
        "std  y+2,   r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+3) = 
                                       *(pointer_x++) ^ r3; */
        "eor  r25,    r3;\n"
        "std  y+3,   r25;\n"
        /*--------------------------------------------------*/
        "ld   r0,     y+;\n"  /* r0 = *(pointer_y++);       */
        "ld   r1,     y+;\n"  /* r1 = *(pointer_y++);       */
        "ld   r2,     y+;\n"  /* r2 = *(pointer_y++);       */
        "ld   r3,     y+;\n"  /* r3 = *(pointer_y++);       */
        /*--------------------------------------------------*/
        "ld   r25,    x+;\n"  /* *(pointer_y+0) = 
                                       *(pointer_x++) ^ r0; */
        "eor  r25,    r0;\n"
        "st   y,     r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+1) = 
                                       *(pointer_x++) ^ r1; */
        "eor  r25,    r1;\n"
        "std  y+1,   r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+2) = 
                                       *(pointer_x++) ^ r2; */
        "eor  r25,    r2;\n"
        "std  y+2,   r25;\n"
        "ld   r25,    x+;\n"  /* *(pointer_y+3) = 
                                       *(pointer_x++) ^ r3; */
        "eor  r25,    r3;\n"
        "std  y+3,   r25;\n"
        /*--------------------------------------------------*/
        "dec  r16;       \n"  /* byte_counter -=1;          */
        /*--------------------------------------------------*/
        /* while (byte_counter != 10);                      */
        "breq key_schedule_done;\n"
        "jmp key_schedule_round;\n"
"key_schedule_done:\n"
        /*--------------------------------------------------*/
        /* Restore all modified registers                   */
        /*--------------------------------------------------*/
        "pop  r31;       \n"
        "pop  r30;       \n"
        "pop  r29;       \n"
        "pop  r28;       \n"
        "pop  r27;       \n" 
        "pop  r26;       \n" 
        "pop  r25;       \n" 
        "pop  r17;       \n"
        "pop  r16;       \n"
        "pop  r3;        \n"
        "pop  r2;        \n"
        "clr  r1;        \n" 
        "pop  r0;        \n"
        /*--------------------------------------------------*/
    :
    : [key] "x" (key), [roundKeys] "z" (roundKeys), [rc_tab] "" (rc_tab), [sbox] "" (sbox)); 
}
#else

#ifdef MSP
/*----------------------------------------------------------------------------*/
/* Optimized for MSP                                                          */
/*----------------------------------------------------------------------------*/
#include <stdint.h>
#include <string.h>
#include "cipher.h"
#include "constants.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile (\
        /*---------------------------------------------------------------*/
        /* r5  - Working temporary                                       */
        /* r6  - Temporary 1                                             */
        /* r7  - Temporary 2                                             */
        /* r8  - Temporary 3                                             */
        /* r9  - Temporary 4                                             */
        /* r10 - RoundKeys imm                                           */
        /* r12 - rc_tab                                                  */
        /* r13 - Loop counter                                            */
        /* r14 - RoundKeys i                                             */
        /* r15 - Key                                                     */
        /*---------------------------------------------------------------*/
        /* Store all modified registers                                  */
        /*---------------------------------------------------------------*/
        "push   r5;                 \n"
        "push   r6;                 \n"
        "push   r7;                 \n"
        "push   r8;                 \n"
        "push   r9;                 \n"
        "push   r10;                \n"
        "push   r12;                \n"
        "push   r13;                \n"
        "push   r14;                \n"
        "push   r15;                \n"
        /*---------------------------------------------------------------*/
        "mov    %[key],         r15;\n"
        "mov    %[rc_tab],      r12;\n"
        "mov    %[roundKeys],   r14;\n" 
        "mov    r14,            r10;\n" 
        /*---------------------------------------------------------------*/
        /* Add round key                                                 */
        /*---------------------------------------------------------------*/
        "mov    @r15+,       0(r14);\n" /* 0                             */ 
        "mov    @r15+,       2(r14);\n" /* 2                             */
        "mov    @r15+,       4(r14);\n" /* 4                             */
        "mov    @r15+,       6(r14);\n" /* 6                             */
        "mov    @r15+,       8(r14);\n" /* 8                             */
        "mov    @r15+,      10(r14);\n" /* 10                            */
        "mov    @r15+,      12(r14);\n" /* 11                            */
        "mov    @r15+,      14(r14);\n" /* 12                            */
        /*---------------------------------------------------------------*/
        "add    #16,            r14;\n"
        /*---------------------------------------------------------------*/
        "mov    #10,            r13;\n" /* 10 rounds                     */
"round_loop:\n"
        /* tmp1 = roundKeys[imm+13];                                     */ 
        "mov.b   13(r10),        r6;\n" 
        /* tmp2 = roundKeys[imm+14];                                     */ 
        "mov.b   14(r10),        r7;\n" 
        /* tmp3 = roundKeys[imm+15];                                     */
        "mov.b   15(r10),        r8;\n" 
        /* tmp4 = roundKeys[imm+12];                                     */ 
        "mov.b   12(r10),        r9;\n" 
        /* roundKeys[i + 0]=sbox[tmp1]^roundKeys[imm++]^rc_tab[round++]; */
        "mov.b  @r12+,           r5;\n" /* r5=[rc_tab++]                 */
        "xor.b  @r10+,           r5;\n" /* r5=[imm++]^r5                 */
        "mov.b  sbox(r6),        r6;\n" /* r6=sbox(r6)                   */
        "xor.b  r6,              r5;\n" /* r6=r6^r5                      */
        "mov.b  r5,         15(r10);\n" /* roundKeys[i+0]                */
        /* roundKeys[i + 1]=sbox[tmp2]^roundKeys[imm++];                 */
        "mov.b  sbox(r7),        r5;\n" /* r5=sbox(r7)                   */
        "xor.b  @r10+,           r5;\n" /* r5=[imm++]^r5                 */
        "mov.b  r5,         15(r10);\n" /* roundKeys[i+1] = r5;          */
        /* roundKeys[i + 2]=sbox[tmp3]^roundKeys[imm++];                 */
        "mov.b  sbox(r8),        r5;\n" /* r5=sbox(r8)                   */
        "xor.b  @r10+,           r5;\n" /* r5=[imm++]^r5                 */
        "mov.b  r5,         15(r10);\n" /* roundKeys[i+2] = r5;          */
        /* roundKeys[i + 3]=sbox[tmp4]^roundKeys[imm++];                 */
        "mov.b  sbox(r9),        r5;\n" /* r5=sbox(r9)                   */
        "xor.b  @r10+,           r5;\n" /* r5=[imm++]^r5                 */
        "mov.b  r5,         15(r10);\n" /* roundKeys[i+3] = r5;          */
        /* roundKeys[i + 4] = roundKeys[imm++]^roundKeys[ip++];          */
        /* roundKeys[i + 5] = roundKeys[imm++]^roundKeys[ip++];          */ 
        "mov   @r10+,           r5;\n" /* roundKeys[imm++]               */
        "xor   @r14+,           r5;\n" /* r5=r5^roundKeys[ip++];         */
        "mov   r5,         15(r10);\n" /* roundKeys[i+4] = r5;           */
        /* roundKeys[i + 6] = roundKeys[imm++]^roundKeys[ip++];          */ 
        /* roundKeys[i + 7] = roundKeys[imm++]^roundKeys[ip++];          */
        "mov   @r10+,           r5;\n" /* roundKeys[imm++]               */
        "xor   @r14+,           r5;\n" /* r5=r5^roundKeys[ip++];         */
        "mov   r5,         15(r10);\n" /* roundKeys[i+6] = r5;           */
        /* roundKeys[i + 8] = roundKeys[imm++]^roundKeys[ip++];          */ 
        /* roundKeys[i + 9] = roundKeys[imm++]^roundKeys[ip++];          */
        "mov   @r10+,           r5;\n" /* roundKeys[imm++]               */
        "xor   @r14+,           r5;\n" /* r5=r5^roundKeys[ip++];         */
        "mov   r5,         15(r10);\n" /* roundKeys[i+8] = r5;           */
        /* roundKeys[i +10] = roundKeys[imm++]^roundKeys[ip++];          */ 
        /* roundKeys[i +11] = roundKeys[imm++]^roundKeys[ip++];          */
        "mov   @r10+,           r5;\n" /* roundKeys[imm++]               */
        "xor   @r14+,           r5;\n" /* r5=r5^roundKeys[ip++];         */
        "mov   r5,         15(r10);\n" /* roundKeys[i+10] = r5;          */
        /* roundKeys[i +12] = roundKeys[imm++]^roundKeys[ip++];          */
        /* roundKeys[i +13] = roundKeys[imm++]^roundKeys[ip++];          */
        "mov   @r10+,           r5;\n" /* roundKeys[imm++]               */
        "xor   @r14+,           r5;\n" /* r5=r5^roundKeys[ip++];         */
        "mov   r5,         15(r10);\n" /* roundKeys[i+12] = r5;          */
        /* roundKeys[i +14] = roundKeys[imm++]^roundKeys[ip++];          */
        /* roundKeys[i +15] = roundKeys[imm++]^roundKeys[ip++];          */
        "mov   @r10+,           r5;\n" /* roundKeys[imm++]               */
        "xor   @r14+,           r5;\n" /* r5=r5^roundKeys[ip++];         */
        "mov   r5,         15(r10);\n" /* roundKeys[i+14] = r5;          */
        /*---------------------------------------------------------------*/
        "add    #4,            r14;\n" /* round keys ip                  */
        /*---------------------------------------------------------------*/
        /* while(loop_counter);                                          */
        "dec    r13;                \n" 
        "jnz    round_loop;         \n"
        /*---------------------------------------------------------------*/
        /* Restore registers                                             */
        /*---------------------------------------------------------------*/
        "pop    r15;                \n"
        "pop    r14;                \n"
        "pop    r13;                \n"
        "pop    r12;                \n"
        "pop    r10;                \n"
        "pop    r9;                 \n"
        "pop    r8;                 \n"
        "pop    r7;                 \n"
        "pop    r6;                 \n"
        "pop    r5;                 \n"
        /*---------------------------------------------------------------*/
    :
    : [key] "m" (key), [roundKeys] "m" (roundKeys), [rc_tab] "" (rc_tab), [sbox] "" (sbox)); 
}

#else
#ifdef ARM
/*----------------------------------------------------------------------------*/
/* Optimized for ARM                                                          */
/*----------------------------------------------------------------------------*/
#include <stdint.h>
#include <string.h>
#include "cipher.h"
#include "constants.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile (\
        /*--------------------------------------------------------------------*/
        /* r0  - key / working temp                                           */
        /* r1  - ptr_l -> roundKeys                                           */
        /* r2  - working temp                                                 */
        /* r3  -                                                              */
        /* r4  - ptr_j -> roundKeys + 3 * 4                                   */
        /* r5  -                                                              */
        /* r6  - Sbox                                                         */
        /* r7  - rc_tab                                                       */
        /* r8  - Loop counter                                                 */
        /* r9  - Temporary 0                                                  */
        /* r10 - Temporary 1                                                  */
        /* r11 - Temporary 2                                                  */
        /* r12 - Temporary 3                                                  */
        /* lr  - 255 for masking                                              */
        /*--------------------------------------------------------------------*/
        /* Store all modified registers                                       */
        /*--------------------------------------------------------------------*/
        "stmdb        sp!,   {r0-r12,lr};              \n" 
        /*--------------------------------------------------------------------*/
        "mov           r0,        %[key];              \n" /* ???             */ 
        "mov           r1,  %[roundKeys];              \n" /* ???             */
        "ldr           r6,         =sbox;              \n"
        "ldr           r7,       =rc_tab;              \n"
        "add           r4,            r1,          #12;\n" /*                 */
        /*--------------------------------------------------------------------*/
        /* memcpy(roundKeys, key, 16);                                        */
        "ldmia         r0,      {r9-r12};              \n"  
        "stmia         r1,      {r9-r12};              \n" 
        /*--------------------------------------------------------------------*/
        "mov           lr,          #255;              \n" /* Byte mask       */
        /* Single load is enough as the result of one step is the input of    */
        /* the next. Using r12 instead of r9 to get rid of mov r12,r9 at the  */
        /* end of the loop.                                                   */ 
        /* t4.v32 = ((uint32_t*)(roundKeys))[j++];                            */
        "ldr            r12,         [r4],          #4;\n" /*r12<-roundKeys[j]*/
        /*--------------------------------------------------------------------*/
        "mov           r8,           #10;              \n"
"key_schedule_loop:                                    \n" 
        /* aes_rotword((uint8_t*)&(t4.v32));                                  */
        "mov            r2,          r12,       lsl#24;\n" /* a << 24         */
        "orr            r9,           r2,    r12,lsr#8;\n" /* | t >> 8        */
        /* t4.v8[0] = READ_SBOX_BYTE(sbox[t4.v8[0]]);                         */
        "and            r2,           lr,           r9;\n" /* [0]             */
        "ldrb           r0,     [r6, r2];              \n" /* r2=sbox(r2)     */
        /* t4.v8[0] ^= READ_KS_BYTE(rc_tab[rc++]);                            */
        "ldrb           r2,          [r7],           #1;\n"
        "eor            r0,            r0,           r2;\n"
        /* t4.v8[1] = READ_SBOX_BYTE(sbox[t4.v8[1]]);                         */
        "and            r2,           lr,     r9,lsr#8;\n" /* [1]             */
        "ldrb           r2,     [r6, r2];              \n" /* r2=sbox(r2)     */
        "orr            r0,           r0,     r2,lsl#8;\n" /*                 */
        /* t4.v8[2] = READ_SBOX_BYTE(sbox[t4.v8[2]]);                         */
        "and            r2,           lr,    r9,lsr#16;\n" /* [1]             */
        "ldrb           r2,     [r6, r2];              \n" /* r2=sbox(r2)     */
        "orr            r0,           r0,    r2,lsl#16;\n" /*                 */
        /* t4.v8[3] = READ_SBOX_BYTE(sbox[t4.v8[3]]);                         */
        "and            r2,           lr,    r9,lsr#24;\n" /* [1]             */
        "ldrb           r2,     [r6, r2];              \n" /* r2=sbox(r2)     */
        "orr            r9,           r0,    r2,lsl#24;\n" /*                 */
        /* t1 = ((uint32_t*)(roundKeys))[l++] ^ t4.v32;                       */
        "ldr            r2,         [r1],           #4;\n" /*(roundKeys))[l++]*/
        "eor            r9,           r9,           r2;\n"
        /* t2 = ((uint32_t*)(roundKeys))[l++] ^ t1;                           */
        "ldr            r2,         [r1],           #4;\n"
        "eor           r10,          r9,            r2;\n"
        /* t3 = ((uint32_t*)(roundKeys))[l++] ^ t2;                           */
        "ldr            r2,         [r1],           #4;\n"
        "eor           r11,          r10,           r2;\n"
        /* t4.v32 = ((uint32_t*)(roundKeys))[l++] ^ t3;                       */
        "ldr            r2,         [r1],           #4;\n"
        "eor           r12,          r11,           r2;\n"
        /* ((uint32_t*)(roundKeys))[k++] = t1                                 */
        /* ((uint32_t*)(roundKeys))[k++] = t2                                 */
        /* ((uint32_t*)(roundKeys))[k++] = t3                                 */
        /* ((uint32_t*)(roundKeys))[k++] = t4                                 */
        "stmia         r4!,     {r9-r12};              \n" 
        /*--------------------------------------------------------------------*/
        /* while (loop_counter > 0)                                           */
        /*--------------------------------------------------------------------*/
        "subs          r8,            r8,           #1;\n"
        "bne           key_schedule_loop;              \n" 
        /*--------------------------------------------------------------------*/
        /* Restore registers                                                  */
        /*--------------------------------------------------------------------*/
        "ldmia        sp!,      {r0-r12,lr};           \n" /*                 */
        /*--------------------------------------------------------------------*/
    :
    : [key] "r" (key), [roundKeys] "r" (roundKeys) 
); 
}

#else
/*----------------------------------------------------------------------------*/
/* Pure C implementation                                                      */
/*----------------------------------------------------------------------------*/
/*
This file is part of the AVR-Crypto-Lib.
Copyright (C) 2008, 2009  Daniel Otte (daniel.otte@rub.de)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"

void aes_rotword(uint8_t *a)
{
    uint8_t t;
    t = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = t;
}

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint8_t i;
    uint8_t rc = 0;

    union {
        uint32_t v32;
        uint8_t v8[4];
    } tmp;


    memcpy(roundKeys, key, 16);

    for (i = 4; i < 44; ++i) 
    {
        tmp.v32 = ((uint32_t*)(roundKeys))[i - 1];
        if (0 == i % 4)
        {
            aes_rotword((uint8_t*)&(tmp.v32));
            
            tmp.v8[0] = READ_SBOX_BYTE(sbox[tmp.v8[0]]);
            tmp.v8[1] = READ_SBOX_BYTE(sbox[tmp.v8[1]]);
            tmp.v8[2] = READ_SBOX_BYTE(sbox[tmp.v8[2]]);
            tmp.v8[3] = READ_SBOX_BYTE(sbox[tmp.v8[3]]);
            tmp.v8[0] ^= READ_KS_BYTE(rc_tab[rc]);
            rc++;
        }
        ((uint32_t*)(roundKeys))[i] = ((uint32_t*)(roundKeys))[i - 4] ^ tmp.v32;
    }
}
/*----------------------------------------------------------------------------*/
#endif
#endif
#endif
