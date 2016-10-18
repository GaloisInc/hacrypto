/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security, 
 * Institute of Information Engineering
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * Written in 2016 by Bao Zhenzhen <baozhenzhen@iie.ac.cn>,
 *					  Luo Peng <luopeng@iie.ac.cn>,
 *					  Zhang Wentao <zhangwentao@iie.ac.cn>
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


#include "stringify.h"

#define CONST_F0 0xf0
#define CONST_0F 0x0f

/* ---------------------------------------------------- */
/* Key Schedule						*/
#define load_key_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15)	\
	ld	k0,	x+			\n\t	\
	ld	k1,	x+			\n\t	\
	ld	k2,	x+			\n\t	\
	ld	k3,	x+			\n\t	\
	ld	k4,	x+			\n\t	\
	ld	k5,	x+			\n\t	\
	ld	k6,	x+			\n\t	\
	ld	k7,	x+			\n\t	\
	ld	k8,	x+			\n\t	\
	ld	k9,	x+			\n\t	\
	ld	k10,	x+			\n\t	\
	ld	k11,	x+			\n\t	\
	ld	k12,	x+			\n\t	\
	ld	k13,	x+			\n\t	\
	ld	k14,	x+			\n\t	\
	ld	k15,	x			\n\t

#define load_key(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15)	\
	STR(load_key_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15))
	
/* store sub keys					*/
#define store_subkey_(k0, k1, k4, k5, k8, k9, k12, k13)	\
	st	x+,	k0			\n\t	\
	st	x+,	k1			\n\t	\
	st	x+,	k4			\n\t	\
	st	x+,	k5			\n\t	\
	st	x+,	k8			\n\t	\
	st	x+,	k9			\n\t	\
	st	x+,	k12			\n\t	\
	st	x+,	k13			\n\t

#define store_subkey(k0, k1, k4, k5, k8, k9, k12, k13)	\
	STR(store_subkey_(k0, k1, k4, k5, k8, k9, k12, k13))
	
/* key schedule 					*/
#define forward_key_update_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, t0, t1, t2, t3)	\
	mov	t0,	k8			\n\t	\
	eor	k8,	k4			\n\t	\
	com	k4				\n\t	\
	mov	t1,	k0			\n\t	\
	and	k0,	k4			\n\t	\
	or	k4,	k12			\n\t	\
	eor	k4,	t1			\n\t	\
	eor	k12,	t0			\n\t	\
	eor	k0,	k12			\n\t	\
	and	k12,	k4			\n\t	\
	eor	k12,	k8			\n\t	\
	or	k8,	k0			\n\t	\
	eor	k8,	k4			\n\t	\
	eor	k4,	t0			\n\t	\
	movw	t0,	k12			\n\t	\
	movw	t2,	k14			\n\t	\
	movw	k12,	k0			\n\t	\
	movw	k14,	k2			\n\t	\
	movw	k0,	k4			\n\t	\
	movw	k2,	k6			\n\t	\
	movw	k4,	k8			\n\t	\
	movw	k6,	k10			\n\t	\
	movw	k8,	t0			\n\t	\
	movw	k10,	t2			\n\t	\
	eor	k0,	k15			\n\t	\
	eor	k1,	k12			\n\t	\
	eor	k2,	k13			\n\t	\
	eor	k3,	k14			\n\t	\
	eor	k8,	k6			\n\t	\
	eor	k9,	k7			\n\t	\
	eor	k10,	k4			\n\t	\
	eor	k11,	k5			\n\t	\
	lpm	t0,	z+			\n\t	\
	eor	k0,	t0			\n\t

#define forward_key_update(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, t0, t1, t2, t3)	\
	STR(forward_key_update_(k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, t0, t1, t2, t3))
/* Key Schedule end					*/
/* ---------------------------------------------------- */


/* ---------------------------------------------------- */
/* Encryption 						*/
/* rotate shift left 1 bit				*/
#define rotate16_left_row1_(s2, s3, zero) 		\
	lsl	s2				\n\t	\
	rol	s3				\n\t	\
	adc	s2, zero			\n\t

#define rotate16_left_row1(s2, s3, zero)		\
	STR(rotate16_left_row1_(s2, s3, zero))
	
/* rotate shift left 12 bits == rotate shift right 4 bits */
#define rotate16_left_row2_(s4, s5, t0, t1)		\
	swap	s4				\n\t	\
	swap	s5				\n\t	\
	movw	t0,	s4			\n\t	\
	eor	t1,	t0			\n\t	\
	andi	t1,	CONST_F0		\n\t	\
	eor	s4,	t1			\n\t	\
	eor	s5,	t1			\n\t

#define rotate16_left_row2(s4, s5, t0, t1)		\
	STR(rotate16_left_row2_(s4, s5, t0, t1))
	
/* rotate shift left 13 bits == rotate shift right 3 bits */
#define rotate16_left_row3_(s6, s7, t0, t1, zero)	\
	swap	s6				\n\t	\
	swap	s7				\n\t	\
	movw	t0,	s6			\n\t	\
	eor	t1,	t0			\n\t	\
	andi	t1,	CONST_F0		\n\t	\
	eor	s6,	t1			\n\t	\
	eor	s7,	t1			\n\t	\
	lsl	s6				\n\t	\
	rol	s7				\n\t	\
	adc	s6,	zero			\n\t

#define rotate16_left_row3(s6, s7, t0, t1, zero)	\
	STR(rotate16_left_row3_(s6, s7, t0, t1, zero))
	
/* sbox				 		*/
#define sbox_(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1, t2, t3)	\
	movw	t0,	s4			\n\t	\
	eor	s4,	s2			\n\t	\
	eor	s5,	s3			\n\t	\
	com	s2				\n\t	\
	com	s3				\n\t	\
	movw	t2,	s0			\n\t	\
	and	s0,	s2			\n\t	\
	and	s1,	s3			\n\t	\
	or	s2,	s6			\n\t	\
	or	s3,	s7			\n\t	\
	eor	s6,	t0			\n\t	\
	eor	s7,	t1			\n\t	\
	eor	s0,	s6			\n\t	\
	eor	s1,	s7			\n\t	\
	eor	s2,	t2			\n\t	\
	eor	s3,	t3			\n\t	\
	and	s6,	s2			\n\t	\
	and	s7,	s3			\n\t	\
	eor	s6,	s4			\n\t	\
	eor	s7,	s5			\n\t	\
	or	s4,	s0			\n\t	\
	or	s5,	s1			\n\t	\
	eor	s4,	s2			\n\t	\
	eor	s5,	s3			\n\t	\
	eor	s2,	t0			\n\t	\
	eor	s3,	t1			\n\t

#define sbox(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1, t2, t3)	\
	STR(sbox_(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1, t2, t3))
	
/* key xor---- load key from ram 			*/
#define keyxor_ram_(s0, s1, s2, s3, s4, s5, s6, s7, k)	\
	ld	k,	z+			\n\t	\
	eor	s0,	k			\n\t	\
	ld	k,	z+			\n\t	\
	eor	s1,	k			\n\t	\
	ld	k,	z+			\n\t	\
	eor	s2,	k			\n\t	\
	ld	k,	z+			\n\t	\
	eor	s3,	k			\n\t	\
	ld	k,	z+			\n\t	\
	eor	s4,	k			\n\t	\
	ld	k,	z+			\n\t	\
	eor	s5,	k			\n\t	\
	ld	k,	z+			\n\t	\
	eor	s6,	k			\n\t	\
	ld	k,	z+			\n\t	\
	eor	s7,	k			\n\t

/* key xor---- load key from flash 		*/
#define keyxor_flash_(s0, s1, s2, s3, s4, s5, s6, s7, k)	\
	lpm	k,	z+			\n\t	\
	eor	s0,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s1,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s2,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s3,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s4,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s5,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s6,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s7,	k			\n\t

/* key xor, it's different between scenario1 and scenario2 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
	#define keyxor(s0, s1, s2, s3, s4, s5, s6, s7, k)     \
		STR(keyxor_flash_(s0, s1, s2, s3, s4, s5, s6, s7, k))
#else
	#define keyxor(s0, s1, s2, s3, s4, s5, s6, s7, k)     \
		STR(keyxor_ram_(s0, s1, s2, s3, s4, s5, s6, s7, k))
#endif

/* one round of encryption			 	*/
#define enc_round(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1, t2, t3, zero)	\
	sbox(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1, t2, t3)		\
	rotate16_left_row1(s2, s3, zero)				\
	rotate16_left_row2(s4, s5, t0, t1)				\
	rotate16_left_row3(s6, s7, t0, t1, zero)
/* Encryption end 					*/
/* ---------------------------------------------------- */


/* ---------------------------------------------------- */
/* Decryption	 					*/
/* invert sbox 						*/
#define invert_sbox_(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1)	\
	movw	t0,	s0			\n\t	\
	and	s0,	s4			\n\t	\
	and	s1,	s5			\n\t	\
	eor	s0,	s6			\n\t	\
	eor	s1,	s7			\n\t	\
	or	s6,	t0			\n\t	\
	or	s7,	t1			\n\t	\
	eor	s6,	s4			\n\t	\
	eor	s7,	s5			\n\t	\
	eor	s2,	s6			\n\t	\
	eor	s3,	s7			\n\t	\
	movw	s4,	s2			\n\t	\
	eor	s2,	t0			\n\t	\
	eor	s3,	t1			\n\t	\
	eor	s2,	s0			\n\t	\
	eor	s3,	s1			\n\t	\
	com	s6				\n\t	\
	com	s7				\n\t	\
	movw	t0,	s6			\n\t	\
	or	s6,	s2			\n\t	\
	or	s7,	s3			\n\t	\
	eor	s6,	s0			\n\t	\
	eor	s7,	s1			\n\t	\
	and	s0,	s2			\n\t	\
	and	s1,	s3			\n\t	\
	eor	s0,	t0			\n\t	\
	eor	s1,	t1			\n\t

#define invert_sbox(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1)	\
	STR(invert_sbox_(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1))

/* rotate shift right 1 bit 				*/
#define rotate16_right_row1_(s2, s3)			\
	bst	s2,	0			\n\t	\
	ror	s3				\n\t	\
	ror	s2				\n\t	\
	bld	s3,	7			\n\t

#define rotate16_right_row1(s2, s3)			\
	STR(rotate16_right_row1_(s2, s3))

/* rotate shift right 12 bits == left 4 bits		*/
#define rotate16_right_row2_(s4, s5, t0, t1)		\
	swap	s4				\n\t	\
	swap	s5				\n\t	\
	movw	t0,	s4			\n\t	\
	eor	t1,	t0			\n\t	\
	andi	t1,	CONST_0F		\n\t	\
	eor	s4,	t1			\n\t	\
	eor	s5,	t1			\n\t

#define rotate16_right_row2(s4, s5, t0, t1)		\
	STR(rotate16_right_row2_(s4, s5, t0, t1))

/* rotate shift right 13 bits == left 3 bits		*/
#define rotate16_right_row3_(s6, s7, zero)		\
	lsl	s6				\n\t	\
    	rol	s7				\n\t	\
    	adc	s6,	zero			\n\t	\
	lsl	s6				\n\t	\
    	rol	s7				\n\t	\
    	adc	s6,	zero			\n\t	\
	lsl	s6				\n\t	\
    	rol	s7				\n\t	\
    	adc	s6,	zero			\n\t

#define rotate16_right_row3(s6, s7, zero)		\
	STR(rotate16_right_row3_(s6, s7, zero))

/* dec key xor---- load key from ram 			*/
#define dec_keyxor_ram_(s0, s1, s2, s3, s4, s5, s6, s7, k)	\
	ld	k,	-z			\n\t	\
	eor	s7,	k			\n\t	\
	ld	k,	-z			\n\t	\
	eor	s6,	k			\n\t	\
	ld	k,	-z			\n\t	\
	eor	s5,	k			\n\t	\
	ld	k,	-z			\n\t	\
	eor	s4,	k			\n\t	\
	ld	k,	-z			\n\t	\
	eor	s3,	k			\n\t	\
	ld	k,	-z			\n\t	\
	eor	s2,	k			\n\t	\
	ld	k,	-z			\n\t	\
	eor	s1,	k			\n\t	\
	ld	k,	-z			\n\t	\
	eor	s0,	k			\n\t

/* dec key xor---- load key from flash 			*/
#define dec_keyxor_flash_(s0, s1, s2, s3, s4, s5, s6, s7, k)	\
	lpm	k,	z+			\n\t	\
	eor	s0,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s1,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s2,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s3,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s4,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s5,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s6,	k			\n\t	\
	lpm	k,	z+			\n\t	\
	eor	s7,	k			\n\t	\
	sbiw	r30,	16			\n\t

/* dec key xor, it's different between scenario1 and scenario2 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
	#define dec_keyxor(s0, s1, s2, s3, s4, s5, s6, s7, k)	\
		STR(dec_keyxor_flash_(s0, s1, s2, s3, s4, s5, s6, s7, k))
#else
	#define dec_keyxor(s0, s1, s2, s3, s4, s5, s6, s7, k)	\
		STR(dec_keyxor_ram_(s0, s1, s2, s3, s4, s5, s6, s7, k))
#endif

/* one round of decryption 					*/
#define dec_round(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1, zero)	\
	rotate16_right_row1(s2, s3)				\
	rotate16_right_row2(s4, s5, t0, t1)			\
	rotate16_right_row3(s6, s7, zero)			\
	invert_sbox(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1)
/* Decryption end 					*/
/* ---------------------------------------------------- */
