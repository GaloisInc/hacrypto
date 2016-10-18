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
 * Written in 2016 by Luo Peng <luopeng@iie.ac.cn>,
 *		      Bao Zhenzhen <baozhenzhen@iie.ac.cn>,
 * 		      Zhang Wentao <zhangwentao@iie.ac.cn>
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

#define EIGHT #8
#define ONE #1
#define XFF00 #0xff00

/* ---------------------------------------------------- */
/* sbox and invert sbox 				*/
/* Sbox for encryption					*/
#define sbox_(s0, s1, s2, s3, t0, t1)			\
	mov	s2,	t0			\n\t	\
	xor	s1,	s2			\n\t	\
	inv	s1				\n\t	\
	mov	s0,	t1			\n\t	\
	and	s1,	s0			\n\t	\
	bis	s3,	s1			\n\t	\
	xor	t1,	s1			\n\t	\
	xor	t0,	s3			\n\t	\
	xor	s3,	s0			\n\t	\
	and	s1,	s3			\n\t	\
	xor	s2,	s3			\n\t	\
	bis	s0,	s2			\n\t	\
	xor	s1,	s2			\n\t	\
	xor	t0,	s1			\n\t

#define sbox(s0, s1, s2, s3, t0, t1)			\
	STR(sbox_(s0, s1, s2, s3, t0, t1))

/* Invert Sbox for decryption				*/
#define invert_sbox_(s0, s1, s2, s3, t0, t1)		\
	mov	s0,	t0			\n\t	\
	and	s2,	s0			\n\t	\
	xor	s3,	s0			\n\t	\
	bis	t0,	s3			\n\t	\
	xor	s2,	s3			\n\t	\
	xor	s3,	s1			\n\t	\
	mov	s1,	s2			\n\t	\
	xor	t0,	s1			\n\t	\
	xor	s0,	s1			\n\t	\
	inv	s3				\n\t	\
	mov	s3,	t0			\n\t	\
	bis	s1,	s3			\n\t	\
	xor	s0,	s3			\n\t	\
	and	s1,	s0			\n\t	\
	xor	t0,	s0			\n\t

#define invert_sbox(s0, s1, s2, s3, t0, t1)		\
	STR(invert_sbox_(s0, s1, s2, s3, t0, t1))

/* Sbox for key schedule				*/
#define ksche_sbox_(s0, s1, s2, s3, t0, t1)		\
	mov.b	s2,	t0			\n\t	\
	xor.b	s1,	s2			\n\t	\
	inv.b	s1				\n\t	\
	mov.b	s0,	t1			\n\t	\
	and.b	s1,	s0			\n\t	\
	bis.b	s3,	s1			\n\t	\
	xor.b	t1,	s1			\n\t	\
	xor.b	t0,	s3			\n\t	\
	xor.b	s3,	s0			\n\t	\
	and.b	s1,	s3			\n\t	\
	xor.b	s2,	s3			\n\t	\
	bis.b	s0,	s2			\n\t	\
	xor.b	s1,	s2			\n\t	\
	xor.b	t0,	s1			\n\t

#define ksche_sbox(s0, s1, s2, s3, t0, t1)		\
	STR(ksche_sbox_(s0, s1, s2, s3, t0, t1))
/* sbox and invert sbox end				*/
/* ---------------------------------------------------- */

/* ---------------------------------------------------- */
/* Key Schedule 					*/
/* store sub keys					*/
#define store_subkey_(k0, k2, k4, k6)			\
	mov	k0,	0(r14)			\n\t	\
	mov	k2,	2(r14)			\n\t	\
	mov	k4,	4(r14)			\n\t	\
	mov	k6,	6(r14)			\n\t	\
	add	EIGHT,	r14			\n\t

#define store_subkey(k0, k2, k4, k6)			\
	STR(store_subkey_(k0, k2, k4, k6))

/* the registers are not enough, so half keys and pointer should be pushed */
#define key_sche_push_data_(k0, k2, k4, k6, t1)		\
	mov	t1,	8(r1)			\n\t	\
	mov	k6,	6(r1)			\n\t	\
	mov	k4,	4(r1)			\n\t	\
	mov	k2,	2(r1)			\n\t	\
	mov	k0,	0(r1)			\n\t

#define key_sche_push_data(k0, k2, k4, k6, t1)		\
	STR(key_sche_push_data_(k0, k2, k4, k6, t1))

/* pop keys and pointer					*/
#define key_sche_pop_data_(k0, k2, k4, k6, t0)		\
	mov	0(r1),		t0		\n\t	\
	and	XFF00,	t0			\n\t	\
	xor	t0,	k0			\n\t	\
	mov	2(r1),		t0		\n\t	\
	and	XFF00,	t0			\n\t	\
	xor	t0,	k2			\n\t	\
	mov	4(r1),		t0		\n\t	\
	and	XFF00,	t0			\n\t	\
	xor	t0,	k4			\n\t	\
	mov	6(r1),		t0		\n\t	\
	and	XFF00,	t0			\n\t	\
	xor	t0,	k6			\n\t

#define key_sche_pop_data(k0, k2, k4, k6, t0)		\
	STR(key_sche_pop_data_(k0, k2, k4, k6, t0))

/* shift row	 					*/
#define key_sche_shift_row_(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1)	\
	mov	k0,	t0			\n\t	\
	mov	k1,	t1			\n\t	\
	mov	k2,	k0			\n\t	\
	mov	k3,	k1			\n\t	\
	mov	k4,	k2			\n\t	\
	mov	k5,	k3			\n\t	\
	mov	k6,	k4			\n\t	\
	mov	k7,	k5			\n\t	\
	mov	t0,	k6			\n\t	\
	mov	t1,	k7			\n\t	\
	mov	k0,	6(r1)			\n\t	\
	swpb	t0				\n\t	\
	swpb	t1				\n\t	\
	mov.b	t0,	k0			\n\t	\
	xor.b	t1,	k0			\n\t	\
	xor	k0,	t1			\n\t	\
	xor	k0,	t0			\n\t	\
	mov	6(r1),	k0			\n\t	\
	xor	t0,	k0			\n\t	\
	xor	t1,	k1			\n\t	\
	xor	k3,	k4			\n\t	\
	xor	k2,	k5			\n\t

#define key_sche_shift_row(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1)	\
	STR(key_sche_shift_row_(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1))

/* key_addRC 						*/
#define key_sche_addrc_(k0, t0, t1)			\
	mov	8(r1),	t1			\n\t	\
	mov.b	@t1+,	t0			\n\t	\
	xor	t0,	k0			\n\t

#define key_sche_addrc(k0, t0, t1)			\
	STR(key_sche_addrc_(k0, t0, t1))

/* key schedule 					*/
#define key_schedule(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1)		\
	key_sche_push_data(k0, k2, k4, k6, t1)				\
	ksche_sbox(k0, k2, k4, k6, t0, t1)				\
	key_sche_pop_data(k0, k2, k4, k6, t0)				\
	key_sche_shift_row(k0, k1, k2, k3, k4, k5, k6, k7, t0, t1)	\
	key_sche_addrc(k0, t0, t1)
/* Key Schedule End 					*/
/* ---------------------------------------------------- */


/* ---------------------------------------------------- */
/* Encryption	 					*/
/* rotate shift left 1 bit				*/
#define rotate16_left_row1_(s1) 			\
	rla	s1				\n\t	\
	adc	s1				\n\t

#define rotate16_left_row1(s1)				\
	STR(rotate16_left_row1_(s1))

/* rotate shift left 12 bits == right 4			*/
#define rotate16_left_row2_(s2)				\
	bit		ONE,		s2	\n\t	\
	rrc		s2			\n\t	\
	bit		ONE,		s2	\n\t	\
	rrc		s2			\n\t	\
	bit		ONE,		s2	\n\t	\
	rrc		s2			\n\t	\
	bit		ONE,		s2	\n\t	\
	rrc		s2			\n\t

#define rotate16_left_row2(s2)				\
	STR(rotate16_left_row2_(s2))

/* rotate shift left 13 bits == right 3		 	*/
#define rotate16_left_row3_(s3)				\
	bit		ONE,		s3	\n\t	\
	rrc		s3			\n\t	\
	bit		ONE,		s3	\n\t	\
	rrc		s3			\n\t	\
	bit		ONE,		s3	\n\t	\
	rrc		s3			\n\t

#define rotate16_left_row3(s3)				\
	STR(rotate16_left_row3_(s3))

/* key xor---- 						*/
#define keyxor_(s0, s1, s2, s3, x)			\
	xor	@x+,	s0			\n\t	\
	xor	@x+,	s1			\n\t	\
	xor	@x+,	s2			\n\t	\
	xor	@x+,	s3			\n\t

#define keyxor(s0, s1, s2, s3, x)			\
	STR(keyxor_(s0, s1, s2, s3, x))

/* one round of encryption			 	*/
#define enc_round(s0, s1, s2, s3, x, t0, t1)		\
	keyxor(s0, s1, s2, s3, x)			\
	sbox(s0, s1, s2, s3, t0, t1)			\
	rotate16_left_row1(s1)				\
	rotate16_left_row2(s2)				\
	rotate16_left_row3(s3)
/* Encryption End 					*/
/* ---------------------------------------------------- */


/* ---------------------------------------------------- */
/* Decryption	 					*/
/* rotate shift right 1 bit 				*/
#define rotate16_right_row1_(s1)			\
	bit		ONE,		s1	\n\t	\
	rrc		s1			\n\t

#define rotate16_right_row1(s1)				\
	STR(rotate16_right_row1_(s1))

/* rotate shift right 12 bits == left 4	 		*/
#define rotate16_right_row2_(s2)			\
	rla	s2				\n\t	\
	adc	s2				\n\t	\
	rla	s2				\n\t	\
	adc	s2				\n\t	\
	rla	s2				\n\t	\
	adc	s2				\n\t	\
	rla	s2				\n\t	\
	adc	s2				\n\t

#define rotate16_right_row2(s2)				\
	STR(rotate16_right_row2_(s2))

/* rotate shift right 13 bits == left 3	 		*/
#define rotate16_right_row3_(s3)			\
	rla	s3				\n\t	\
	adc	s3				\n\t	\
	rla	s3				\n\t	\
	adc	s3				\n\t	\
	rla	s3				\n\t	\
	adc	s3				\n\t

#define rotate16_right_row3(s3)				\
	STR(rotate16_right_row3_(s3))

/* dec key xor----  					*/
#define dec_keyxor_(s0, s1, s2, s3, x)			\
	xor	0(x),	s0			\n\t	\
	xor	2(x),	s1			\n\t	\
	xor	4(x),	s2			\n\t	\
	xor	6(x),	s3			\n\t

#define dec_keyxor(s0, s1, s2, s3, x)			\
	STR(dec_keyxor_(s0, s1, s2, s3, x))

/* one round of decryption 				*/
#define dec_round(s0, s1, s2, s3, x, t0, t1)		\
	dec_keyxor(s0, s1, s2, s3, x)			\
	rotate16_right_row1(s1)				\
    	rotate16_right_row2(s2)				\
    	rotate16_right_row3(s3)				\
	invert_sbox(s0, s1, s2, s3, t0, t1)
/* Decryption End 					*/
/* ---------------------------------------------------- */
