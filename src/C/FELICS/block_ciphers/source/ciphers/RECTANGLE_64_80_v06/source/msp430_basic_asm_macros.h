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
 *		      Zhang Wentao <zhangwentao@iie.ac.cn>
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
#define XFFF0 #0xfff0
#define X000F #0x000f

/* ---------------------------------------------------- */
/* SBOX AND INVERT_SBOX 				*/
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
/* SBOX AND INVERT_SBOX END				*/
/* ---------------------------------------------------- */

/* ---------------------------------------------------- */
/* KEY SCHEDULE 					*/
/* store sub keys					*/
#define store_subkey_(k0, k1, k2, k3)			\
	mov	k0,	0(r14)			\n\t	\
	mov	k1,	2(r14)			\n\t	\
	mov	k2,	4(r14)			\n\t	\
	mov	k3,	6(r14)			\n\t	\
	add	EIGHT,	r14			\n\t

#define store_subkey(k0, k1, k2, k3)			\
	STR(store_subkey_(k0, k1, k2, k3))

/* the registers are not enough 			*/
#define key_sche_push_data_(k0, k1, k2, k3, t0, t1)	\
	mov	k3,	2(r1)			\n\t	\
	mov	k2,	0(r1)			\n\t	\
	mov	k1,	t1			\n\t 	\
	mov	k0,	t0			\n\t

#define key_sche_push_data(k0, k1, k2, k3, t0, t1)	\
	STR(key_sche_push_data_(k0, k1, k2, k3, t0, t1))

/* pop keys 						*/
#define key_sche_pop_data_(k0, k1, k2, k3, t0, t1, t2, t3)	\
	and	XFFF0,	t0			\n\t	\
	and	X000F,	k0			\n\t	\
	xor	t0,	k0			\n\t	\
	and	XFFF0,	t1			\n\t	\
	and	X000F,	k1			\n\t	\
	xor	t1,	k1			\n\t	\
	mov	0(r1),	t2			\n\t	\
	and	XFFF0,	t2			\n\t	\
	and	X000F,	k2			\n\t	\
	xor	t2,	k2			\n\t	\
	mov	2(r1),	t3			\n\t	\
	and	XFFF0,	t3			\n\t	\
	and	X000F,	k3			\n\t	\
	xor	t3,	k3			\n\t

#define key_sche_pop_data(k0, k1, k2, k3, t0, t1, t2, t3)	\
	STR(key_sche_pop_data_(k0, k1, k2, k3, t0, t1, t2, t3))

/* shift row	 					*/
#define key_sche_shift_row_(k0, k1, k2, k3, k4, t0)	\
	mov	k0,	t0			\n\t	\
	mov	k1,	k0			\n\t	\
	mov	k2,	k1			\n\t	\
	mov	k3,	k2			\n\t	\
	mov	k4,	k3			\n\t	\
	mov	t0,	k4			\n\t	\
	swpb	t0				\n\t	\
	xor	t0,	k0			\n\t	\
	mov	k2,	t0			\n\t	\
	bit	ONE,	t0			\n\t	\
	rrc	t0				\n\t	\
	bit	ONE,	t0			\n\t	\
	rrc	t0				\n\t	\
	bit	ONE,	t0			\n\t	\
	rrc	t0				\n\t	\
	bit	ONE,	t0			\n\t	\
	rrc	t0				\n\t	\
	xor	t0,	k3			\n\t

#define key_sche_shift_row(k0, k1, k2, k3, k4, t0)	\
	STR(key_sche_shift_row_(k0, k1, k2, k3, k4, t0))

/* key_addRC 						*/
#define key_sche_addrc_(k0, t0)				\
	mov.b	@r15+,	t0			\n\t	\
	xor	t0,	k0			\n\t

#define key_sche_addrc(k0, t0)				\
	STR(key_sche_addrc_(k0, t0))

/* key schedule 					*/
#define key_schedule(k0, k1, k2, k3, k4, t0, t1, t2, t3)\
	key_sche_push_data(k0, k1, k2, k3, t0, t1)	\
	sbox(k0, k1, k2, k3, t2, t3)			\
	key_sche_pop_data(k0, k1, k2, k3, t0, t1, t2, t3)\
	key_sche_shift_row(k0, k1, k2, k3, k4, t0)	\
	key_sche_addrc(k0, t0)
/* KEY SCHEDULE END 					*/
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
