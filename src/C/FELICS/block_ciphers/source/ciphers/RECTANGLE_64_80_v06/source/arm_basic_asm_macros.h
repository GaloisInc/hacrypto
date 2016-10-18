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

#define ZERO #0
#define FOUR #4
#define EIGHT #8

#define SIXTEEN #16
#define TWENTY_FORE #24

#define ONE #1
#define	THREE #3
#define TWELVE #12
#define THIRTEEN #13
#define FIFTEEN #15

/* ---------------------------------------------------- */
/* Sbox and ISbox 					*/
/* ---------------------------------------------------- */
/* Sbox for key schedule and encryption			*/
#define sbox_(s0, s1, s2, s3, t0, t1)			\
	orns t0, s3, s1				\n\t	\
	eors t0, t0, s0				\n\t	\
	bics s0, s0, s1				\n\t	\
	eors t1, s2, s3				\n\t	\
	eors s0, s0, t1				\n\t	\
	eors s3, s1, s2				\n\t	\
	eors s1, s2, t0				\n\t	\
	ands t1, t0, t1				\n\t	\
	eors s3, s3, t1				\n\t	\
	orrs s2, s0, s3				\n\t	\
	eors s2, s2, t0				\n\t

#define sbox(s0, s1, s2, s3, t0, t1)			\
	STR(sbox_(s0, s1, s2, s3, t0, t1))

/* invert sbox for decryption				*/
#define invert_sbox_(s0, s1, s2, s3, t0, t1, t2)	\
	eors t2, s0, s1				\n\t	\
	orrs t0, s0, s3				\n\t	\
	eors t0, t0, s2				\n\t	\
	eors s2, s1, t0				\n\t	\
	ands t1, s0, t0				\n\t	\
	eors t1, t1, s3				\n\t	\
	eors s1, t1, s2				\n\t	\
	orns t1, t0, s1				\n\t	\
	eors s3, t2, t1				\n\t	\
	orns t1, s3, s1				\n\t	\
	eors s0, t0, t1				\n\t

#define invert_sbox(s0, s1, s2, s3, t0, t1, t2)		\
	STR(invert_sbox_(s0, s1, s2, s3, t0, t1, t2))
/* Sbox and ISbox End 					*/	
/* ---------------------------------------------------- */

/* ---------------------------------------------------- */
/* KEY SCHEDULE 					*/
/* store temp key					*/
#define temp_key_(k0, k1, k2, k3, tk0, tk1, tk2)	\
	mov	tk0,	k0			\n\t	\
	mov	tk1,	k1			\n\t	\
	mov	tk2,	k2			\n\t	\
	bfi	tk2,	k3,SIXTEEN,SIXTEEN	\n\t

#define temp_key(k0, k1, k2, k3, tk0, tk1, tk2)		\
	STR(temp_key_(k0, k1, k2, k3, tk0, tk1, tk2))

/* recover key and shift row 				*/
#define shift_row_(k0, k1, k2, k3, k4, tk0, tk1, tk2, t0, t1)	\
	bfi	tk0,	k0,ZERO,FOUR		\n\t	\
	bfi	tk1,	k1,ZERO,FOUR		\n\t	\
	bfi	tk2,	k2,ZERO,FOUR		\n\t	\
	lsr	t0,	tk2,SIXTEEN		\n\t	\
	bfi	t0,	k3,ZERO,FOUR		\n\t	\
	/* row0' = (row0<<<8 )eor row1 */	\n\t	\
	rev16	t1,	tk0			\n\t	\
	eor 	k0,	tk1,	t1		\n\t	\
	mov	k1,	tk2			\n\t	\
	mov	k2,	t0			\n\t	\
	/* row3' = (row3<<<12)eor row4 */	\n\t	\
	bfi	t0,	t0,SIXTEEN,FOUR		\n\t	\
	eor	k3,	k4,	t0, lsr FOUR	\n\t	\
	mov	k4,	tk0			\n\t

#define shift_row(k0, k1, k2, k3, k4, tk0, tk1, tk2, t0, t1)	\
	STR(shift_row_(k0, k1, k2, k3, k4, tk0, tk1, tk2, t0, t1))

/* key_addRC 						*/
#define key_sche_addrc_(k0, rc_p, t0)			\
	ldrb	t0,	[rc_p]			\n\t	\
	eors	k0,	t0			\n\t	\
	add	rc_p,	rc_p,	ONE		\n\t

#define key_sche_addrc(k0, rc_p, t0)			\
	STR(key_sche_addrc_(k0, rc_p, t0))

/* key schedule						*/
#define key_schedule(k0, k1, k2, k3, k4, t0, t1, tk0, tk1, tk2, rc_p)	\
	temp_key(k0, k1, k2, k3, tk0, tk1, tk2)		\
	sbox(k0, k1, k2, k3, t0, t1)			\
	shift_row(k0, k1, k2, k3, k4, tk0, tk1, tk2, t0, t1)\
	key_sche_addrc(k0, rc_p, t0)

/* store sub keys					*/
#define store_subkey_(k0, k1, k2, k3, p)		\
	bfi	k0,	k1,SIXTEEN,SIXTEEN	\n\t	\
	bfi	k2,	k3,SIXTEEN,SIXTEEN	\n\t	\
	stm	p!,	{k0,k2}			\n\t

#define store_subkey(k0, k1, k2, k3, p)			\
	STR(store_subkey_(k0, k1, k2, k3, p))
/* KEY SCHEDULE END 					*/	
/* ---------------------------------------------------- */

/* ---------------------------------------------------- */
/* ENCRYPTION 						*/
/* key xor---- 						*/
#define keyxor_(s0, s1, s2, s3, t0, t1, rk_p)		\
	ldm	rk_p!,	{t0, t1}		\n\t	\
	eors	s0,	s0,	t0		\n\t	\
	eor	s1,	s1,	t0,lsr SIXTEEN	\n\t	\
	eors	s2,	s2,	t1		\n\t	\
	eor	s3,	s3,	t1,lsr SIXTEEN	\n\t

#define keyxor(s0, s1, s2, s3, t0, t1, rk_p)		\
	STR(keyxor_(s0, s1, s2, s3, t0, t1, rk_p))

/* rotate shift left 1 bit, 12 bits, 13 bits		*/
#define rotate16_left_row_(s1, s2, s3)			\
	bfi	s1,	s1,SIXTEEN,FIFTEEN	\n\t	\
	ror	s1,	s1,	FIFTEEN		\n\t	\
	bfi	s2,	s2,SIXTEEN,FOUR		\n\t	\
	ror	s2,	s2,	FOUR		\n\t	\
	bfi	s3,	s3,SIXTEEN,THREE	\n\t	\
	ror	s3,	s3,	THREE		\n\t

#define rotate16_left_row(s1, s2, s3)			\
	STR(rotate16_left_row_(s1, s2, s3))
/* ENCRYPTION END 					*/	
/* ---------------------------------------------------- */

/* ---------------------------------------------------- */
/* DECRYPTION	 					*/	
/* dec key eor---- 					*/
#define dec_keyxor_(s0, s1, s2, s3, t0, t1, rk_p)	\
	ldm	rk_p,	{t0, t1}		\n\t	\
	eors	s0,	s0,	t0		\n\t	\
	eor	s1,	s1,	t0,lsr SIXTEEN	\n\t	\
	eors	s2,	s2,	t1		\n\t	\
	eor	s3,	s3,	t1,lsr SIXTEEN	\n\t	\
	subs	rk_p,	rk_p,	EIGHT		\n\t

#define dec_keyxor(s0, s1, s2, s3, t0, t1, rk_p)	\
	STR(dec_keyxor_(s0, s1, s2, s3, t0, t1, rk_p))

/* rotate shift right 1 bit, 12 bits, 13 bits		*/
#define rotate16_right_row_(s1, s2, s3)			\
	bfi	s1,	s1,SIXTEEN,ONE		\n\t	\
	ror	s1,	s1,	ONE		\n\t	\
	bfi	s2,	s2,SIXTEEN,TWELVE	\n\t	\
	ror	s2,	s2,	TWELVE		\n\t	\
	bfi	s3,	s3,SIXTEEN,THIRTEEN	\n\t	\
	ror	s3,	s3,	THIRTEEN	\n\t

#define rotate16_right_row(s1, s2, s3)			\
	STR(rotate16_right_row_(s1, s2, s3))
/* DECRYPTION END 					*/	
/* ---------------------------------------------------- */
