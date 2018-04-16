#ifndef _GF16_AVX2_H_
#define _GF16_AVX2_H_

#include <stdint.h>

#include "gf16.h"

#include "gf16_sse.h"

//extern const unsigned char __mask_low[];
//extern const unsigned char __mask_16[];
//extern const unsigned char __gf16_exp[];
//extern const char __gf16_log[];
//extern const unsigned char __gf16_mul[];
//extern const unsigned char __gf256_mul[];
//extern const unsigned char __gf16_mulx2[];


#include "immintrin.h"

//////////////  GF(4)  /////////////////////////////


static inline __m256i tbl32_gf4_x2( __m256i a )
{
	__m256i m55 = _mm256_load_si256((__m256i const *)__mask_0x55 );
	__m256i a0 = a&m55;
	__m256i a1 = _mm256_srli_epi16(a,1)&m55;
	__m256i a0_a1 = a0^a1;
	return a1^_mm256_slli_epi16(a0_a1,1);
}

static inline __m256i tbl32_gf4_x3( __m256i a )
{
	__m256i m55 = _mm256_load_si256((__m256i const *)__mask_0x55 );
	__m256i a0 = a&m55;
	__m256i a1 = _mm256_srli_epi16(a,1)&m55;
	__m256i a0_a1 = a0^a1;
	return a0_a1^_mm256_slli_epi16(a0,1);
}

static inline __m256i _tbl32_gf4_mul( __m256i a , __m256i b0 , __m256i b1 )
{
	__m256i m55 = _mm256_load_si256((__m256i const *)__mask_0x55 );
	__m256i a0 = a&m55;
	__m256i a1 = _mm256_srli_epi16(a,1)&m55;
	__m256i a0b0 = a0&b0;
	__m256i ab1 = (a1&b0)^(a0&b1);
	__m256i a1b1 = a1&b1;
	return _mm256_slli_epi16(ab1^a1b1,1)^a0b0^a1b1;
}

static inline __m256i tbl32_gf4_mul( __m256i a , __m256i b )
{
	return _tbl32_gf4_mul( a , b , _mm256_srli_epi16(b,1) );
}




//////////////  GF(16)  /////////////////////////////


static inline __m256i tbl32_gf16_inv( __m256i a )
{
	__m256i tab_l = _mm256_load_si256((__m256i const *) __gf16_inv );
	return _mm256_shuffle_epi8(tab_l,a);
}

static inline __m256i tbl32_gf16_log( __m256i a )
{
	__m256i tab_l = _mm256_load_si256((__m256i const *) __gf16_log );
	return _mm256_shuffle_epi8(tab_l,a);
}

static inline __m256i tbl32_gf16_exp( __m256i a )
{
	__m256i tab_l = _mm256_load_si256((__m256i const *) __gf16_exp );
	return _mm256_shuffle_epi8(tab_l,a);
}


static inline __m256i tbl32_gf16_mul_0x8( __m256i b )
{
	__m256i tab_l = _mm256_load_si256((__m256i const *) (__gf16_mulx2+  8*32 ));
	return _mm256_shuffle_epi8(tab_l,b);
}

static inline __m256i tbl32_gf16_mul_log( __m256i a , __m256i logb , __m256i mask_f )
{
	__m256i la = tbl32_gf16_log( a );
	__m256i la_lb = _mm256_add_epi8(la,logb);
	return tbl32_gf16_exp( _mm256_sub_epi8(la_lb, mask_f&_mm256_cmpgt_epi8(la_lb,mask_f) ) );
}

static inline __m256i tbl32_gf16_mul_log_log( __m256i loga , __m256i logb , __m256i mask_f )
{
	__m256i la_lb = _mm256_add_epi8(loga,logb);
	return tbl32_gf16_exp( _mm256_sub_epi8(la_lb, mask_f&_mm256_cmpgt_epi8(la_lb,mask_f) ) );
}



/////////////////////////////  GF(256) ////////////////////////////////////////


static inline __m256i tbl32_gf256_mul_const( unsigned char a , __m256i b )
{
	__m256i mask_f = _mm256_load_si256((__m256i const *) __mask_low);
	__m256i tab = _mm256_load_si256((__m256i const *) (__gf256_mul+  ((unsigned)a)*32 ));
	__m256i tab_l = _mm256_permute2x128_si256( tab , tab , 0 );
	__m256i tab_h = _mm256_permute2x128_si256( tab , tab , 0x11 );

	return _mm256_shuffle_epi8(tab_l,b&mask_f)^_mm256_shuffle_epi8(tab_h,_mm256_srli_epi16(b,4)&mask_f);
}



static inline __m256i tbl32_gf256_mul( __m256i a , __m256i b )
{
	__m256i mask_f = _mm256_load_si256((__m256i const *) __mask_low);
	__m256i log_16 = _mm256_load_si256((__m256i const *) __gf16_log);
	__m256i exp_16 = _mm256_load_si256((__m256i const *) __gf16_exp);

	__m256i a0 = a&mask_f;
	__m256i a1 = _mm256_srli_epi16(a,4)&mask_f;
	__m256i b0 = b&mask_f;
	__m256i b1 = _mm256_srli_epi16(b,4)&mask_f;

	__m256i la0 = _mm256_shuffle_epi8(log_16,a0);
	__m256i la1 = _mm256_shuffle_epi8(log_16,a1);
	__m256i lb0 = _mm256_shuffle_epi8(log_16,b0);
	__m256i lb1 = _mm256_shuffle_epi8(log_16,b1);

	__m256i la0b0 = _mm256_add_epi8(la0,lb0);
	__m256i la1b0 = _mm256_add_epi8(la1,lb0);
	__m256i la0b1 = _mm256_add_epi8(la0,lb1);
	__m256i la1b1 = _mm256_add_epi8(la1,lb1);

	__m256i r0 = _mm256_shuffle_epi8(exp_16, _mm256_sub_epi8(la0b0, mask_f&_mm256_cmpgt_epi8(la0b0,mask_f) ) );
	__m256i r1 = _mm256_shuffle_epi8(exp_16, _mm256_sub_epi8(la1b0, mask_f&_mm256_cmpgt_epi8(la1b0,mask_f) ) )
			^_mm256_shuffle_epi8(exp_16, _mm256_sub_epi8(la0b1, mask_f&_mm256_cmpgt_epi8(la0b1,mask_f) ) );
	__m256i r2 = _mm256_shuffle_epi8(exp_16, _mm256_sub_epi8(la1b1, mask_f&_mm256_cmpgt_epi8(la1b1,mask_f) ) );

	return _mm256_slli_epi16(r1^r2,4)^r0^tbl32_gf16_mul_0x8(r2);
}







#endif
