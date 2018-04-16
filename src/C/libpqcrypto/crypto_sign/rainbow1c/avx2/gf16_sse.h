#ifndef _GF16_SSE_H_
#define _GF16_SSE_H_

#include <stdint.h>

#include "gf16.h"
#include "gf16_tabs.h"


//extern const unsigned char __mask_low[];
//extern const unsigned char __mask_16[];
//extern const unsigned char __gf16_exp[];
//extern const char __gf16_log[];
//extern const unsigned char __gf16_mul[];
//extern const unsigned char __gf256_mul[];
//extern const unsigned char __gf16_mulx2[];


#include "emmintrin.h"
#include "tmmintrin.h"

//////////////  GF(4)  /////////////////////////////

static inline __m128i tbl_gf4_x2( __m128i a )
{
	__m128i m55 = _mm_load_si128((__m128i const *)__mask_0x55 );
	__m128i a0 = a&m55;
	__m128i a1 = _mm_srli_epi16(a,1)&m55;
	__m128i a0_a1 = a0^a1;
	return a1^_mm_slli_epi16(a0_a1,1);
}

static inline __m128i tbl_gf4_x3( __m128i a )
{
	__m128i m55 = _mm_load_si128((__m128i const *)__mask_0x55 );
	__m128i a0 = a&m55;
	__m128i a1 = _mm_srli_epi16(a,1)&m55;
	__m128i a0_a1 = a0^a1;
	return a0_a1^_mm_slli_epi16(a0,1);
}

static inline __m128i _tbl_gf4_mul( __m128i a , __m128i b0 , __m128i b1 )
{
	__m128i m55 = _mm_load_si128((__m128i const *)__mask_0x55 );
	__m128i a0 = a&m55;
	__m128i a1 = _mm_srli_epi16(a,1)&m55;
	__m128i a0b0 = a0&b0;
	__m128i ab1 = (a1&b0)^(a0&b1);
	__m128i a1b1 = a1&b1;
	return _mm_slli_epi16(ab1^a1b1,1)^a0b0^a1b1;
}

static inline __m128i tbl_gf4_mul( __m128i a , __m128i b )
{
	return _tbl_gf4_mul( a , b , _mm_srli_epi16(b,1) );
}




//////////////  GF(16)  /////////////////////////////

static inline __m128i tbl_gf16_squ( __m128i a )
{
	__m128i tab_l = _mm_load_si128((__m128i const *) __gf16_squ );
	return _mm_shuffle_epi8(tab_l,a);
}

static inline __m128i tbl_gf16_squ_sl4( __m128i a )
{
	__m128i tab_l = _mm_load_si128((__m128i const *) __gf16_squ_sl4 );
	return _mm_shuffle_epi8(tab_l,a);
}

static inline __m128i tbl_gf16_squ_x8( __m128i a )
{
	__m128i tab_l = _mm_load_si128((__m128i const *) __gf16_squ_x8 );
	return _mm_shuffle_epi8(tab_l,a);
}


static inline __m128i tbl_gf16_inv( __m128i a )
{
	__m128i tab_l = _mm_load_si128((__m128i const *) __gf16_inv );
	return _mm_shuffle_epi8(tab_l,a);
}

static inline __m128i tbl_gf16_log( __m128i a )
{
	__m128i tab_l = _mm_load_si128((__m128i const *) __gf16_log );
	return _mm_shuffle_epi8(tab_l,a);
}

static inline __m128i tbl_gf16_exp( __m128i a )
{
	__m128i tab_l = _mm_load_si128((__m128i const *) __gf16_exp );
	return _mm_shuffle_epi8(tab_l,a);
}

static inline __m128i tbl_gf16_mul_const( unsigned char a , __m128i b )
{
	__m128i tab_l = _mm_load_si128((__m128i const *) (__gf256_mul+  ((unsigned)a)*32 ));
	return _mm_shuffle_epi8(tab_l,b);
}

static inline __m128i tbl_gf16_mul_0x8( __m128i b )
{
	__m128i tab_l = _mm_load_si128((__m128i const *) (__gf256_mul+  8*32 ));
	return _mm_shuffle_epi8(tab_l,b);
}

static inline __m128i tbl_gf16_mul( __m128i a , __m128i b )
{
	__m128i mask_f = _mm_load_si128((__m128i const *) __mask_low);
	__m128i log_16 = _mm_load_si128((__m128i const *) __gf16_log);
	__m128i exp_16 = _mm_load_si128((__m128i const *) __gf16_exp);

	__m128i la = _mm_shuffle_epi8(log_16,a);
	__m128i lb = _mm_shuffle_epi8(log_16,b);
	__m128i la_lb = _mm_add_epi8(la,lb);

	__m128i r0 = _mm_shuffle_epi8(exp_16, _mm_sub_epi8(la_lb, mask_f&_mm_cmpgt_epi8(la_lb,mask_f) ) );
	return r0;
}

static inline __m128i tbl_gf16_mul_log( __m128i a , __m128i logb , __m128i mask_f )
{
	__m128i la = tbl_gf16_log( a );
	__m128i la_lb = _mm_add_epi8(la,logb);
	return tbl_gf16_exp( _mm_sub_epi8(la_lb, mask_f&_mm_cmpgt_epi8(la_lb,mask_f) ) );
}

static inline __m128i tbl_gf16_mul_log_log( __m128i loga , __m128i logb , __m128i mask_f )
{
	__m128i la_lb = _mm_add_epi8(loga,logb);
	return tbl_gf16_exp( _mm_sub_epi8(la_lb, mask_f&_mm_cmpgt_epi8(la_lb,mask_f) ) );
}



/////////////////////////////  GF(256) ////////////////////////////////////////


static inline __m128i tbl_gf256_mul_const( unsigned char a , __m128i b )
{
	__m128i mask_f = _mm_load_si128((__m128i const *) __mask_low);
	__m128i tab_l = _mm_load_si128((__m128i const *) (__gf256_mul+  ((unsigned)a)*32 ));
	__m128i tab_h = _mm_load_si128((__m128i const *) (__gf256_mul+  ((unsigned)a)*32 + 16 ));

	return _mm_shuffle_epi8(tab_l,b&mask_f)^_mm_shuffle_epi8(tab_h,_mm_srli_epi16(b,4)&mask_f);
}

static inline __m128i tbl_gf256_mul( __m128i a , __m128i b )
{
	__m128i mask_f = _mm_load_si128((__m128i const *) __mask_low);
	__m128i log_16 = _mm_load_si128((__m128i const *) __gf16_log);
	__m128i exp_16 = _mm_load_si128((__m128i const *) __gf16_exp);

	__m128i a0 = a&mask_f;
	__m128i a1 = _mm_srli_epi16(a,4)&mask_f;
	__m128i b0 = b&mask_f;
	__m128i b1 = _mm_srli_epi16(b,4)&mask_f;

	__m128i la0 = _mm_shuffle_epi8(log_16,a0);
	__m128i la1 = _mm_shuffle_epi8(log_16,a1);
	__m128i lb0 = _mm_shuffle_epi8(log_16,b0);
	__m128i lb1 = _mm_shuffle_epi8(log_16,b1);

	__m128i la0b0 = _mm_add_epi8(la0,lb0);
	__m128i la1b0 = _mm_add_epi8(la1,lb0);
	__m128i la0b1 = _mm_add_epi8(la0,lb1);
	__m128i la1b1 = _mm_add_epi8(la1,lb1);

	__m128i r0 = _mm_shuffle_epi8(exp_16, _mm_sub_epi8(la0b0, mask_f&_mm_cmpgt_epi8(la0b0,mask_f) ) );
	__m128i r1 = _mm_shuffle_epi8(exp_16, _mm_sub_epi8(la1b0, mask_f&_mm_cmpgt_epi8(la1b0,mask_f) ) )
			^_mm_shuffle_epi8(exp_16, _mm_sub_epi8(la0b1, mask_f&_mm_cmpgt_epi8(la0b1,mask_f) ) );
	__m128i r2 = _mm_shuffle_epi8(exp_16, _mm_sub_epi8(la1b1, mask_f&_mm_cmpgt_epi8(la1b1,mask_f) ) );

	return _mm_slli_epi16(r1^r2,4)^r0^tbl_gf16_mul_0x8(r2);
}

static inline __m128i tbl_gf256_squ( __m128i a )
{
	__m128i mask_f = _mm_load_si128((__m128i const *) __mask_low);
	__m128i a0 = a&mask_f;
	__m128i a1 = _mm_srli_epi16(a,4)&mask_f;
	__m128i a0squ = tbl_gf16_squ(a0);
	__m128i a1squ_sl4 = tbl_gf16_squ_sl4(a1);
	__m128i a1squ_x8 = tbl_gf16_squ_x8( a1 );
	return a1squ_sl4^a0squ^a1squ_x8;
}

static inline __m128i tbl_gf256_inv( __m128i a )
{
#if 1
// faster
	__m128i mask_f = _mm_load_si128((__m128i const *) __mask_low);
	__m128i a0 = a&mask_f;
	__m128i a1 = _mm_srli_epi16(a,4)&mask_f;
	__m128i a0_a1 = a0^a1;
	__m128i a1squx8 = tbl_gf16_squ_x8( a1 );
	__m128i a0xa0_a1 = tbl_gf16_mul( a0 , a0_a1 );
	__m128i denominator = a1squx8^a0xa0_a1;
	__m128i _denominator = tbl_gf16_inv( denominator );
	__m128i b1 = tbl_gf16_mul( _denominator , a1 );
	__m128i a1inv = tbl_gf16_inv(a1);
	__m128i b01 = tbl_gf16_mul( a0_a1 , a1inv );
	b01 = tbl_gf16_mul( b01 , b1 );
	__m128i a1x8 = tbl_gf16_mul_0x8( a1 );
	__m128i a0inv = tbl_gf16_inv(a0);
	__m128i a1x8xb1_1 = tbl_gf16_mul( a1x8 , b1 ) ^ _mm_set1_epi8(1);
	__m128i b02 = tbl_gf16_mul( a0inv , a1x8xb1_1 );
	__m128i b0 = _mm_setzero_si128();
	b0 |= _mm_andnot_si128( _mm_cmpeq_epi8(b0,a1inv), b01 ) |  _mm_andnot_si128( _mm_cmpeq_epi8(b0,a0inv), b02 );
	return _mm_slli_epi16(b1,4)^b0;
#else
// slow
	__m128i a2 = tbl_gf256_squ(a);
	__m128i a3 = tbl_gf256_mul(a2,a);
	__m128i a6 = tbl_gf256_squ(a3);
	__m128i a7 = tbl_gf256_mul(a6,a);
	__m128i ae = tbl_gf256_squ(a7);
	__m128i af = tbl_gf256_mul(ae,a);
	__m128i af1 = tbl_gf256_squ(af);
	__m128i af2 = tbl_gf256_squ(af1);
	__m128i af3 = tbl_gf256_squ(af2);
	__m128i a7f = tbl_gf256_mul(af3,a7);
	return tbl_gf256_squ(a7f);
#endif
}


static inline void gf256_inv_simd_16x( uint8_t * c , const uint8_t * a , unsigned n_x16 )
{
	for(unsigned i=0;i<n_x16; i++) {
		__m128i _a = _mm_load_si128( (__m128i*)(a+i*16) );
		__m128i _c = tbl_gf256_inv( _a );
		_mm_store_si128( (__m128i*)(c+i*16) , _c );
	}
}

static inline void gf256_mul_simd_16x( uint8_t * c , const uint8_t * a , const uint8_t * b , unsigned n_x16 )
{
	for(unsigned i=0;i<n_x16; i++) {
		__m128i _a = _mm_load_si128( (__m128i*)(a+i*16) );
		__m128i _b = _mm_load_si128( (__m128i*)(b+i*16) );
		__m128i _c = tbl_gf256_mul( _a , _b );
		_mm_store_si128( (__m128i*)(c+i*16) , _c );
	}
}

static inline __m128i tbl_gf256_set_value( unsigned char a ) { return _mm_set1_epi8(a); }

static inline void _tbl_gf256_set_value( unsigned char * b, unsigned char a ) {
	_mm_storeu_si128( (__m128i *)b , _mm_set1_epi8(a) );
}

static inline unsigned char tbl_gf256_get_1st_value( __m128i a ) { return (_mm_extract_epi16(a,0)&0xff); }



//////////////////////////////////  GF(256^3)  //////////////////////////////////////////////////


static inline void tbl_gf256_3_mul_const( __m128i * r , unsigned char a , const __m128i * b )
{
	r[0] = tbl_gf256_mul_const( a , b[0] );
	r[1] = tbl_gf256_mul_const( a , b[1] );
	r[2] = tbl_gf256_mul_const( a , b[2] );
}


// gf256^3 := gf256[X]/X^3+0x2
// ( a0 + a1 x + a2 x^2 )( b0 + b1 x + b2 x^2 )
// =  a0b0 ( 1 + x )
//  + a1b1 ( x + x^3 )
//  + a2b2 ( x^3 + x^4 )
//  + (a0+a1)(b0+b1) ( x + x^2 )
//  + (a1+a2)(b1+b2) ( x^2 + x^3 )
//  + (a0+a1+a2)(b0+b1+b2)  x^2
static inline void tbl_gf256_3_mul( __m128i * r , const __m128i * a , const __m128i * b )
{
        __m128i a0b0 = tbl_gf256_mul( a[0] , b[0] );
        __m128i a1b1 = tbl_gf256_mul( a[1] , b[1] );
        __m128i a2b2 = tbl_gf256_mul( a[2] , b[2] );
        __m128i a0a1_b0b1 = tbl_gf256_mul( a[0]^a[1] , b[0]^b[1] );
        __m128i a1a2_b1b2 = tbl_gf256_mul( a[1]^a[2] , b[1]^b[2] );
        __m128i a0a1a2_b0b1b2 = tbl_gf256_mul( a[0]^a[1]^a[2] , b[0]^b[1]^b[2] );

        __m128i r3 = a1b1^a2b2^a1a2_b1b2;

	r[0] = a0b0^ tbl_gf256_mul_const(2,r3);
	r[1] = a0b0^a1b1^a0a1_b0b1 ^ tbl_gf256_mul_const(2,a2b2);
	r[2] = a0a1_b0b1^a1a2_b1b2^a0a1a2_b0b1b2;
}

// gf256^3 := gf256[X]/X^3+0x2
static inline void tbl_gf256_3_squ( __m128i * r , const __m128i * a )
{
	__m128i r0 = tbl_gf256_squ( a[0] );
	__m128i r2 = tbl_gf256_squ( a[1] );
	__m128i r4 = tbl_gf256_squ( a[2] );

	r[0] = r0;
	r[1] = tbl_gf256_mul_const( 2 , r4 );
	r[2] = r2;
}


static inline void tbl_gf256_3_set_value( __m128i * r , uint32_t a )
{
	r[0] = tbl_gf256_set_value( a&0xff );
	r[1] = tbl_gf256_set_value( (a>>8)&0xff );
	r[2] = tbl_gf256_set_value( (a>>16)&0xff );
}

static inline uint32_t tbl_gf256_3_get_1st_value( const __m128i * a )
{
	uint32_t r0 = tbl_gf256_get_1st_value( a[0] );
	uint32_t r1 = tbl_gf256_get_1st_value( a[1] );
	uint32_t r2 = tbl_gf256_get_1st_value( a[2] );

	return r0^(r1<<8)^(r2<<16);
}








#endif
