#ifndef _GF_EXT_AESNI_H_
#define _GF_EXT_AESNI_H_


//#include "gf16.h"

#include "blas.h"

#include "bitmat_prod_sse.h"

#include "emmintrin.h"
#include "wmmintrin.h"


#ifdef  __cplusplus
extern  "C" {
#endif



#define _MUL_128( c0,c2,a0,b0 ) \
do {\
  __m128i tt = _mm_clmulepi64_si128( a0,b0 , 0x01 ); \
  c0 = _mm_clmulepi64_si128( a0,b0, 0 ); \
  c2 = _mm_clmulepi64_si128( a0,b0, 0x11 ); \
  tt ^= _mm_clmulepi64_si128( a0,b0 , 0x10 ); \
  c0 ^= _mm_slli_si128( tt , 8 ); \
  c2 ^= _mm_srli_si128( tt , 8 ); \
} while(0)



#define _SQU_128( c0,c2,a0 ) \
do {\
  c0 = _mm_clmulepi64_si128( a0,a0, 0 ); \
  c2 = _mm_clmulepi64_si128( a0,a0, 0x11 ); \
} while(0)



#define _MUL_128_KARATSUBA( c0,c1,a0,b0 ) \
do {\
  c0 = _mm_clmulepi64_si128( a0,b0 , 0x00 ); \
  c1 = _mm_clmulepi64_si128( a0,b0 , 0x11 ); \
  __m128i _tt0 = a0^_mm_srli_si128(a0,8); \
  __m128i _tt1 = b0^_mm_srli_si128(b0,8); \
  _tt0 = _mm_clmulepi64_si128( _tt0, _tt1 , 0 )^c0^c1; \
  c0 ^= _mm_slli_si128( _tt0 , 8 ); \
  c1 ^= _mm_srli_si128( _tt0 , 8 ); \
} while(0)


#define _MUL_3_KARATSUBA( c0,c2,c4,a0,a2,b0,b2 ) \
do {\
 __m128i p0 = _mm_clmulepi64_si128( a0 , b0 , 0 ); \
 __m128i p2 = _mm_clmulepi64_si128( b2 , a2 , 0 ); \
 __m128i a1 = _mm_srli_si128(a0,8); \
 __m128i b1 = _mm_srli_si128(b0,8); \
 __m128i p012 = _mm_clmulepi64_si128( a1^a0^a2 , b1^b0^b2 , 0 ); \
 __m128i p01 = _mm_clmulepi64_si128( a0^a1 , b0^b1 , 0 ); \
 __m128i p02 = _mm_clmulepi64_si128( a0^a2 , b0^b2 , 0 ); \
 __m128i p12 = _mm_clmulepi64_si128( a1^a2 , b1^b2 , 0 ); \
 __m128i c64, c192; \
 c0 = p0; \
 c64 = p012 ^ p02 ^ p12 ^ p2; \
 c2 = p012 ^ p01 ^ p12; \
 c192 = p012 ^ p01 ^ p02 ^ p0; \
 c4 = p2; \
 c0 ^= _mm_slli_si128( c64 , 8 ); \
 c2 ^= _mm_srli_si128( c64 , 8 ); \
 c2 ^= _mm_slli_si128( c192 , 8 ); \
 c4 ^= _mm_srli_si128( c192 , 8 ); \
} while(0)


#define _MUL_4_KARATSUBA( c0,c2,c4,c6,a0,a2,b0,b2 ) \
do {\
  c0 = _mm_clmulepi64_si128( a0,b0 , 0x00 ); \
  c2 = _mm_clmulepi64_si128( a0,b0 , 0x11 ); \
  __m128i _tt0 = a0^_mm_srli_si128(a0,8); \
  __m128i _tt1 = b0^_mm_srli_si128(b0,8); \
  __m128i _tt2 = _mm_clmulepi64_si128( _tt0, _tt1 , 0 )^c0^c2; \
  c0 ^= _mm_slli_si128( _tt2 , 8 ); \
  c2 ^= _mm_srli_si128( _tt2 , 8 ); \
 \
  c4 = _mm_clmulepi64_si128( a2,b2 , 0x00 ); \
  c6 = _mm_clmulepi64_si128( a2,b2 , 0x11 ); \
  _tt0 = a2^_mm_srli_si128(a2,8); \
  _tt1 = b2^_mm_srli_si128(b2,8); \
  _tt2 = _mm_clmulepi64_si128( _tt0, _tt1 , 0 )^c4^c6; \
  c4 ^= _mm_slli_si128( _tt2 , 8 ); \
  c6 ^= _mm_srli_si128( _tt2 , 8 ); \
 \
  __m128i a02 = a0^a2; \
  __m128i b02 = b0^b2; \
  __m128i c22 = _mm_clmulepi64_si128( a02,b02 , 0x00 ); \
  __m128i c42 = _mm_clmulepi64_si128( a02,b02 , 0x11 ); \
  _tt0 = a02^_mm_srli_si128(a02,8); \
  _tt1 = b02^_mm_srli_si128(b02,8); \
  _tt2 = _mm_clmulepi64_si128( _tt0, _tt1 , 0 )^c22^c42; \
  c22 ^= _mm_slli_si128( _tt2 , 8 ); \
  c42 ^= _mm_srli_si128( _tt2 , 8 ); \
 \
  c22 ^= c0 ^ c4; \
  c42 ^= c2 ^ c6; \
  c2 ^= c22; \
  c4 ^= c42; \
} while(0)


////////////////  GF(2^240)  ////////////////////////

#define W32 32


extern const uint64_t gf25630to2240[];

extern const uint64_t gf2240to25630[];


static inline
void gf25630_from_2240_sse( uint8_t * r , const uint8_t * a , unsigned len ) { bitmatrix_prod_sse( r , gf2240to25630 , a , len ); }

static inline
void gf2240_from_25630_sse( uint8_t * r , const uint8_t * a , unsigned len ) { bitmatrix_prod_sse( r , gf25630to2240 , a , len ); }



/// x^240 + x^8 + x^5 + x^3 + 1  --> 0x129
/// x^256 = x^24 + x^21 + x^19 + x^16 --> 0x1290000
static const uint64_t _gf2ext240_reducer[2] __attribute__((aligned(16)))  = {0x1290000ULL,0x129ULL};
static const uint32_t _gf2ext240_mask_112bit[4] __attribute__((aligned(16)))  = {0xffffffff,0xffffffff,0xffffffff,0xffff};


static inline
void _gf2ext240_reduce_sse( __m128i * p_x0 , __m128i * p_x128 , __m128i x256 , __m128i x384 )
{
	__m128i reducer = _mm_load_si128( (__m128i const*)_gf2ext240_reducer );
	__m128i x0 = _mm_load_si128( p_x0 );
	__m128i x128 = _mm_load_si128( p_x128 );

	__m128i tt = _mm_clmulepi64_si128( x384 , reducer , 1 );
	x128 ^= _mm_clmulepi64_si128( x384 , reducer , 0 );
	x256 ^= _mm_srli_si128( tt , 8 );
	x128 ^= _mm_slli_si128( tt , 8 );

	tt = _mm_clmulepi64_si128( x256 , reducer , 1 );
	x0 ^= _mm_clmulepi64_si128( x256 , reducer , 0 );
	x128 ^= _mm_srli_si128( tt , 8 );
	x0 ^= _mm_slli_si128( tt , 8 );

	x0 ^= _mm_clmulepi64_si128( _mm_srli_si128(x128,6) , reducer , 0x11 );
	x128 &= *(__m128i*)_gf2ext240_mask_112bit;

	_mm_store_si128( p_x128 , x128 );
	_mm_store_si128( p_x0 , x0 );
}

static inline
void gf2ext240_mul_sse( uint8_t * c , const uint8_t * a , const uint8_t * b )
{
	__m128i a0 = _mm_loadu_si128( (__m128i const *)a );
	__m128i a128 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(a+14) ) , 2 );
	__m128i b0 = _mm_loadu_si128( (__m128i const *)b );
	__m128i b128 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(b+14) ) , 2 );
	__m128i c0,c128,c256,c384;
	_MUL_128_KARATSUBA( c0,c128, a0,b0 );
	_MUL_128_KARATSUBA( c256,c384, a128,b128 );

	__m128i tt0,tt1;
	a0 ^= a128;
	b0 ^= b128;
	_MUL_128_KARATSUBA( tt0,tt1, a0,b0 );
	tt0 ^= c0 ^ c256;
	tt1 ^= c128 ^ c384;
	c128 ^= tt0;
	c256 ^= tt1;

	_gf2ext240_reduce_sse( &c0 , &c128 , c256 , c384 );
	_mm_storeu_si128((__m128i*) c , c0 );
	_mm_storeu_si128((__m128i*) (c+14) , _mm_alignr_epi8(c128,c0,14) );
}


static inline
void gf2ext240_squ_sse( uint8_t * c , const uint8_t * a )
{
	__m128i a0 = _mm_loadu_si128( (__m128i const *)a );
	__m128i a128 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(a+14) ) , 2 );
	__m128i c0,c128,c256,c384;
	_SQU_128( c0,c128, a0 );
	_SQU_128( c256,c384, a128 );

	_gf2ext240_reduce_sse( &c0 , &c128 , c256 , c384 );
	_mm_storeu_si128((__m128i*) c , c0 );
	_mm_storeu_si128((__m128i*) (c+14) , _mm_alignr_epi8(c128,c0,14) );
}

static inline
void gf2ext240_pow_16_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext240_squ_sse(b,a);
	for(unsigned i=0;i<3;i++) gf2ext240_squ_sse( b , b );
}
static inline
void gf2ext240_pow_32_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext240_squ_sse(b,a);
	for(unsigned i=0;i<4;i++) gf2ext240_squ_sse( b , b );
}
static inline
void gf2ext240_pow_64_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext240_squ_sse(b,a);
	for(unsigned i=0;i<5;i++) gf2ext240_squ_sse( b , b );
}

static inline
void gf2ext240_pow_256_1_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext240_squ_sse(b,a);
	for(unsigned i=0;i<7;i++) gf2ext240_squ_sse( b , b );
}


/// 256^32 - 2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
static inline
void gf2ext240_inv_sse( uint8_t * b , const uint8_t * a )
{
//	static const unsigned W = 32;
	uint8_t tmp[W32] __attribute__((aligned(16))) = {0}; gf2ext240_squ_sse(tmp,a);
	uint8_t a3[W32] __attribute__((aligned(16))); gf2ext240_mul_sse(a3,tmp,a);
	gf2ext240_squ_sse(tmp,a3);
	gf2ext240_squ_sse(tmp,tmp);
	uint8_t aF[W32] __attribute__((aligned(16))); gf2ext240_mul_sse(aF,tmp,a3);
	gf2ext240_squ_sse(tmp,aF);
	gf2ext240_squ_sse(tmp,tmp);
	gf2ext240_squ_sse(tmp,tmp);
	gf2ext240_squ_sse(tmp,tmp);
	uint8_t aFF[W32] __attribute__((aligned(16))); gf2ext240_mul_sse(aFF,tmp,aF);

	for(unsigned i=0;i<W32;i++) tmp[i]=aFF[i];
	for(unsigned i=0;i<28;i++) {
		gf2ext240_pow_256_1_sse(tmp,tmp);
		gf2ext240_mul_sse(tmp,tmp,aFF);
	}
	gf2ext240_squ_sse(tmp,tmp);
	gf2ext240_squ_sse(tmp,tmp);
	gf2ext240_squ_sse(tmp,tmp);
	gf2ext240_squ_sse(tmp,tmp);
	gf2ext240_mul_sse(tmp,tmp,aF);
	gf2ext240_squ_sse(tmp,tmp);
	gf2ext240_squ_sse(tmp,tmp);
	gf2ext240_mul_sse(tmp,tmp,a3);
	gf2ext240_squ_sse(tmp,tmp);
	gf2ext240_mul_sse(tmp,tmp,a);
	gf2ext240_squ_sse(b,tmp);

}






////////////////  GF(2^184)  ////////////////////////

#ifndef W23
#define W23 23
#endif

extern const uint64_t gf25623to2184[];

extern const uint64_t gf2184to25623[];

static inline
void gf25623_from_2184_sse( uint8_t * r , const uint8_t * a , unsigned len ) { bitmatrix_prod_sse( r , gf2184to25623 , a , len ); }

static inline
void gf2184_from_25623_sse( uint8_t * r , const uint8_t * a , unsigned len ) { bitmatrix_prod_sse( r , gf25623to2184 , a , len ); }



/// x^184 + x^8 + x^6 + x^4 + x^3 + x^2 + 1  --> 0x15d
/// x^192 = x^16 + x^14 + x^12 + x^11 + x^10 + x^8 --> 0x15d<<8
static const uint64_t _gf2ext184_reducer[2] __attribute__((aligned(16)))  = {0x15d00ULL,0x15dULL};


static inline
void _gf2ext184_reduce_sse( __m128i * p_x0 , __m128i * p_x128 , __m128i x256 )
{
	__m128i reducer = _mm_load_si128( (__m128i const*)_gf2ext184_reducer );
	__m128i x0 = _mm_load_si128( p_x0 );
	__m128i x128 = _mm_load_si128( p_x128 );

	x128 ^= _mm_clmulepi64_si128( x256 , reducer , 1 );
	__m128i tt = _mm_clmulepi64_si128( x256 , reducer , 0 );
	x128 ^= _mm_srli_si128( tt , 8 );
	x0 ^= _mm_slli_si128( tt , 8 );

	x0 ^= _mm_clmulepi64_si128( x128 , reducer , 1 );
	x0 ^= _mm_clmulepi64_si128( _mm_srli_epi64( x128 , 56 ) , reducer , 0x10 );

	x128 = _mm_slli_si128( x128 , 9 );
	x128 = _mm_srli_si128( x128 , 9 );

	_mm_store_si128( p_x128 , x128 );
	_mm_store_si128( p_x0 , x0 );
}

static inline
void gf2ext184_mul_sse( uint8_t * c , const uint8_t * a , const uint8_t * b )
{
	__m128i a0 = _mm_loadu_si128( (__m128i const *)a );
	__m128i a128 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(a+7) ) , 9 );
	__m128i b0 = _mm_loadu_si128( (__m128i const *)b );
	__m128i b128 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(b+7) ) , 9 );

	/// 3 way karatsuba
	__m128i c0,c128,c256;
	_MUL_3_KARATSUBA( c0,c128,c256,a0,a128,b0,b128 );

	_gf2ext184_reduce_sse( &c0 , &c128 , c256 );
	_mm_storeu_si128((__m128i*) c , c0 );
	_mm_storeu_si128((__m128i*) (c+7) , _mm_alignr_epi8(c128,c0,7) );
}


static inline
void gf2ext184_squ_sse( uint8_t * c , const uint8_t * a )
{
	__m128i a0 = _mm_loadu_si128( (__m128i const *)a );
	__m128i a128 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(a+7) ) , 9 );

	__m128i c0,c128,c256;
	c0 = _mm_clmulepi64_si128( a0,a0, 0 );
	c128 = _mm_clmulepi64_si128( a0,a0, 0x11 );
	c256 = _mm_clmulepi64_si128( a128,a128, 0 );

	_gf2ext184_reduce_sse( &c0 , &c128 , c256 );
	_mm_storeu_si128((__m128i*) c , c0 );
	_mm_storeu_si128((__m128i*) (c+7) , _mm_alignr_epi8(c128,c0,7) );

}

static inline
void gf2ext184_pow_16_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext184_squ_sse(b,a);
	for(unsigned i=0;i<3;i++) gf2ext184_squ_sse( b , b );
}
static inline
void gf2ext184_pow_32_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext184_squ_sse(b,a);
	for(unsigned i=0;i<4;i++) gf2ext184_squ_sse( b , b );
}
static inline
void gf2ext184_pow_64_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext184_squ_sse(b,a);
	for(unsigned i=0;i<5;i++) gf2ext184_squ_sse( b , b );
}

static inline
void gf2ext184_pow_256_1_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext184_squ_sse(b,a);
	for(unsigned i=0;i<7;i++) gf2ext184_squ_sse( b , b );
}


static inline
void gf2ext184_inv_sse( uint8_t * b , const uint8_t * a )
{
//	static const unsigned W = 32;
	uint8_t tmp[W23] __attribute__((aligned(16))) = {0}; gf2ext184_squ_sse(tmp,a);
	uint8_t a3[W23] __attribute__((aligned(16))); gf2ext184_mul_sse(a3,tmp,a);
	gf2ext184_squ_sse(tmp,a3);
	gf2ext184_squ_sse(tmp,tmp);
	uint8_t aF[W23] __attribute__((aligned(16))); gf2ext184_mul_sse(aF,tmp,a3);
	gf2ext184_squ_sse(tmp,aF);
	gf2ext184_squ_sse(tmp,tmp);
	gf2ext184_squ_sse(tmp,tmp);
	gf2ext184_squ_sse(tmp,tmp);
	uint8_t aFF[W23] __attribute__((aligned(16))); gf2ext184_mul_sse(aFF,tmp,aF);

	for(unsigned i=0;i<W23;i++) tmp[i]=aFF[i];
	for(unsigned i=0;i<(W23-2);i++) {
		gf2ext184_pow_256_1_sse(tmp,tmp);
		gf2ext184_mul_sse(tmp,tmp,aFF);
	}
	gf2ext184_squ_sse(tmp,tmp);
	gf2ext184_squ_sse(tmp,tmp);
	gf2ext184_squ_sse(tmp,tmp);
	gf2ext184_squ_sse(tmp,tmp);
	gf2ext184_mul_sse(tmp,tmp,aF);
	gf2ext184_squ_sse(tmp,tmp);
	gf2ext184_squ_sse(tmp,tmp);
	gf2ext184_mul_sse(tmp,tmp,a3);
	gf2ext184_squ_sse(tmp,tmp);
	gf2ext184_mul_sse(tmp,tmp,a);
	gf2ext184_squ_sse(b,tmp);

}





////////////////  GF(2^312)  ////////////////////////

#ifndef W39
#define W39 39
#endif


extern const uint64_t gf25639to2312[];

extern const uint64_t gf2312to25639[];

static inline
void gf25639_from_2312_sse( uint8_t * r , const uint8_t * a , unsigned len ) { bitmatrix_prod_sse( r , gf2312to25639 , a , len ); }

static inline
void gf2312_from_25639_sse( uint8_t * r , const uint8_t * a , unsigned len ) { bitmatrix_prod_sse( r , gf25639to2312 , a , len ); }



/// x^312 + x^9 + x^7 + x^4 + 1  --> 0x291
/// x^320 = .....  --> 0x291 << 8
static const uint64_t _gf2ext312_reducer[2] __attribute__((aligned(16)))  = {0x29100ULL,0x291ULL};

static inline
void _gf2ext312_reduce_sse( __m128i * p_x0 , __m128i * p_x128 , __m128i * p_x256 , __m128i x384 , __m128i x512 )
{
	__m128i reducer = _mm_load_si128( (__m128i const*)_gf2ext312_reducer );
	__m128i x0 = _mm_load_si128( p_x0 );
	__m128i x128 = _mm_load_si128( p_x128 );
	__m128i x256 = _mm_load_si128( p_x256 );

	x256 ^= _mm_clmulepi64_si128( x512 , reducer , 1 );
	__m128i tt = _mm_clmulepi64_si128( x512 , reducer , 0 );
	x256 ^= _mm_srli_si128( tt , 8 );
	x128 ^= _mm_slli_si128( tt , 8 );

	x128 ^= _mm_clmulepi64_si128( x384 , reducer , 1 );
	tt = _mm_clmulepi64_si128( x384 , reducer , 0 );
	x128 ^= _mm_srli_si128( tt , 8 );
	x0 ^= _mm_slli_si128( tt , 8 );

	x0 ^= _mm_clmulepi64_si128( x256 , reducer , 1 );
	x0 ^= _mm_clmulepi64_si128( _mm_srli_epi64( x256 , 56 ) , reducer , 0x10 );

	x256 = _mm_slli_si128( x256 , 9 );
	x256 = _mm_srli_si128( x256 , 9 );

	_mm_store_si128( p_x0 , x0 );
	_mm_store_si128( p_x128 , x128 );
	_mm_store_si128( p_x256 , x256 );
}


static inline
void gf2ext312_mul_sse( uint8_t * c , const uint8_t * a , const uint8_t * b )
{
	__m128i a0 = _mm_loadu_si128( (__m128i const *)a );
	__m128i a2 = _mm_loadu_si128( (__m128i const *)(a+16) );
	__m128i a4 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(a+16+7) ) , 9 );
	__m128i b0 = _mm_loadu_si128( (__m128i const *)b );
	__m128i b2 = _mm_loadu_si128( (__m128i const *)(b+16) );
	__m128i b4 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(b+16+7) ) , 9 );

	__m128i a3 = _mm_alignr_epi8(a4,a2,8);
	__m128i b3 = _mm_alignr_epi8(b4,b2,8);

	__m128i c0,c2,c4,c6,c8;
	_MUL_3_KARATSUBA( c0 , c2 , c4 , a0 , a2 , b0 , b2 );
	_MUL_128_KARATSUBA( c6,c8,a3,b3 );

	__m128i c3,c5,c7;
	a0 ^= a3;
	b0 ^= b3;
	_MUL_3_KARATSUBA( c3 , c5 , c7 , a0 , a2 , b0 , b2 );
	c3 ^= c0^c6;
	c5 ^= c2^c8;
	c7 ^= c4;

	c2 ^= _mm_slli_si128( c3 , 8 );
	c4 ^= _mm_alignr_epi8( c5, c3 , 8 );
	c6 ^= _mm_alignr_epi8( c7 , c5 , 8 );
	c8 ^= _mm_srli_si128( c7 , 8 );

	_gf2ext312_reduce_sse( &c0 , &c2 ,&c4 , c6 , c8 );
	_mm_storeu_si128((__m128i*) c , c0 );
	_mm_storeu_si128((__m128i*) (c+16) , c2 );
	_mm_storeu_si128((__m128i*) (c+16+7) , _mm_alignr_epi8(c4,c2,7) );
}


static inline
void gf2ext312_squ_sse( uint8_t * c , const uint8_t * a )
{
	__m128i a0 = _mm_loadu_si128( (__m128i const *)a );
	__m128i a2 = _mm_loadu_si128( (__m128i const *)(a+16) );
	__m128i a4 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(a+16+7) ) , 9 );

	__m128i c0,c2,c4,c6,c8;
	c0 = _mm_clmulepi64_si128( a0,a0, 0 );
	c2 = _mm_clmulepi64_si128( a0,a0, 0x11 );
	c4 = _mm_clmulepi64_si128( a2,a2, 0 );
	c6 = _mm_clmulepi64_si128( a2,a2, 0x11 );
	c8 = _mm_clmulepi64_si128( a4,a4, 0 );

	_gf2ext312_reduce_sse( &c0 , &c2 ,&c4 , c6 , c8 );
	_mm_storeu_si128((__m128i*) c , c0 );
	_mm_storeu_si128((__m128i*) (c+16) , c2 );
	_mm_storeu_si128((__m128i*) (c+16+7) , _mm_alignr_epi8(c4,c2,7) );

}



static inline
void gf2ext312_pow_16_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext312_squ_sse(b,a);
	for(unsigned i=0;i<3;i++) gf2ext312_squ_sse( b , b );
}
static inline
void gf2ext312_pow_32_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext312_squ_sse(b,a);
	for(unsigned i=0;i<4;i++) gf2ext312_squ_sse( b , b );
}
static inline
void gf2ext312_pow_64_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext312_squ_sse(b,a);
	for(unsigned i=0;i<5;i++) gf2ext312_squ_sse( b , b );
}

static inline
void gf2ext312_pow_256_1_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext312_squ_sse(b,a);
	for(unsigned i=0;i<7;i++) gf2ext312_squ_sse( b , b );
}


static inline
void gf2ext312_inv_sse( uint8_t * b , const uint8_t * a )
{
	uint8_t tmp[W39] __attribute__((aligned(16))) = {0}; gf2ext312_squ_sse(tmp,a);
	uint8_t a3[W39] __attribute__((aligned(16))); gf2ext312_mul_sse(a3,tmp,a);
	gf2ext312_squ_sse(tmp,a3);
	gf2ext312_squ_sse(tmp,tmp);
	uint8_t aF[W39] __attribute__((aligned(16))); gf2ext312_mul_sse(aF,tmp,a3);
	gf2ext312_squ_sse(tmp,aF);
	gf2ext312_squ_sse(tmp,tmp);
	gf2ext312_squ_sse(tmp,tmp);
	gf2ext312_squ_sse(tmp,tmp);
	uint8_t aFF[W39] __attribute__((aligned(16))); gf2ext312_mul_sse(aFF,tmp,aF);

	for(unsigned i=0;i<W39;i++) tmp[i]=aFF[i];
	for(unsigned i=0;i<(W39-2);i++) {
		gf2ext312_pow_256_1_sse(tmp,tmp);
		gf2ext312_mul_sse(tmp,tmp,aFF);
	}
	gf2ext312_squ_sse(tmp,tmp);
	gf2ext312_squ_sse(tmp,tmp);
	gf2ext312_squ_sse(tmp,tmp);
	gf2ext312_squ_sse(tmp,tmp);
	gf2ext312_mul_sse(tmp,tmp,aF);
	gf2ext312_squ_sse(tmp,tmp);
	gf2ext312_squ_sse(tmp,tmp);
	gf2ext312_mul_sse(tmp,tmp,a3);
	gf2ext312_squ_sse(tmp,tmp);
	gf2ext312_mul_sse(tmp,tmp,a);
	gf2ext312_squ_sse(b,tmp);

}





////////////////  GF(2^448)  ////////////////////////

#ifndef W56
#define W56 56
#endif


extern const uint64_t gf25656to2448[];

extern const uint64_t gf2448to25656[];

static inline
void gf25656_from_2448_sse( uint8_t * r , const uint8_t * a , unsigned len ) { bitmatrix_prod_sse( r , gf2448to25656 , a , len ); }

static inline
void gf2448_from_25656_sse( uint8_t * r , const uint8_t * a , unsigned len ) { bitmatrix_prod_sse( r , gf25656to2448 , a , len ); }



/// x^448 + x^7 + x^5 + x^4 + x^3 + x^2 + 1  --> 0xbd
static const uint64_t _gf2ext448_reducer[2] __attribute__((aligned(16)))  = {0xbdULL,0xbdULL};


static inline
void _gf2ext448_reduce_sse( __m128i * p_x0 , __m128i * p_x128 , __m128i * p_x256 , __m128i * p_x384 , __m128i x512 , __m128i x640 , __m128i x768 )
{
	__m128i reducer = _mm_load_si128( (__m128i const*)_gf2ext448_reducer );
	__m128i x0 = _mm_load_si128( p_x0 );
	__m128i x128 = _mm_load_si128( p_x128 );
	__m128i x256 = _mm_load_si128( p_x256 );
	__m128i x384 = _mm_load_si128( p_x384 );

	x384 ^= _mm_clmulepi64_si128( x768 , reducer , 1 );
	__m128i tt0 = _mm_clmulepi64_si128( x768 , reducer , 0 );
	x384 ^= _mm_srli_si128( tt0 , 8 );

	x256 ^= _mm_clmulepi64_si128( x640 , reducer , 1 );
	__m128i tt1 = _mm_clmulepi64_si128( x640 , reducer , 0 );
	x256 ^= _mm_alignr_epi8( tt0 , tt1 , 8 );

	x128 ^= _mm_clmulepi64_si128( x512 , reducer , 1 );
	__m128i tt2 = _mm_clmulepi64_si128( x512 , reducer , 0 );
	x128 ^= _mm_alignr_epi8( tt1 , tt2 , 8 );

	x0 ^= _mm_clmulepi64_si128( x384 , reducer , 1 );
	x0 ^= _mm_slli_si128( tt2 , 8 );

	_mm_store_si128( p_x0 , x0 );
	_mm_store_si128( p_x128 , x128 );
	_mm_store_si128( p_x256 , x256 );
	_mm_store_si128( p_x384 , x384 );
}


static inline
void gf2ext448_mul_sse( uint8_t * c , const uint8_t * a , const uint8_t * b )
{
	__m128i a0 = _mm_loadu_si128( (__m128i const *)a );
	__m128i a2 = _mm_loadu_si128( (__m128i const *)(a+16) );
	__m128i a4 = _mm_loadu_si128( (__m128i const *)(a+32) );
	__m128i a6 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(a+16*2+8) ) , 8 );
	__m128i b0 = _mm_loadu_si128( (__m128i const *)b );
	__m128i b2 = _mm_loadu_si128( (__m128i const *)(b+16) );
	__m128i b4 = _mm_loadu_si128( (__m128i const *)(b+32) );
	__m128i b6 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(b+16*2+8) ) , 8 );

	__m128i c0,c2,c4,c6,c8, c10, c12;
	_MUL_4_KARATSUBA( c0 , c2 , c4 , c6 , a0 , a2 , b0 , b2 );
	_MUL_3_KARATSUBA( c8 , c10 , c12 , a4 , a6 , b4 , b6 );
	a0 ^= a4;
	a2 ^= a6;
	b0 ^= b4;
	b2 ^= b6;
	__m128i t0,t2,t4,t6;
	_MUL_4_KARATSUBA( t0 , t2 , t4 , t6 , a0 , a2 , b0 , b2 );
	t0 ^= c0 ^ c8;
	t2 ^= c2 ^ c10;
	t4 ^= c4 ^ c12;
	t6 ^= c6;
	c4 ^= t0;
	c6 ^= t2;
	c8 ^= t4;
	c10 ^= t6;

	_gf2ext448_reduce_sse( &c0 , &c2 ,&c4 , &c6 , c8 , c10 ,c12 );
	_mm_storeu_si128((__m128i*) c , c0 );
	_mm_storeu_si128((__m128i*) (c+16) , c2 );
	_mm_storeu_si128((__m128i*) (c+32) , c4 );
	_mm_storeu_si128((__m128i*) (c+32+8) , _mm_alignr_epi8(c6,c4,8) );
}


static inline
void gf2ext448_squ_sse( uint8_t * c , const uint8_t * a )
{
	__m128i a0 = _mm_loadu_si128( (__m128i const *)a );
	__m128i a2 = _mm_loadu_si128( (__m128i const *)(a+16) );
	__m128i a4 = _mm_loadu_si128( (__m128i const *)(a+32) );
	__m128i a6 = _mm_srli_si128( _mm_loadu_si128( (__m128i const *)(a+16*2+8) ) , 8 );

	__m128i c0,c2,c4,c6,c8, c10, c12;
	c0 = _mm_clmulepi64_si128( a0,a0, 0 );
	c2 = _mm_clmulepi64_si128( a0,a0, 0x11 );
	c4 = _mm_clmulepi64_si128( a2,a2, 0 );
	c6 = _mm_clmulepi64_si128( a2,a2, 0x11 );
	c8 = _mm_clmulepi64_si128( a4,a4, 0 );
	c10 = _mm_clmulepi64_si128( a4,a4, 0x11 );
	c12 = _mm_clmulepi64_si128( a6,a6, 0 );

	_gf2ext448_reduce_sse( &c0 , &c2 ,&c4 , &c6 , c8 , c10 ,c12 );
	_mm_storeu_si128((__m128i*) c , c0 );
	_mm_storeu_si128((__m128i*) (c+16) , c2 );
	_mm_storeu_si128((__m128i*) (c+32) , c4 );
	_mm_storeu_si128((__m128i*) (c+32+8) , _mm_alignr_epi8(c6,c4,8) );
}



static inline
void gf2ext448_pow_16_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext448_squ_sse(b,a);
	for(unsigned i=0;i<3;i++) gf2ext448_squ_sse( b , b );
}
static inline
void gf2ext448_pow_32_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext448_squ_sse(b,a);
	for(unsigned i=0;i<4;i++) gf2ext448_squ_sse( b , b );
}
static inline
void gf2ext448_pow_64_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext448_squ_sse(b,a);
	for(unsigned i=0;i<5;i++) gf2ext448_squ_sse( b , b );
}

static inline
void gf2ext448_pow_256_1_sse( uint8_t * b , const uint8_t * a )
{
	gf2ext448_squ_sse(b,a);
	for(unsigned i=0;i<7;i++) gf2ext448_squ_sse( b , b );
}


static inline
void gf2ext448_inv_sse( uint8_t * b , const uint8_t * a )
{
	uint8_t tmp[W56] __attribute__((aligned(16))) = {0}; gf2ext448_squ_sse(tmp,a);
	uint8_t a3[W56] __attribute__((aligned(16))); gf2ext448_mul_sse(a3,tmp,a);
	gf2ext448_squ_sse(tmp,a3);
	gf2ext448_squ_sse(tmp,tmp);
	uint8_t aF[W56] __attribute__((aligned(16))); gf2ext448_mul_sse(aF,tmp,a3);
	gf2ext448_squ_sse(tmp,aF);
	gf2ext448_squ_sse(tmp,tmp);
	gf2ext448_squ_sse(tmp,tmp);
	gf2ext448_squ_sse(tmp,tmp);
	uint8_t aFF[W56] __attribute__((aligned(16))); gf2ext448_mul_sse(aFF,tmp,aF);

	for(unsigned i=0;i<W56;i++) tmp[i]=aFF[i];
	for(unsigned i=0;i<(W56-2);i++) {
		gf2ext448_pow_256_1_sse(tmp,tmp);
		gf2ext448_mul_sse(tmp,tmp,aFF);
	}
	gf2ext448_squ_sse(tmp,tmp);
	gf2ext448_squ_sse(tmp,tmp);
	gf2ext448_squ_sse(tmp,tmp);
	gf2ext448_squ_sse(tmp,tmp);
	gf2ext448_mul_sse(tmp,tmp,aF);
	gf2ext448_squ_sse(tmp,tmp);
	gf2ext448_squ_sse(tmp,tmp);
	gf2ext448_mul_sse(tmp,tmp,a3);
	gf2ext448_squ_sse(tmp,tmp);
	gf2ext448_mul_sse(tmp,tmp,a);
	gf2ext448_squ_sse(b,tmp);

}







#ifdef  __cplusplus
}
#endif



#endif
