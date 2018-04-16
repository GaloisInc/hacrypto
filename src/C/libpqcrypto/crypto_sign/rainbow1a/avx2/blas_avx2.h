#ifndef _BLAS_AVX2_H_
#define _BLAS_AVX2_H_

#include "gf16.h"

#include <immintrin.h>

#include "blas_config.h"
#include "assert.h"

#include "gf16_avx2.h"

#include "blas_sse.h"


#ifdef  __cplusplus
extern  "C" {
#endif



/////////////////  GF( 16 ) /////////////////////////////////////



static inline
void gf16v_mul_scalar_avx2( uint8_t * a, uint8_t gf16_b , unsigned _num_byte ) {
	unsigned b = gf16_b&0xf;
	__m256i m_tab = _mm256_load_si256( (__m256i*) (__gf16_mul + 32*b) );
	__m256i ml = _mm256_permute2x128_si256( m_tab , m_tab , 0 );
	__m256i mh = _mm256_permute2x128_si256( m_tab , m_tab , 0x11 );
	__m256i mask = _mm256_load_si256( (__m256i*) __mask_low );

	unsigned i=0;
	uint8_t temp[32] __attribute__((aligned(32)));
	for(;i<_num_byte;i+=32) {
		__m256i inp;
		if( i+32 <= _num_byte ) { inp = _mm256_loadu_si256( (__m256i*)(a+i) ); }
		else {
			for(unsigned j=0;j+i<_num_byte;j++) temp[j] = a[i+j];
			inp = _mm256_load_si256( (__m256i*) temp );
		}
		__m256i r0 = _mm256_shuffle_epi8(ml, inp&mask );
		__m256i r1 = _mm256_shuffle_epi8(mh, _mm256_srli_epi16(_mm256_andnot_si256(mask,inp),4) );
		r0 ^= r1;
		if( i+32 <= _num_byte ) _mm256_storeu_si256( (__m256i*)(a+i) , r0 );
		else {
			_mm256_store_si256( (__m256i*)temp , r0 );
			for(unsigned j=0;j+i<_num_byte;j++) a[i+j] = temp[j];
		}
	}
}



static inline
void gf16v_madd_avx2( uint8_t * accu_c, const uint8_t * a , uint8_t gf16_b, unsigned _num_byte ) {
	unsigned b = gf16_b&0xf;
	__m256i m_tab = _mm256_load_si256( (__m256i*) (__gf16_mul + 32*b) );
	__m256i ml = _mm256_permute2x128_si256( m_tab , m_tab , 0 );
	__m256i mh = _mm256_permute2x128_si256( m_tab , m_tab , 0x11 );
	__m256i mask = _mm256_load_si256( (__m256i*) __mask_low );

	unsigned i=0;
	uint8_t temp[32] __attribute__((aligned(32)));
	for(;i<_num_byte;i+=32) {
		__m256i inp;
		__m256i out;
		if( i+32 <= _num_byte ) {
			inp = _mm256_loadu_si256( (__m256i*)(a+i) );
			out = _mm256_loadu_si256( (__m256i*)(accu_c+i) );
		} else {
			for(unsigned j=0;j+i<_num_byte;j++) temp[j] = a[i+j];
			inp = _mm256_load_si256( (__m256i*) temp );
			for(unsigned j=0;j+i<_num_byte;j++) temp[j] = accu_c[i+j];
			out = _mm256_load_si256( (__m256i*) temp );
		}
		__m256i r0 = _mm256_shuffle_epi8(ml, inp&mask );
		__m256i r1 = _mm256_shuffle_epi8(mh, _mm256_srli_epi16(_mm256_andnot_si256(mask,inp),4) );
		r0 ^= r1^out;
		if( i+32 <= _num_byte ) _mm256_storeu_si256( (__m256i*)(accu_c+i) , r0 );
		else {
			_mm256_store_si256( (__m256i*)temp , r0 );
			for(unsigned j=0;j+i<_num_byte;j++) accu_c[i+j] = temp[j];
		}
	}
}




static inline
void gf16mat_prod_multab_avx2( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * multab ) {
	assert( n_A_width <= 256 );
	assert( n_A_vec_byte <= 128 );

	__m256i mask_f = _mm256_load_si256( (__m256i*)__mask_low);

	__m256i r0[4];
	__m256i r1[4];
	unsigned n_ymm = ((n_A_vec_byte + 31)>>5);
	for(unsigned i=0;i<n_ymm;i++) r0[i] = _mm256_setzero_si256();
	for(unsigned i=0;i<n_ymm;i++) r1[i] = _mm256_setzero_si256();

	for(unsigned i=0;i<n_A_width;i++) {
		__m128i ml = _mm_load_si128( (__m128i*)( multab + i*16) );
		__m256i mt = _mm256_inserti128_si256(_mm256_castsi128_si256(ml),ml,1);
		for(unsigned j=0;j<n_ymm;j++) {
			__m256i inp = _mm256_loadu_si256( (__m256i*)(matA+j*32) );
			r0[j] ^= _mm256_shuffle_epi8( mt , inp&mask_f );
			r1[j] ^= _mm256_shuffle_epi8( mt , _mm256_srli_epi16(inp,4)&mask_f );
		}
		matA += n_A_vec_byte;
	}
	uint8_t temp[128] __attribute__((aligned(32)));
	for(unsigned i=0;i<n_ymm;i++) _mm256_store_si256( (__m256i*)(temp + i*32) , r0[i]^_mm256_slli_epi16(r1[i],4) );
	for(unsigned i=0;i<n_A_vec_byte;i++) c[i] = temp[i];
}

#if 0
static inline
void gf16mat_prod_avx2( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * b ) {
	assert( n_A_width <= 128 );
	assert( n_A_vec_byte <= 64 );

	uint8_t multab[128*16] __attribute__((aligned(32)));
	gf16v_generate_multab_sse( multab , b , n_A_width );

	gf16mat_prod_multab_avx2( c , matA , n_A_vec_byte , n_A_width , multab );
}
#else
static inline
void gf16mat_prod_avx2( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * b ) {
	assert( n_A_width <= 256 );
	assert( n_A_vec_byte <= 128 );

	__m256i mask_f = _mm256_load_si256( (__m256i*)__mask_low);

	__m256i r0[4];
	__m256i r1[4];
	unsigned n_ymm = ((n_A_vec_byte + 31)>>5);
	for(unsigned i=0;i<n_ymm;i++) r0[i] = _mm256_setzero_si256();
	for(unsigned i=0;i<n_ymm;i++) r1[i] = _mm256_setzero_si256();

	uint8_t x[256] __attribute__((aligned(32)));
	gf16v_split_sse( x , b , n_A_width );
	for(unsigned i=0;i< ((n_A_width+31)>>5);i++) {
		__m256i lx = tbl32_gf16_log( _mm256_load_si256((__m256i*)(x+i*32)) );
		_mm256_store_si256((__m256i*)(x+i*32),lx);
	}

	for(unsigned i=0;i<n_A_width;i++) {
		x[0] = x[i];
		__m256i ml = _mm256_broadcastb_epi8( _mm_load_si128((__m128i*)x) );
		//__m128i ml = _mm_set1_epi8(x[i]);
		for(unsigned j=0;j<n_ymm;j++) {
			__m256i inp = _mm256_loadu_si256( (__m256i*)(matA+j*32) );
			r0[j] ^= tbl32_gf16_mul_log( inp&mask_f , ml , mask_f );
			r1[j] ^= tbl32_gf16_mul_log( _mm256_srli_epi16(inp,4)&mask_f , ml , mask_f );
		}
		matA += n_A_vec_byte;
	}
	for(unsigned i=0;i<n_ymm;i++) _mm256_store_si256( (__m256i*)(x + i*32) , r0[i]^_mm256_slli_epi16(r1[i],4) );
	for(unsigned i=0;i<n_A_vec_byte;i++) c[i] = x[i];
}
#endif




///////////////////////////////  GF( 256 ) ////////////////////////////////////////////////////



static inline
void gf256v_add_avx2( uint8_t * accu_b, const uint8_t * a , unsigned _num_byte ) {
	//uint8_t temp[32] __attribute__((aligned(32)));
	unsigned n_ymm = (_num_byte)>>5;
	unsigned i=0;
	for(;i<n_ymm;i++) {
		__m256i inp = _mm256_loadu_si256( (__m256i*) (a+i*32) );
		__m256i out = _mm256_loadu_si256( (__m256i*) (accu_b+i*32) );
		out ^= inp;
		_mm256_storeu_si256( (__m256i*) (accu_b+i*32) , out );
	}
	if( 0 == (_num_byte&0x1f) ) return;
	n_ymm <<= 5;
	gf256v_add_sse( accu_b + n_ymm , a + n_ymm , _num_byte - n_ymm );
}





static inline
void gf256mat_prod_multab_avx2( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * multab ) {
	assert( n_A_width <= 256 );
	assert( n_A_vec_byte <= 256 );

	__m256i mask_f = _mm256_load_si256((__m256i const *) __mask_low);

	__m256i r[8];
	unsigned n_ymm = ((n_A_vec_byte + 31)>>5);
	for(unsigned i=0;i<n_ymm;i++) r[i] = _mm256_setzero_si256();

	for(unsigned i=0;i<n_A_width;i++) {
		__m256i mt = _mm256_load_si256( (__m256i*)( multab + i*32) );
		__m256i ml = _mm256_permute2x128_si256(mt,mt,0x00 );
		__m256i mh = _mm256_permute2x128_si256(mt,mt,0x11 );
		for(unsigned j=0;j<n_ymm;j++) {
			__m256i inp = _mm256_loadu_si256( (__m256i*)(matA+j*32) );
			r[j] ^= _mm256_shuffle_epi8( ml , inp&mask_f );
			r[j] ^= _mm256_shuffle_epi8( mh , _mm256_srli_epi16(inp,4)&mask_f );
		}
		matA += n_A_vec_byte;
	}
	uint8_t r8[256] __attribute__((aligned(32)));
	for(unsigned i=0;i<n_ymm;i++) _mm256_store_si256( (__m256i*)(r8 + i*32) , r[i] );
	for(unsigned i=0;i<n_A_vec_byte;i++) c[i] = r8[i];
}


#if 0
// slower
static inline
void gf256mat_prod_secure_avx2( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * b ) {
	assert( n_A_width <= 128 );
	assert( n_A_vec_byte <= 80 );

	uint8_t multab[256*16] __attribute__((aligned(32)));
	gf256v_generate_multab_sse( multab , b , n_A_width );

	gf256mat_prod_multab_avx2( c , matA , n_A_vec_byte , n_A_width , multab );
}
#else
static inline
void gf256mat_prod_secure_avx2( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * b ) {
	assert( n_A_width <= 256 );
	assert( n_A_vec_byte <= 256 );

	__m256i mask_f = _mm256_load_si256( (__m256i*)__mask_low);

	__m256i r[8];
	unsigned n_ymm = ((n_A_vec_byte + 31)>>5);
	for(unsigned i=0;i<n_ymm;i++) r[i] = _mm256_setzero_si256();

	uint8_t x0[256] __attribute__((aligned(32)));
	uint8_t x1[256] __attribute__((aligned(32)));
	for(unsigned i=0;i<n_A_width;i++) x0[i] = b[i];
	for(unsigned i=0;i< ((n_A_width+31)>>5);i++) {
		__m256i inp = _mm256_load_si256((__m256i*)(x0+i*32));
		__m256i i0 = inp&mask_f;
		__m256i i1 = _mm256_srli_epi16(inp,4)&mask_f;
		_mm256_store_si256((__m256i*)(x0+i*32),tbl32_gf16_log(i0));
		_mm256_store_si256((__m256i*)(x1+i*32),tbl32_gf16_log(i1));
	}

	for(unsigned i=0;i<n_A_width;i++) {
		x0[0] = x0[i]; __m256i m0 = _mm256_broadcastb_epi8( _mm_load_si128((__m128i*)x0) );
		x1[0] = x1[i]; __m256i m1 = _mm256_broadcastb_epi8( _mm_load_si128((__m128i*)x1) );
		//__m128i ml = _mm_set1_epi8(x[i]);
		for(unsigned j=0;j<n_ymm;j++) {
			__m256i inp = _mm256_loadu_si256( (__m256i*)(matA+j*32) );
			__m256i l_i0 = tbl32_gf16_log(inp&mask_f);
			__m256i l_i1 = tbl32_gf16_log(_mm256_srli_epi16(inp,4)&mask_f);

			__m256i ab0 = tbl32_gf16_mul_log_log( l_i0 , m0 , mask_f );
			__m256i ab1 = tbl32_gf16_mul_log_log( l_i1 , m0 , mask_f )^tbl32_gf16_mul_log_log( l_i0 , m1 , mask_f );
			__m256i ab2 = tbl32_gf16_mul_log_log( l_i1 , m1 , mask_f );
			__m256i ab2x8 = tbl32_gf16_mul_0x8( ab2 );

			r[j] ^= ab0 ^ ab2x8 ^ _mm256_slli_epi16( ab1^ab2 , 4 );
		}
		matA += n_A_vec_byte;
	}
	for(unsigned i=0;i<n_ymm;i++) _mm256_store_si256( (__m256i*)(x0 + i*32) , r[i] );
	for(unsigned i=0;i<n_A_vec_byte;i++) c[i] = x0[i];
}
#endif







#ifdef  __cplusplus
}
#endif



#endif
