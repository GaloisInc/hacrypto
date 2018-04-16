#ifndef _BLAS_AVX2_H_
#define _BLAS_AVX2_H_

#include "blas.h"

#include "gf31_sse.h"

#include <immintrin.h>


#ifdef  __cplusplus
extern  "C" {
#endif


static inline
__m256i _gf31v_u8_to_u16_avx2( __m128i a ) {
	__m128i zero = _mm_setzero_si128();
	__m128i a0 = _mm_unpacklo_epi8( a , zero );
	__m128i a1 = _mm_unpackhi_epi8( a , zero );

	return _mm256_insertf128_si256 ( _mm256_castsi128_si256(a0) , a1 , 1 );
}


static inline
void gf31v_u8_to_u16( uint8_t * a16 , const uint8_t * a8 , unsigned n ) {
	uint16_t * a = (uint16_t *)a16;
	while( 16 <= n ){
		__m128i pa = _mm_loadu_si128( (const __m128i*)a8 );
		__m256i pr = _gf31v_u8_to_u16_avx2( pa );
		_mm256_storeu_si256( (__m256i*) a , pr );
		a += 16;
		a8 += 16;
		n -= 16;

	}
	if( 0 == n ) return;

	uint8_t temp[32] __attribute__((aligned(32))) = {0};
	uint16_t * temp_u16 = (uint16_t*)temp;
	for(unsigned i=0;i<n;i++) temp[i] = a8[i];
	__m128i pa = _mm_load_si128( (const __m128i*)temp );
	__m256i pr = _gf31v_u8_to_u16_avx2(pa);
	_mm256_store_si256( (__m256i*) temp , pr );
	for(unsigned i=0;i<n;i++) a[i] = temp_u16[i];
}


static inline
__m128i _gf31v_u16_to_u8_avx2( __m256i a ) {
	__m128i a1 = _mm256_extractf128_si256( a , 1 );
	__m128i a0 = _mm256_castsi256_si128( a );
	return _mm_packus_epi16( a0 , a1 );
}


static inline
void gf31v_u16_to_u8( uint8_t * a8 , const uint8_t * a16 , unsigned n ) {
	const uint16_t * a = (const uint16_t *)a16;
	while( 16 <= n ){
		__m256i pa = _mm256_loadu_si256( (const __m256i*)a );
		__m128i pr = _gf31v_u16_to_u8_avx2( pa );
		_mm_storeu_si128( (__m128i*) a8 , pr );
		a += 16;
		a8 += 16;
		n -= 16;

	}
	if( 0 == n ) return;

	uint8_t temp[32] __attribute__((aligned(32))) = {0};
	uint16_t * temp16 = (uint16_t *) &temp[0];

	for(unsigned i=0;i<n;i++) temp16[i] = a[i];
	__m256i pa = _mm256_load_si256( (const __m256i*)temp );
	__m128i pr = _gf31v_u16_to_u8_avx2(pa);
	_mm_store_si128( (__m128i*) temp , pr );
	for(unsigned i=0;i<n;i++) a8[i] = temp[i];
}



static inline
void gf31v_mul_scalar_u16_avx2( uint16_t * r , const uint16_t * a , uint16_t b , unsigned n ) {
	__m256i mb = _mm256_set1_epi16( b );
	while( 16 <= n ){
		__m256i pa = _mm256_loadu_si256( (const __m256i*)a );
		__m256i pr = _mm256_mullo_epi16( pa , mb );
		_mm256_storeu_si256( (__m256i*) r , pr );

		a += 16;
		r += 16;
		n -= 16;

	}
	if( 0 == n ) return;

	uint16_t temp[16] __attribute__((aligned(32))) = {0};

	for(unsigned i=0;i<n;i++) temp[i] = a[i];
	__m256i pa = _mm256_load_si256( (const __m256i*)temp );
	__m256i pr = _mm256_mullo_epi16( pa , mb );
	_mm256_store_si256( (__m256i*) temp , pr );
	for(unsigned i=0;i<n;i++) r[i] = temp[i];
}


static inline
__m256i _gf31v_reduce_u16_avx2( __m256i a ){
	__m256i mask = _mm256_set1_epi16( 31 );
	return _mm256_add_epi16( a&mask , _mm256_srli_epi16(a,5) );
}



static inline
void gf31v_reduce_u16_avx2( uint16_t * a , unsigned n ) {
	while( 16 <= n ){
		__m256i pa = _mm256_loadu_si256( (const __m256i*)a );
		pa = _gf31v_reduce_u16_avx2( pa );
		_mm256_storeu_si256( (__m256i*) a , pa );
		a += 16;
		n -= 16;

	}
	if( 0 == n ) return;

	uint16_t temp[16] __attribute__((aligned(32))) = {0};

	for(unsigned i=0;i<n;i++) temp[i] = a[i];
	__m256i pa = _mm256_load_si256( (const __m256i*)temp );
	__m256i pr = _gf31v_reduce_u16_avx2(pa);
	_mm256_store_si256( (__m256i*) temp , pr );
	for(unsigned i=0;i<n;i++) a[i] = temp[i];
}


static inline
__m256i _gf31v_reduce_u8_avx2( __m256i a ){
	__m256i mask_31 = _mm256_set1_epi8( 31 );
	__m256i mask_30 = _mm256_set1_epi8( 30 );
	__m256i r1 = _mm256_sub_epi8( a , _mm256_cmpgt_epi8(a,mask_30)&mask_31 );
	__m256i r2 = _mm256_sub_epi8( r1 , _mm256_cmpgt_epi8(r1,mask_30)&mask_31 );

	return r2;
}


static inline
void gf31v_reduce_u8_avx2( uint8_t * a , unsigned n ) {
	while( 32 <= n ){
		__m256i pa = _mm256_loadu_si256( (const __m256i*)a );
		pa = _gf31v_reduce_u8_avx2( pa );
		_mm256_storeu_si256( (__m256i*) a , pa );
		a += 32;
		n -= 32;

	}
	if( 0 == n ) return;

	uint8_t temp[32] __attribute__((aligned(32))) = {0};

	for(unsigned i=0;i<n;i++) temp[i] = a[i];
	__m256i pa = _mm256_load_si256( (const __m256i*)temp );
	__m256i pr = _gf31v_reduce_u8_avx2(pa);
	_mm256_store_si256( (__m256i*) temp , pr );
	for(unsigned i=0;i<n;i++) a[i] = temp[i];
}



static inline
void gf31v_add_avx2( uint8_t * accu_b, const uint8_t * a , unsigned n ) {
	__m256i mask_31 = _mm256_set1_epi8( 31 );
	__m256i mask_30 = _mm256_set1_epi8( 30 );

	while( 32 <= n ){
		__m256i pa = _mm256_loadu_si256( (const __m256i*)a );
		__m256i pb = _mm256_loadu_si256( (const __m256i*)accu_b );
		__m256i pc = _mm256_add_epi8( pa , pb );
		__m256i r1 = _mm256_sub_epi8( pc , _mm256_cmpgt_epi8(pc,mask_30)&mask_31 );
		_mm256_storeu_si256( (__m256i*) accu_b , r1 );
		a += 32;
		accu_b += 32;
		n -= 32;

	}
	if( 0 == n ) return;

	uint8_t temp[32] __attribute__((aligned(32))) = {0};

	for(unsigned i=0;i<n;i++) temp[i] = a[i];
	__m256i pa = _mm256_load_si256( (const __m256i*)temp );
	for(unsigned i=0;i<n;i++) temp[i] = accu_b[i];
	__m256i pb = _mm256_load_si256( (const __m256i*)temp );
	__m256i pc = _mm256_add_epi8( pa , pb );
	__m256i r1 = _mm256_sub_epi8( pc , _mm256_cmpgt_epi8(pc,mask_30)&mask_31 );
	_mm256_store_si256( (__m256i*) temp , r1 );

	for(unsigned i=0;i<n;i++) accu_b[i] = temp[i];
}

static inline
void gf31v_sub_avx2( uint8_t * accu_b, const uint8_t * a , unsigned n ) {
	__m256i mask_31 = _mm256_set1_epi8( 31 );
	__m256i mask_30 = _mm256_set1_epi8( 30 );

	while( 32 <= n ){
		__m256i pa = _mm256_loadu_si256( (const __m256i*)a );
		__m256i pb = _mm256_loadu_si256( (const __m256i*)accu_b );
		__m256i pc = _mm256_add_epi8( pb , _mm256_sub_epi8(mask_31,pa) );
		__m256i r1 = _mm256_sub_epi8( pc , _mm256_cmpgt_epi8(pc,mask_30)&mask_31 );
		_mm256_storeu_si256( (__m256i*) accu_b , r1 );
		a += 32;
		accu_b += 32;
		n -= 32;

	}
	if( 0 == n ) return;

	uint8_t temp[32] __attribute__((aligned(32))) = {0};

	for(unsigned i=0;i<n;i++) temp[i] = a[i];
	__m256i pa = _mm256_load_si256( (const __m256i*)temp );
	for(unsigned i=0;i<n;i++) temp[i] = accu_b[i];
	__m256i pb = _mm256_load_si256( (const __m256i*)temp );
	__m256i pc = _mm256_add_epi8( pb , _mm256_sub_epi8(mask_31,pa) );
	__m256i r1 = _mm256_sub_epi8( pc , _mm256_cmpgt_epi8(pc,mask_30)&mask_31 );
	_mm256_store_si256( (__m256i*) temp , r1 );

	for(unsigned i=0;i<n;i++) accu_b[i] = temp[i];
}


static inline
__m256i _gf31v_mul_u8_avx2( __m256i a , uint16_t b ){
	__m256i zero = _mm256_setzero_si256();
	__m256i a0 = _mm256_unpacklo_epi8( a , zero );
	__m256i a1 = _mm256_unpackhi_epi8( a , zero );
	__m256i bb = _mm256_set1_epi16( b );

	a0 = _mm256_mullo_epi16( a0 , bb );
	a1 = _mm256_mullo_epi16( a1 , bb );

	a0 = _gf31v_reduce_u16_avx2( a0 );
	a1 = _gf31v_reduce_u16_avx2( a1 );

	__m256i r = _mm256_packs_epi16( a0 , a1 );
	return _gf31v_reduce_u8_avx2( r );
}




static inline
void gf31mat_prod_avx2( uint8_t * c , const uint8_t * mat , unsigned n_mat_h , unsigned n_mat_w , const uint8_t * b ) {
#ifdef _TWO_COL_MAT_
	assert( 256 >= n_mat_h );
	assert( 256 >= n_mat_w );
	assert( 0 == (n_mat_w&1) );

	__m256i r[16];
	unsigned n_ymm = (n_mat_h+15)>>4;
	for(unsigned i=0;i<n_ymm;i++) r[i] = _mm256_setzero_si256();

	const uint16_t * b_u16 = (const uint16_t *)b;

	for(unsigned i=0;i<n_mat_w/2;i++) {
		__m256i bi = _mm256_set1_epi16( b_u16[i] );

		for(unsigned j=0;j<n_ymm;j++) {
			__m256i tmp = _mm256_loadu_si256( (__m256i*)(mat+j*32) );
			r[j] = _mm256_add_epi16( r[j] , _mm256_maddubs_epi16( tmp , bi ) );
		}
		mat += n_mat_h*2;
	}


	uint8_t temp[256] __attribute__((aligned(32)));
	for(unsigned j=0;j<n_ymm;j++) {
		r[j] = _gf31v_reduce_u16_avx2( r[j] );
		r[j] = _gf31v_reduce_u16_avx2( r[j] );
	}
	unsigned n_ymm_2 = (n_ymm+1)/2;
	for(unsigned j=0;j<n_ymm_2;j++){
		r[j] = _mm256_packs_epi16( r[j*2] , r[j*2+1] );
		r[j] = _mm256_permute4x64_epi64( r[j] , 0xd8 ); //     3,1,2,0
		r[j] = _gf31v_reduce_u8_avx2( r[j] );
		_mm256_store_si256( (__m256i*)(&temp[32*j]) , r[j] );
	}

	for(unsigned i=0;i<n_mat_h;i++) c[i] = temp[i];
#else
	assert( 256 >= n_mat_h );
	assert( 256 >= n_mat_w );

	__m256i r[16];
	unsigned n_ymm = (n_mat_h+15)>>4;
	for(unsigned i=0;i<n_ymm;i++) r[i] = _mm256_setzero_si256();

	//__m256i tmp_col[16];
	__m256i zero = _mm256_setzero_si256();

	for(unsigned i=0;i<n_mat_w;i++) {
		__m256i bi = _mm256_set1_epi16( b[i] );

		for(unsigned j=0;j<n_ymm;j++) {
			__m256i tmp = _mm256_loadu_si256( (__m256i*)(mat+j*32) );
			__m256i t0 = _mm256_unpacklo_epi8( tmp , zero );
			__m256i t1 = _mm256_unpackhi_epi8( tmp , zero );
			r[j*2] = _mm256_add_epi16( r[j*2] , _mm256_mullo_epi16( t0 , bi ) );
			r[j*2+1] = _mm256_add_epi16( r[j*2+1] , _mm256_mullo_epi16( t1 , bi ) );
		}
		mat += n_mat_h;
	}
	uint8_t temp[256] __attribute__((aligned(32)));
	for(unsigned j=0;j<n_ymm;j++) {
		r[j*2] = _gf31v_reduce_u16_avx2( r[j*2] );
		r[j*2+1] = _gf31v_reduce_u16_avx2( r[j*2+1] );
		r[j*2] = _gf31v_reduce_u16_avx2( r[j*2] );
		r[j*2+1] = _gf31v_reduce_u16_avx2( r[j*2+1] );

		r[j*2] = _mm256_packs_epi16( r[j*2] , r[j*2+1] );
		r[j*2] = _gf31v_reduce_u8_avx2( r[j*2] );
		_mm256_store_si256( (__m256i*)(&temp[32*j]) , r[j*2] );
	}

	for(unsigned i=0;i<n_mat_h;i++) c[i] = temp[i];
#endif
}






static inline
unsigned _gf31mat_gauss_elim_avx2_core( uint16_t * mat , unsigned h , unsigned w )
{
	assert( 400 >= w );
	assert( 0 == (w&15) );
	__m256i ai_ymm[25];

	unsigned char r8 = 1;
	unsigned n_ymm = w>>4;

	for(unsigned i=0;i<h;i++) {
		uint16_t * ai = mat + w*i;
		unsigned st_ymm = i>>4;
		for(unsigned j=i+1;j<h;j++) {
			uint16_t * aj = mat + w*j;
			short mm = gf31_is_nonzero(ai[i])^gf31_is_nonzero(aj[i]);
			__m256i mask = _mm256_set1_epi16( 0-mm );

			for(unsigned k=st_ymm;k<n_ymm;k++) {
				__m256i ai_k = _mm256_add_epi16( _mm256_load_si256( (__m256i*)(ai+k*16) ) , _mm256_load_si256( (__m256i*)(aj+k*16) )&mask );
				_mm256_store_si256( (__m256i*)(ai+k*16) , ai_k );
			}
		}
		r8 &= gf31_is_nonzero(ai[i]);
		uint8_t pivot = ai[i];
		//uint16_t inv_p = gf31_inv( pivot ); /// XXX:
		uint16_t inv_p = gf31_inv_sse( pivot ); /// XXX:

		__m256i mul_p = _mm256_set1_epi16( inv_p );
		for(unsigned k=st_ymm;k<n_ymm;k++) {
			ai_ymm[k] = _mm256_load_si256( (__m256i*)(ai+k*16) );
			ai_ymm[k] = _mm256_mullo_epi16( mul_p , ai_ymm[k] );
			ai_ymm[k] = _gf31v_reduce_u16_avx2( ai_ymm[k] );
			ai_ymm[k] = _gf31v_reduce_u8_avx2( ai_ymm[k] );
			_mm256_store_si256( (__m256i*)(ai+k*16) , ai_ymm[k] );
		}

		__m256i mask_62 = _mm256_set1_epi16(62);
		for(unsigned j=0;j<h;j++) {
			if(i==j) continue;
			uint16_t * aj = mat + w*j;
#if 1
			__m256i aj_i = _mm256_set1_epi16( aj[i] );

			for(unsigned k=st_ymm;k<n_ymm;k++) {
				__m256i aixaj_i = _mm256_mullo_epi16( ai_ymm[k] , aj_i );
				__m256i tmp = _gf31v_reduce_u16_avx2( aixaj_i );
				tmp = _gf31v_reduce_u16_avx2( tmp );

				__m256i aj_ymm = _mm256_add_epi16( mask_62 , _mm256_load_si256( (__m256i*)(aj+k*16) ) );

				tmp = _mm256_sub_epi16( aj_ymm , tmp );
				tmp = _gf31v_reduce_u16_avx2( tmp );

				aj_ymm = _gf31v_reduce_u8_avx2( tmp );
				_mm256_store_si256( (__m256i*)(aj+k*16) , aj_ymm );
			}
#else
			uint16_t aji = aj[i];
			for(unsigned k=0;k<w;k++) {
				aj[k] = aj[k]+31- ((ai[k]*aji)%31);
				aj[k] %= 31;
			}
#endif
		}
	}
	return r8;
}

static inline
unsigned _gf31mat_gauss_elim_avx2( uint8_t * mat , unsigned h , unsigned w )
{
	assert( 200 >= h );
	assert( 400 >= w );
	uint16_t mat_16[200*400] __attribute__((aligned(32)));

	unsigned w_16 = ((w+15)>>4)<<4;
	for(unsigned i=0;i<h;i++) {
		gf31v_u8_to_u16( (uint8_t*)(mat_16+i*w_16) , mat + i*w , w );
	}

	unsigned r = _gf31mat_gauss_elim_avx2_core( mat_16 , h , w_16 );
	for(unsigned i=0;i<h;i++) {
		for(unsigned j=0;j<w;j++) mat[i*w+j] = mat_16[i*w_16+j];
	}
	return r;
}

#ifdef  __cplusplus
}
#endif



#endif

