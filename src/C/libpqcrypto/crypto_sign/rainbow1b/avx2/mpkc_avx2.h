
#ifndef _MPKC_AVX2_H_
#define _MPKC_AVX2_H_



#include "blas.h"

#include "blas_avx2.h"


#ifdef  __cplusplus
extern  "C" {
#endif



static inline
unsigned generate_quadratic_terms( uint8_t * z , const uint8_t * x , unsigned n )
{
	assert( 224 >= n );

	uint8_t temp[224] __attribute__((aligned(32)));
	memcpy( temp , x , n );

	unsigned n_ymm = (n+31)>>5;
	__m256i xx[7];
	for(unsigned i=0;i<n_ymm;i++) xx[i] = _mm256_load_si256( (__m256i*)(temp+i*32) );

	unsigned r = 0;
	for(unsigned i=0;i<n;i++){
		unsigned n_reg = (i>>5)+1;
		for(unsigned j=0;j<n_reg;j++) {
			__m256i rr =  _gf31v_mul_u8_avx2( xx[j] , x[i] );
			_mm256_store_si256( (__m256i*)(temp+j*32) , rr );
		}
		memcpy( z , temp , i+1 );
		z += (i+1);
		r += (i+1);
	}
	return r;
}


static inline
void mpkc_pub_map_gf31_n_m_avx2( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w , unsigned n, unsigned m)
{
	assert( 128 >= m );
	assert( 0 == (n&1) ); // n is even

	__m256i r[8];
	unsigned n_ymm = (m+15)>>4;
	for(unsigned i=0;i<n_ymm;i++) r[i] = _mm256_setzero_si256();

	const uint8_t * linear_mat = pk_mat;
	const uint16_t * xi = (const uint16_t *)w;
	for(unsigned i=0;i<(n/2);i++) {
		__m256i _ymm_xi = _mm256_set1_epi16( xi[i] );
		for(unsigned j=0;j<n_ymm;j++) {
			__m256i eq = _mm256_loadu_si256( (__m256i*)(linear_mat+32*j) );
			r[j] = _mm256_add_epi16( r[j] , _mm256_maddubs_epi16( eq , _ymm_xi )  );

		}
		linear_mat += (m*2);
	}

	assert( 196 >= n );
	uint8_t xx[196*(196+1)/2 +32] __attribute__((aligned(32)));
	unsigned n_terms = generate_quadratic_terms( xx , w , n );

	const uint8_t * quad_mat = pk_mat + n*m;
	xi = (const uint16_t *) xx;
	for(unsigned i=0;i<(n_terms/2);i++) {
		__m256i _ymm_xi = _mm256_set1_epi16( xi[i] );
		for(unsigned j=0;j<n_ymm;j++) {
			__m256i eq = _mm256_loadu_si256( (__m256i*)(quad_mat+32*j) );
			r[j] = _mm256_add_epi16( r[j] , _mm256_maddubs_epi16( eq , _ymm_xi )  );

		}
		quad_mat += (m*2);
		if(0 == (i&0x1f) ) for(unsigned j=0;j<n_ymm;j++) r[j] = _gf31v_reduce_u16_avx2( r[j] ); // reduce here
	}

	for(unsigned j=0;j<n_ymm;j++) r[j] = _gf31v_reduce_u16_avx2( r[j] ); // reduce here
	for(unsigned j=0;j<n_ymm;j++) r[j] = _gf31v_reduce_u16_avx2( r[j] ); // reduce here

	uint8_t temp[256] __attribute__((aligned(32)));
	for(unsigned i=0;i<n_ymm;i++) _mm256_store_si256( (__m256i*)(temp+32*i) , r[i] );
	gf31v_u16_to_u8( z , temp , m );

	for(unsigned i=0;i<m;i++) z[i] += quad_mat[i];
	gf31v_reduce_u8_avx2( z , m );
}


static inline
void mpkc_pub_map_gf31_avx2( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w )
{
	mpkc_pub_map_gf31_n_m_avx2( z , pk_mat , w , _PUB_N , _PUB_M );
}


#ifdef  __cplusplus
}
#endif


#endif
