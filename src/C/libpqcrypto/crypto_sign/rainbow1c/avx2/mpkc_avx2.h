
#ifndef _MPKC_AVX2_H_
#define _MPKC_AVX2_H_



#include "blas_avx2.h"

#include "mpkc.h"





#ifdef  __cplusplus
extern  "C" {
#endif


static inline
void mpkc_pub_map_gf256_avx2( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w )
{
	uint8_t r[((_PUB_M_BYTE+31)/32)*32] __attribute__((aligned(32))) = {0};
	uint8_t tmp[((_PUB_M_BYTE+31)/32)*32] __attribute__((aligned(32)));
	const unsigned n_var = _PUB_N;

	unsigned align_len = ((_PUB_M_BYTE+31)/32)*32;
	const uint8_t * linear_mat = pk_mat;
	for(unsigned i=0;i<n_var;i++) {
		gf256v_madd( r , linear_mat , w[i] , align_len );
		linear_mat += _PUB_M_BYTE;
	}

	const uint8_t * quad_mat = pk_mat + (_PUB_M_BYTE)*(_PUB_N);
	for(unsigned i=0;i<n_var;i++) {
		memset( tmp , 0 , _PUB_M_BYTE );
		for(unsigned j=0;j<=i;j++) {
			gf256v_madd( tmp , quad_mat , w[j] , align_len );
			quad_mat += _PUB_M_BYTE;
		}
		gf256v_madd( r , tmp , w[i] , align_len );
	}
	gf256v_add( r , quad_mat , _PUB_M_BYTE );
	memcpy( z , r , _PUB_M_BYTE );
}

static inline
void mpkc_pub_map_gf256_n_m_avx2( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w , unsigned n, unsigned m)
{
	assert( 160 >= n );
	assert( 128 >= m );

	uint8_t tmp[160] __attribute__((aligned(32)));
	uint8_t tmp2[160] __attribute__((aligned(32)));
	uint8_t r[128] __attribute__((aligned(32))) = {0};

	uint8_t multab[160*32] __attribute__((aligned(32)));
	gf256v_generate_multab_sse( multab , w , n );

	const uint8_t * linear_mat = pk_mat;
	gf256mat_prod_multab_avx2( r , linear_mat , m , n , multab );

	const uint8_t * quad_mat = pk_mat + n*m;
	for(unsigned i=0;i<n;i++) {
		gf256mat_prod_multab_avx2( tmp , quad_mat , m , i+1 , multab );
		gf256mat_prod_multab_avx2( tmp2 , tmp , m , 1 , multab+i*32 );
		gf256v_add( r , tmp2 , m );
		quad_mat += (i+1)*m;
	}
	gf256v_add( r , quad_mat , m );

	memcpy( z , r , m );
}


static inline
void mq_gf256_multab_n_m_avx2( uint8_t * z , const uint8_t * pk_mat , const uint8_t * multab , unsigned n, unsigned m)
{
	assert( 144 >= n );
	assert( 144 >= m );

	uint8_t tmp[144] __attribute__((aligned(32)));
	uint8_t tmp2[144] __attribute__((aligned(32)));
	uint8_t r[144] __attribute__((aligned(32))) = {0};

	const uint8_t * linear_mat = pk_mat;
	gf256mat_prod_multab_avx2( r , linear_mat , m , n , multab );

	const uint8_t * quad_mat = pk_mat + n*m;
	for(unsigned i=0;i<n;i++) {
		gf256mat_prod_multab_avx2( tmp , quad_mat , m , i+1 , multab );
		gf256mat_prod_multab_avx2( tmp2 , tmp , m , 1 , multab+i*32 );
		gf256v_add( r , tmp2 , m );
		quad_mat += (i+1)*m;
	}
	gf256v_add( r , quad_mat , m );

	memcpy( z , r , m );
}




#ifdef  __cplusplus
}
#endif


#endif
