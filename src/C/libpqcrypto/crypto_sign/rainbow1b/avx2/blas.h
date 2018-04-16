#ifndef _BLAS_H_
#define _BLAS_H_

#include <stdint.h>
#include <stdio.h>
#include "prng_utils.h"


#include "gf31.h"

#include "blas_config.h"
#include <assert.h>


#ifdef _BLAS_AVX2_

#include "blas_avx2.h"

#define gf31mat_prod gf31mat_prod_avx2
#define gf31mat_gauss_elim _gf31mat_gauss_elim_avx2

#define gf31v_add gf31v_add_avx2
//#define gf31v_sub gf31v_sub_avx2
#define gf31v_sub _gf31v_sub


#else

#define gf31mat_prod _gf31mat_prod
#define gf31mat_gauss_elim _gf31mat_gauss_elim

#define gf31v_add _gf31v_add
#define gf31v_sub _gf31v_sub

#endif



#ifdef  __cplusplus
extern  "C" {
#endif



extern unsigned char __zero_32[32];

#ifdef _TWO_COL_MAT_
static inline
void to_maddusb_format( uint8_t * z , const uint8_t * x , unsigned n, unsigned m )
{
	assert( m <= 256 );
	uint8_t temp[512];
	while( n > 1 ) {
		for(unsigned i=0;i<m;i++) temp[i*2] = x[i];
		for(unsigned i=0;i<m;i++) temp[i*2+1] = x[m+i];
		for(unsigned i=0;i<m*2;i++) z[i] = temp[i];

		n -= 2;
		x += 2*m;
		z += 2*m;
	}
	if( 1 == n ) {
		for(unsigned i=0;i<m;i++) z[i] = x[i];
	}
}

static inline
void maddusb_to_normal( uint8_t * z , const uint8_t * x , unsigned n, unsigned m )
{
	assert( m <= 256 );
	uint8_t temp[512];
	while( n > 1 ) {
		for(unsigned i=0;i<m;i++) temp[i] = x[i*2];
		for(unsigned i=0;i<m;i++) temp[m+i] = x[i*2+1];
		for(unsigned i=0;i<m*2;i++) z[i] = temp[i];

		n -= 2;
		x += 2*m;
		z += 2*m;
	}
	if( 1 == n ) {
		for(unsigned i=0;i<m;i++) z[i] = x[i];
	}
}
#endif


static inline
void gf31v_rand( uint8_t * a , unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) {
		prng_bytes( a+i , 1 );
		/// Reject sampling
		while( 0 == (a[i]>>3) ) prng_bytes( a+i , 1 );
		a[i]%=31;
	}
}


static inline
void gf256v_fdump(FILE * fp, const uint8_t *v, unsigned _num_byte) {
	fprintf(fp,"[%2d][",_num_byte);
	for(unsigned i=0;i<_num_byte;i++) { fprintf(fp,"0x%02x,",v[i]); if(7==(i%8)) fprintf(fp," ");}
	fprintf(fp,"]");
}

static inline
void _gf31v_add( uint8_t * accu_b, const uint8_t * a , unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) accu_b[i] = gf31_add( accu_b[i] , a[i] );
}

static inline
void _gf31v_sub( uint8_t * accu_b, const uint8_t * a , unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) accu_b[i] = gf31_sub( accu_b[i] , a[i] );
}

static inline
void gf31v_set_zero( uint8_t * b, unsigned _num_byte ) { for(unsigned i=0;i<_num_byte;i++) b[i]=0; }

static inline
unsigned gf31v_is_zero( const uint8_t * a, unsigned _num_byte ) {
	unsigned char r = 0;
	for(unsigned i=0;i<_num_byte;i++) r |= a[i];
	return (0==r);
}

static inline
void gf31v_mul_scalar( uint8_t *a, uint8_t b, unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) a[i] = gf31_mul( a[i] , b );
}

static inline
void gf31v_madd( uint8_t * accu_c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) accu_c[i] = gf31_add( accu_c[i] , gf31_mul( a[i] , b ) );
}


static inline
void gf31v_msub( uint8_t * accu_c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) accu_c[i] = gf31_sub( accu_c[i] , gf31_mul( a[i] , b ) );
}


static inline
void gf256mat_fdump(FILE * fp, const uint8_t *v, unsigned n_vec_byte , unsigned n_vec ) {
	for(unsigned i=0;i<n_vec;i++) {
		fprintf(fp,"[%d]",i);
		gf256v_fdump(fp,v,n_vec_byte);
		fprintf(fp,"\n");
		v += n_vec_byte;
	}
}

#ifdef _TWO_COL_MAT_
static inline
void gf31v_madd_2col( uint8_t * accu_c, const uint8_t * a , uint8_t b1, uint8_t b2 , unsigned n ) {
	for(unsigned i=0;i<n;i++) {
		unsigned char c = gf31_add( gf31_mul( a[i*2] , b1 ) , gf31_mul( a[i*2+1] , b2 ) );
		accu_c[i] = gf31_add( accu_c[i] , c );
	}
}
#endif

static inline
void _gf31mat_prod( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * b ) {
#ifdef _TWO_COL_MAT_
	gf31v_set_zero(c,n_A_vec_byte);
	unsigned odd = n_A_width&1;
	n_A_width ^= odd;
	for(unsigned i=0;i<n_A_width;i+=2) {
		gf31v_madd_2col( c , matA , b[i] , b[i+1] , n_A_vec_byte );
		matA += 2*n_A_vec_byte;
	}
	if( 1 == odd ) gf31v_madd( c , matA , b[n_A_width] , n_A_vec_byte );
#else
	gf31v_set_zero(c,n_A_vec_byte);
	for(unsigned i=0;i<n_A_width;i++) {
		gf31v_madd( c , matA , b[i] , n_A_vec_byte );
		matA += n_A_vec_byte;
	}
#endif
}

static inline
void gf31mat_mul( uint8_t * c , const uint8_t * a , const uint8_t * b , unsigned len_vec ) {
	unsigned n_vec_byte = len_vec;
	for(unsigned k=0;k<len_vec;k++){
		gf31v_set_zero( c , n_vec_byte );
		const uint8_t * bk = b + n_vec_byte * k;
		for(unsigned i=0;i<len_vec;i++) {
			gf31v_madd( c , a + n_vec_byte * i , bk[i] , n_vec_byte  );
		}
		c += n_vec_byte;
	}
}


static inline
unsigned _gf31mat_gauss_elim( uint8_t * mat , unsigned h , unsigned w )
{
	unsigned char r8 = 1;
	for(unsigned i=0;i<h;i++) {
		uint8_t * ai = mat + w*i;
		for(unsigned j=i+1;j<h;j++) {
			uint8_t * aj = mat + w*j;
			gf31v_madd( ai , aj , gf31_is_nonzero(ai[i])^gf31_is_nonzero(aj[i]) , w );
		}
		r8 &= gf31_is_nonzero(ai[i]);
		uint8_t pivot = ai[i];
		pivot = gf31_inv( pivot );
		gf31v_mul_scalar( ai , pivot , w );
		for(unsigned j=0;j<h;j++) {
			if(i==j) continue;
			uint8_t * aj = mat + w*j;
			gf31v_msub( aj , ai , aj[i] , w );
		}
	}
	return r8;
}

static inline
void gf31mat_submat( uint8_t * mat2 , unsigned w2 , unsigned st , const uint8_t * mat , unsigned w , unsigned h )
{
	for(unsigned i=0;i<h;i++) {
		for(unsigned j=0;j<w2;j++) mat2[i*w2+j] = mat[i*w+st+j];
	}
}


static inline
unsigned gf31mat_rand_inv( uint8_t * a , uint8_t * b , unsigned H )
{
	uint8_t * aa = (uint8_t *)malloc( H*H*2 );
	unsigned k;
	for(k=0;k<100;k++){
		gf31v_set_zero( aa , H*H*2 );
		//memset( aa , 0 , H*H*2 );
		for(unsigned i=0;i<H;i++){
			uint8_t * ai = aa + i*2*H;
			gf31v_rand( ai , H );
			ai[H+i] = 1;
		}
		gf31mat_submat( a , H , 0 , aa , 2*H , H );
		unsigned r = gf31mat_gauss_elim( aa , H , 2*H );
		if( r ) {
			gf31mat_submat( b , H , H , aa , 2*H , H );
			break;
		}
	}
	free( aa );
	return (100!=k);
}






#ifdef  __cplusplus
}
#endif



#endif

