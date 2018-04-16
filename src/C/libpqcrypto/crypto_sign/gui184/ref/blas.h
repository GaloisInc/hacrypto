#ifndef _BLAS_H_
#define _BLAS_H_

#include <stdint.h>
#include <stdio.h>
//#include <openssl/rand.h>
#include "prng_utils.h"

#include "gf16.h"

#include "blas_config.h"


#ifdef  __cplusplus
extern  "C" {
#endif



#define gf16v_mul_scalar  _gf16v_mul_scalar
#define gf16v_madd        _gf16v_madd
#define gf16mat_prod      _gf16mat_prod
#define gf16v_dot         _gf16v_dot

#define gf256v_add        _gf256v_add
#define gf256v_mul_scalar  _gf256v_mul_scalar
#define gf256v_madd        _gf256v_madd
#define gf256v_m0x10_add  _gf256v_m0x10_add
#define gf256v_m0x4_add  _gf256v_m0x4_add
#define gf256mat_prod      _gf256mat_prod




extern const unsigned char __zero_32[32];


static inline
void gf256v_fdump(FILE * fp, const uint8_t *v, unsigned _num_byte) {
	fprintf(fp,"[%2d][",_num_byte);
	for(unsigned i=0;i<_num_byte;i++) { fprintf(fp,"0x%02x,",v[i]); if(7==(i%8)) fprintf(fp," ");}
	fprintf(fp,"]");
}

static inline
void _gf256v_add( uint8_t * accu_b, const uint8_t * a , unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) accu_b[i]^=a[i];
}

static inline
void gf256v_set_zero( uint8_t * b, unsigned _num_byte ) { gf256v_add( b , b , _num_byte ); }

static inline
unsigned gf256v_is_zero( const uint8_t * a, unsigned _num_byte ) {
	unsigned char r = 0;
	for(unsigned i=0;i<_num_byte;i++) r |= a[i];
	return (0==r);
}

static inline
void _gf16v_mul_scalar( uint8_t * a, uint8_t gf16_b , unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) a[i] = gf256_mul_gf16( a[i] , gf16_b );
}

static inline
void _gf16v_madd( uint8_t * accu_c, const uint8_t * a , uint8_t gf16_b, unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) accu_c[i] ^= gf256_mul_gf16( a[i] , gf16_b );
}

static inline
void _gf256v_mul_scalar( uint8_t *a, uint8_t b, unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) a[i] = gf256_mul( a[i] , b );
}

static inline
void _gf256v_madd( uint8_t * accu_c, const uint8_t * a , uint8_t gf256_b, unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) accu_c[i] ^= gf256_mul( a[i] , gf256_b );
}

static inline
void _gf256v_m0x10_add( uint8_t * accu_c, const uint8_t * a , unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) accu_c[i] ^= gf256_mul_0x10( a[i] );
}

static inline
void _gf256v_m0x4_add( uint8_t * accu_c, const uint8_t * a , unsigned _num_byte ) {
	for(unsigned i=0;i<_num_byte;i++) accu_c[i] ^= gf256_mul_0x4( a[i] );
}


static inline
void gf256v_rand( uint8_t * a , unsigned _num_byte ) {
//	RAND_bytes( a , _num_byte );
	prng_bytes( a , _num_byte );
}




static inline
void gf256v_polymul( uint8_t * c, const uint8_t * a , const uint8_t * b , unsigned _num ) {
	for(unsigned i=0;i<_num*2-1;i++) c[i] = 0;
	for(unsigned i=0;i<_num;i++) _gf256v_madd( c+i , a , b[i] , _num );
}


static inline
void _gf256mat_prod( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * b ) {
	gf256v_set_zero(c,n_A_vec_byte);
	for(unsigned i=0;i<n_A_width;i++) {
		gf256v_madd( c , matA , b[i] , n_A_vec_byte );
		matA += n_A_vec_byte;
	}
}

static inline
void gf256mat_mul( uint8_t * c , const uint8_t * a , const uint8_t * b , unsigned len_vec ) {
	unsigned n_vec_byte = len_vec;
	for(unsigned k=0;k<len_vec;k++){
		gf256v_set_zero( c , n_vec_byte );
		const uint8_t * bk = b + n_vec_byte * k;
		for(unsigned i=0;i<len_vec;i++) {
			gf256v_madd( c , a + n_vec_byte * i , bk[i] , n_vec_byte  );
		}
		c += n_vec_byte;
	}
}



///////////////////////  GF(2) ////////////////////////////////



static inline
unsigned char gf2v_get_ele( const uint8_t * a , unsigned i ) {
	unsigned char r = a[i>>3];
	r = r>>(i&7);
	return r&1;
}

static inline
unsigned char gf2v_set_ele( uint8_t * a , unsigned i , uint8_t v ) {
	unsigned char m = (1<<(i&7));
	a[i>>3] &= (~m);
	m &= v<<(i&7);
	a[i>>3] |= m;
	return v;
}


#if 0
static inline
void gf2v_madd( uint8_t * c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	if( 0 != (_num_byte & 3) ) {
		printf("error\n");
		exit(-1);
	}
	uint32_t vv = ((uint32_t)0)-b;
	for(unsigned j=0;j<_num_byte;j+=4)
		((uint32_t*)(c+j))[0] ^= (vv)&((uint32_t*)(a+j))[0];
}
#else
static inline
void gf2v_madd_64b( uint8_t * c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	uint64_t vv = ((uint64_t)0)-b;
	for(unsigned j=0;j<_num_byte;j+=8)
		((uint64_t*)(c+j))[0] ^= (vv)&((uint64_t*)(a+j))[0];
}
static inline
void gf2v_madd_32b( uint8_t * c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	uint32_t vv = ((uint32_t)0)-b;
	for(unsigned j=0;j<_num_byte;j+=4)
		((uint32_t*)(c+j))[0] ^= (vv)&((uint32_t*)(a+j))[0];
}
static inline
void gf2v_madd_16b( uint8_t * c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	uint16_t vv = ((uint16_t)0)-b;
	for(unsigned j=0;j<_num_byte;j+=2)
		((uint16_t*)(c+j))[0] ^= (vv)&((uint16_t*)(a+j))[0];
}
static inline
void gf2v_madd( uint8_t * c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	uint8_t vv = ((uint8_t)0)-b;
	for(unsigned j=0;j<_num_byte;j++) c[j] ^= a[j] & vv;
}
#endif

static inline
void gf2mat_prod( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * b ) {
	gf256v_set_zero(c,n_A_vec_byte);
	for(unsigned i=0;i<n_A_width;i++) {
		gf2v_madd( c , matA , gf2v_get_ele(b,i) , n_A_vec_byte );
		matA += n_A_vec_byte;
	}
}


static inline
unsigned gf2mat_gauss_elim( uint8_t * a , uint8_t * b , unsigned W )
{
	unsigned n_vec_byte = (W+7)/8;
	uint8_t succ = 1;
	for(unsigned i=0;i<W;i++) {
		uint8_t * ai = a + n_vec_byte*i;
		uint8_t * bi = b + n_vec_byte*i;

		for(unsigned j=i+1;j<W;j++) {
			uint8_t piv = gf2v_get_ele(ai,i);
			uint8_t * aj = a + n_vec_byte*j;
			uint8_t * bj = b + n_vec_byte*j;
			uint8_t m = (~piv)&1;
			gf2v_madd( ai , aj , m , n_vec_byte );
			gf2v_madd( bi , bj , m , n_vec_byte );
		}
		succ &= gf2v_get_ele( ai , i );
		for(unsigned j=0;j<W;j++) {
			if(i==j) continue;
			uint8_t * aj = a + n_vec_byte*j;
			uint8_t * bj = b + n_vec_byte*j;

			uint8_t e = gf2v_get_ele(aj,i);
			gf2v_madd( aj , ai , e , n_vec_byte );
			gf2v_madd( bj , bi , e , n_vec_byte );
		}
	}
	return succ;
}

static inline
unsigned gf2mat_rand_inv( uint8_t * a , uint8_t * b , unsigned H )
{
	unsigned n_vec_byte = (H+7)/8;
	uint8_t * aa = (uint8_t *)malloc( n_vec_byte*H );
	unsigned k;
	for(k=0;k<100;k++){
		gf256v_set_zero( b , n_vec_byte*H );
		for(unsigned i=0;i<H;i++){
			gf256v_rand( a + i*n_vec_byte, n_vec_byte );
			gf2v_set_ele( b + n_vec_byte * i , i , 1 );
		}
		gf256v_set_zero( aa , n_vec_byte*H );
		gf256v_add( aa , a , n_vec_byte*H );
		if( gf2mat_gauss_elim(aa,b,H) ) break;
	}
	free( aa );
	return (100!=k);
}






#ifdef  __cplusplus
}
#endif



#endif

