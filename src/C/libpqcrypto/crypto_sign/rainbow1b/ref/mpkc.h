
#ifndef _MPKC_H_
#define _MPKC_H_



#include "blas.h"

#include "string.h"

#include "rainbow_config.h"



#define IDX_XSQ(i,n_var) (((2*(n_var)+1-i)*(i)/2)+n_var)

/// xi <= xj
#define IDX_QTERMS_REVLEX(xi,xj) ((xj)*(xj+1)/2 + (xi))



#define mpkc_pub_map_gf31 mpkc_pub_map_gf31_ref
#define mpkc_pub_map_gf31_n_m mpkc_pub_map_gf31_n_m_ref




#ifdef  __cplusplus
extern  "C" {
#endif


static inline
void to_maddusb_format_mq( uint8_t * z , const uint8_t * x , unsigned _n, unsigned m )
{
	assert( m <= 128 );
	unsigned n = (_n+1)*(_n+2)/2;
	uint8_t temp[256];
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
void maddusb_to_normal_mq( uint8_t * z , const uint8_t * x , unsigned _n, unsigned m )
{
	assert( m <= 128 );
	unsigned n = (_n+1)*(_n+2)/2;
	uint8_t temp[256];
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

#ifdef _TWO_COL_MAT_

static inline
void _generate_quadratic_terms_revlex_gf31_n( uint8_t * r , const uint8_t * a , unsigned n )
{
	for(unsigned i=0;i<n;i++) {
		memcpy( r , a , i+1 );
		gf31v_mul_scalar( r , a[i] , i+1 );
		r += (i+1);
	}
}

static inline
void _mpkc_pub_map_gf31( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w )
{
	assert( 0 == (_PUB_N %2 ) );

	uint8_t r[_PUB_M_BYTE]  = {0};
	uint8_t tmp[_PUB_M_BYTE] ;

	const uint8_t * mat_linear = pk_mat;
	gf31mat_prod( tmp , mat_linear , _PUB_M_BYTE , _PUB_N , w );
	gf31v_add( r , tmp , _PUB_M_BYTE );

	const uint8_t * mat_quadratic = pk_mat + (_PUB_N)*(_PUB_M_BYTE);
	uint8_t quad_terms[TERMS_QUAD_POLY(_PUB_N)];
	_generate_quadratic_terms_revlex_gf31_n( quad_terms , w , _PUB_N );
	gf31mat_prod( tmp , mat_quadratic , _PUB_M_BYTE , TERMS_QUAD_POLY(_PUB_N)-_PUB_N-1 , quad_terms );
	gf31v_add( r , tmp , _PUB_M_BYTE );

	const uint8_t * vec_constant  = pk_mat + (TERMS_QUAD_POLY(_PUB_N)-1)*(_PUB_M_BYTE);
	gf31v_add( r , vec_constant , _PUB_M_BYTE );

	memcpy( z , r , _PUB_M_BYTE );
}
#else
static inline
void _mpkc_pub_map_gf31( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w )
{
	uint8_t r[_PUB_M_BYTE]  = {0};
	uint8_t tmp[_PUB_M_BYTE] ;
	const unsigned n_var = _PUB_N;

	const uint8_t * linear_mat = pk_mat;
	for(unsigned i=0;i<n_var;i++) {
		gf31v_madd( r , linear_mat , w[i] , _PUB_M_BYTE );
		linear_mat += _PUB_M_BYTE;
	}

	const uint8_t * quad_mat = pk_mat + (_PUB_M_BYTE)*(_PUB_N);
	for(unsigned i=0;i<n_var;i++) {
		memset( tmp , 0 , _PUB_M_BYTE );
		for(unsigned j=0;j<=i;j++) {
			gf31v_madd( tmp , quad_mat , w[j] , _PUB_M_BYTE );
			quad_mat += _PUB_M_BYTE;
		}
		gf31v_madd( r , tmp , w[i] , _PUB_M_BYTE );
	}
	gf31v_add( r , quad_mat , _PUB_M_BYTE );
	memcpy( z , r , _PUB_M_BYTE );
}
#endif

static inline
void mpkc_pub_map_gf31_ref( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w )
{
	_mpkc_pub_map_gf31( z , pk_mat , w );
}


#ifdef _TWO_COL_MAT_
static inline
void _mpkc_pub_map_gf31_n_m( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w , unsigned n, unsigned m)
{
	assert( 0 == (n %2 ) );
	assert( 128 >= m );
	assert( 140 >= n );

	uint8_t quad_terms[TERMS_QUAD_POLY(140)];
	uint8_t tmp[128] ;
	uint8_t *r = z;
	memset(r,0,m);

	const uint8_t * mat_linear = pk_mat;
	gf31mat_prod( tmp , mat_linear , m , n , w );
	gf31v_add( r , tmp , m );

	const uint8_t * mat_quadratic = pk_mat + (n)*(m);
	_generate_quadratic_terms_revlex_gf31_n( quad_terms , w , n );
	gf31mat_prod( tmp , mat_quadratic , m , TERMS_QUAD_POLY(n)-n-1 , quad_terms );
	gf31v_add( r , tmp , m );

	const uint8_t * vec_constant  = pk_mat + (TERMS_QUAD_POLY(n)-1)*(m);
	gf31v_add( r , vec_constant , m );
}
#else
static inline
void _mpkc_pub_map_gf31_n_m( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w , unsigned n, unsigned m)
{
	assert( m <= 128 );

	uint8_t tmp[128] ;
	uint8_t *r = z;
	memset(r,0,m);

	const uint8_t * linear_mat = pk_mat;
	for(unsigned i=0;i<n;i++) {
		gf31v_madd( r , linear_mat , w[i] , m );
		linear_mat += m;
	}

	const uint8_t * quad_mat = pk_mat + n*m;
	for(unsigned i=0;i<n;i++) {
		memset( tmp , 0 , m );
		for(unsigned j=0;j<=i;j++) {
			gf31v_madd( tmp , quad_mat , w[j] , m );
			quad_mat += m;
		}
		gf31v_madd( r , tmp , w[i] , m );
	}
	gf31v_add( r , quad_mat , m );
}
#endif

static inline
void mpkc_pub_map_gf31_n_m_ref( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w , unsigned n, unsigned m)
{
	_mpkc_pub_map_gf31_n_m( z , pk_mat , w , n , m );
}



static inline
void mpkc_interpolate_gf31( uint8_t * poly , void (*quad_poly)(void *,const void *,const void *) , const void * key )
{
	uint8_t tmp[_PUB_N_BYTE] = {0};
	uint8_t tmp_r0[_PUB_M_BYTE] = {0};
	uint8_t tmp_r1[_PUB_M_BYTE] = {0};
	uint8_t tmp_r2[_PUB_M_BYTE] = {0};
	const unsigned n_var = _PUB_N;

	uint8_t * const_terms = poly + (_PUB_KEY_LEN - _PUB_M_BYTE );
	gf31v_set_zero(tmp,_PUB_N_BYTE);
	quad_poly( const_terms , key , tmp );

	for(unsigned i=0;i<n_var;i++) {
		gf31v_set_zero(tmp,_PUB_N_BYTE);
		tmp[i] = 1;
		quad_poly( tmp_r0 , key , tmp ); /// v + v^2
		gf31v_sub( tmp_r0 , const_terms , _PUB_M_BYTE );
		tmp[i] = 30; /// 30 = -1
		quad_poly( tmp_r1 , key , tmp ); /// -v + v^2
		gf31v_sub( tmp_r1 , const_terms , _PUB_M_BYTE );
		//memcpy( tmp_r2 , tmp_r1 , _PUB_M_BYTE );

		gf31v_sub( tmp_r0 , tmp_r1 , _PUB_M_BYTE );    /// 2*v
		gf31v_mul_scalar( tmp_r0 , 16 , _PUB_M_BYTE ); /// 2*v * 16 = 32*v mod 31 = v
		gf31v_add( tmp_r1 , tmp_r0 , _PUB_M_BYTE);    ///  v^2
		memcpy( poly + _PUB_M_BYTE*i , tmp_r0 , _PUB_M_BYTE );
		memcpy( poly + _PUB_M_BYTE*(n_var+IDX_QTERMS_REVLEX(i,i)) , tmp_r1 , _PUB_M_BYTE );
	}

	for(unsigned i=0;i<n_var;i++) {
		unsigned base_idx = n_var+IDX_QTERMS_REVLEX(0,i);
		memcpy( tmp_r1 , poly + _PUB_M_BYTE*i , _PUB_M_BYTE );
		memcpy( tmp_r2 , poly + _PUB_M_BYTE*(n_var+IDX_QTERMS_REVLEX(i,i)) , _PUB_M_BYTE );

		for(unsigned j=0;j<i;j++) {
			gf31v_set_zero(tmp,_PUB_N_BYTE);
			tmp[i] = 1;
			tmp[j] = 1;

			quad_poly( tmp_r0 , key , tmp ); /// v1 + v1^2 + v2 + v2^2 + v1v2
			gf31v_sub( tmp_r0 , const_terms , _PUB_M_BYTE );

			gf31v_sub( tmp_r0 , tmp_r1 , _PUB_M_BYTE );
			gf31v_sub( tmp_r0 , tmp_r2 , _PUB_M_BYTE );
			gf31v_sub( tmp_r0 , poly+_PUB_M_BYTE*j , _PUB_M_BYTE );
			gf31v_sub( tmp_r0 , poly+_PUB_M_BYTE*(n_var+IDX_QTERMS_REVLEX(j,j)) , _PUB_M_BYTE );

			memcpy( poly + _PUB_M_BYTE*(base_idx+j), tmp_r0 , _PUB_M_BYTE );
		}
	}

	to_maddusb_format_mq( poly , poly , _PUB_N , _PUB_M );

}



#ifdef  __cplusplus
}
#endif


#endif
