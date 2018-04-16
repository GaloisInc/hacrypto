
#ifndef _MPKC_H_
#define _MPKC_H_



#include "blas.h"

#include "string.h"

#include "mpkc_config.h"


#ifndef TERMS_QUAD_POLY_GF2
#define TERMS_QUAD_POLY_GF2(N) (((N)*(N-1)/2)+N)
#endif


#ifdef  __cplusplus
extern  "C" {
#endif



#define IDX_XSQ(i,n_var) (((2*(n_var)+1-i)*(i)/2)+n_var)

/// xi <= xj
#define IDX_QTERMS_REVLEX(xi,xj) ((xj)*(xj+1)/2 + (xi))



/////////////////////  GF(2)  ////////////////////////////////////


static inline
void mpkc_pub_map_gf2( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w )
{
	uint8_t r[_PUB_M_BYTE]  = {0};

	const unsigned n_var = _PUB_N;
	uint8_t x[_PUB_N]  = {0};
	for(unsigned i=0;i<n_var;i++) x[i] = gf2v_get_ele(w,i);

	const uint8_t * linear_mat = pk_mat;
	for(unsigned i=0;i<n_var;i++) {
		if( x[i] ) gf256v_add( r , linear_mat , _PUB_M_BYTE );
		linear_mat += _PUB_M_BYTE;
	}

	const uint8_t * quad_mat = pk_mat + (_PUB_M_BYTE)*(_PUB_N);
	for(unsigned i=1;i<n_var;i++) {
		if( 0 == x[i] ) {
			quad_mat += _PUB_M_BYTE*i;
			continue;
		}
		for(unsigned j=0;j<i;j++) {
			if( x[j] ) gf256v_add( r , quad_mat , _PUB_M_BYTE );
			quad_mat += _PUB_M_BYTE;
		}
	}
	/// constant terms
	gf256v_add( r , quad_mat , _PUB_M_BYTE );
	memcpy( z , r , _PUB_M_BYTE );
}


static inline
void mpkc_interpolate_gf2( uint8_t * poly , void (*quad_poly)(void *,const void *,const void *) , const void * key )
{
	uint8_t tmp[_PUB_N_BYTE] = {0};
	const unsigned n_var = _PUB_N;

	/// constant terms
	uint8_t * constant_terms = poly + (TERMS_QUAD_POLY_GF2(_PUB_N)*_PUB_M_BYTE);
	quad_poly( constant_terms , key , tmp );

	for(unsigned i=0;i<n_var;i++) {
		gf256v_set_zero(tmp,_PUB_N_BYTE);
		gf2v_set_ele(tmp,i,1);
		quad_poly( poly + (_PUB_M_BYTE * i) , key , tmp ); /// v
		gf256v_add( poly + (_PUB_M_BYTE * i) , constant_terms , _PUB_M_BYTE );
	}

	uint8_t * q_poly = poly + _PUB_M_BYTE*n_var;
	for(unsigned i=1;i<n_var;i++) {
		for(unsigned j=0;j<i;j++) {
			gf256v_set_zero(tmp,_PUB_N_BYTE);
			gf2v_set_ele(tmp,i,1);
			gf2v_set_ele(tmp,j,1);
			quad_poly( q_poly  , key , tmp ); /// v1*v2 + v1 + v2 + c
			gf256v_add( q_poly , poly + (i*_PUB_M_BYTE) , _PUB_M_BYTE );
			gf256v_add( q_poly , poly + (j*_PUB_M_BYTE) , _PUB_M_BYTE );
			gf256v_add( q_poly , constant_terms , _PUB_M_BYTE );
			q_poly += _PUB_M_BYTE;
		}
	}
}




#ifdef  __cplusplus
}
#endif


#endif
