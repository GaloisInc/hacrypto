
#ifndef _MPKC_H_
#define _MPKC_H_




#define IDX_XSQ(i,n_var) (((2*(n_var)+1-i)*(i)/2)+n_var)

/// xi <= xj
#define IDX_QTERMS_REVLEX(xi,xj) ((xj)*(xj+1)/2 + (xi))



#ifdef _BLAS_AVX2_

#include "mpkc_avx2.h"

#define mpkc_pub_map_gf16       mpkc_pub_map_gf16_avx2
#define mpkc_pub_map_gf16_n_m   mpkc_pub_map_gf16_n_m_avx2

#else

#define mpkc_pub_map_gf16       _mpkc_pub_map_gf16
#define mpkc_pub_map_gf16_n_m   _mpkc_pub_map_gf16_n_m

#endif





#ifdef  __cplusplus
extern  "C" {
#endif




void _mpkc_pub_map_gf16( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w );

void _mpkc_pub_map_gf16_n_m( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w , unsigned n, unsigned m );

void mpkc_interpolate_gf16( uint8_t * poly , void (*quad_poly)(void *,const void *,const void *) , const void * key );


#ifdef  __cplusplus
}
#endif


#endif
