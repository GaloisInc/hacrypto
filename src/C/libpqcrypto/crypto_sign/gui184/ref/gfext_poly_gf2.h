
#ifndef _GFEXT_POLY_GF2_H_
#define _GFEXT_POLY_GF2_H_



#ifdef  __cplusplus
extern  "C" {
#endif


unsigned find_unique_root_sparse_poly( uint8_t * root , const uint8_t * sparse_poly , const unsigned * degree , unsigned n_sp_terms );


#define _DEBUG_GFEXT_POLY_

#ifdef _DEBUG_GFEXT_POLY_


void poly_eval( uint8_t *val , const uint8_t * poly , unsigned deg , const uint8_t * a );

void poly_fdump(FILE *fp, const uint8_t *poly, unsigned deg );

void poly_normalize( uint8_t * rp , const uint8_t * p , unsigned deg );

unsigned _get_deg1poly_gcd( uint8_t * gcd , const uint8_t * p1 , const uint8_t * p2 , unsigned deg );

#endif



#ifdef  __cplusplus
}
#endif


#endif





