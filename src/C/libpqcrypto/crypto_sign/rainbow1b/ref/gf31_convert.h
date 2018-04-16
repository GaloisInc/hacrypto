#ifndef _GF31_CONVERT_H_
#define _GF31_CONVERT_H_

#include <stdio.h>
#include <stdlib.h>


#ifdef  __cplusplus
extern  "C" {
#endif

int gf31_sanity_check( const unsigned char * gf31v , unsigned n );


int gf31_quick_pack( unsigned char * pack_bitstring , const unsigned char * gf31v , unsigned n_gf31 );

int gf31_quick_unpack( unsigned char * gf31v , const unsigned char * pack_bitstring , unsigned n_gf31 );


int gf31_from_digest( unsigned char * gf31v , const unsigned char * digest , unsigned n_gf31 );


#ifdef  __cplusplus
}
#endif



#endif

