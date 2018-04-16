#ifndef _PRNG_UTILS_H_
#define _PRNG_UTILS_H_

#include <stdio.h>
#include <stdlib.h>



#ifdef  __cplusplus
extern  "C" {
#endif


void prng_bytes( unsigned char * a , unsigned _num_byte );

void prng_dump_set( unsigned is_record );

unsigned prng_dump( unsigned char ** ptr_rnd_generated );



void userrand_bytes( unsigned char * a , unsigned _num_byte );

int userrand_source_file( const char * file_name );

unsigned userrand_dump_generated( unsigned char * buffer , unsigned size_buffer );



#ifdef  __cplusplus
}
#endif



#endif

