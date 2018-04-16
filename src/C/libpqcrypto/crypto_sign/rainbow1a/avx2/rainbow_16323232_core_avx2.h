
#ifndef _RAINBOW_16323232_CORE_H_
#define _RAINBOW_16323232_CORE_H_

#include "rainbow_16.h"



#ifdef  __cplusplus
extern  "C" {
#endif

unsigned rainbow_ivs_central_map_16323232_avx2( uint8_t * r , const rainbow_ckey * k , const uint8_t * a );


int rainbow_sign_16323232_avx2( uint8_t * signature , const uint8_t * _sk , const uint8_t * _digest );



#ifdef  __cplusplus
}
#endif

#endif
