
#ifndef _RAINBOW_H_
#define _RAINBOW_H_

#include "rainbow_config.h"

#include "blas.h"


//#define _DEBUG_MPKC_
#define _DEBUG_RAINBOW_

#ifdef  __cplusplus
extern  "C" {
#endif



struct _rainbow_ckey {
	uint8_t l1_o[_O1*_O1];
	uint8_t l1_vo[_O1][_V1*_O1];
	uint8_t l1_vv[TERMS_QUAD_POLY(_V1)*_O1];

	uint8_t l2_o[_O2*_O2];
	uint8_t l2_vo[_O2][_V2*_O2];
	uint8_t l2_vv[TERMS_QUAD_POLY(_V2)*_O2];
};

typedef struct _rainbow_ckey rainbow_ckey;

struct _rainbow_key {
	uint8_t mat_t[_SEC_N * _PUB_N_BYTE];
	uint8_t vec_t[_PUB_N_BYTE];
	uint8_t mat_s[_PUB_M * _PUB_M_BYTE];
	uint8_t vec_s[_PUB_M_BYTE];

	rainbow_ckey ckey;
};

typedef struct _rainbow_key rainbow_key;


#define _SEC_KEY_LEN       (sizeof(rainbow_key))

#define _SEC_KEY_LEN_PACK  (_GF31_PACK_SIZE(_SEC_KEY_LEN))

#define _SALT_SEC_KEY_LEN  (_SEC_KEY_LEN_PACK + 1 )




void rainbow_genkey( uint8_t * pk , rainbow_key * sk );


unsigned rainbow_secmap( uint8_t * w , const rainbow_key * sk , const uint8_t * z );



#include "mpkc.h"
#define rainbow_pubmap mpkc_pub_map_gf31



#ifdef _DEBUG_RAINBOW_

unsigned rainbow_ivs_central_map( uint8_t * r , const rainbow_ckey * k , const uint8_t * a );

void rainbow_central_map( uint8_t * r , const rainbow_ckey * k , const uint8_t * a );

void rainbow_pubmap_seckey( uint8_t * z , const rainbow_key * sk , const uint8_t * w );

void rainbow_genkey_debug( rainbow_key * pk , rainbow_key * sk );

#endif


/// algorithm 7
int rainbow_sign( uint8_t * signature , const rainbow_key * sk , const uint8_t * digest );

/// algorithm 8
int rainbow_verify( const uint8_t * digest , const uint8_t * signature , const uint8_t * pk );




#ifdef  __cplusplus
}
#endif


#endif
