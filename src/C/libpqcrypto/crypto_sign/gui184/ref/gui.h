
#ifndef _GUI_H_
#define _GUI_H_


#include "gui_config.h"

#include "blas.h"


//#define _DEBUG_MPKC_


#ifdef  __cplusplus
extern  "C" {
#endif

#define KEYNAME(gf,ext,v,a) gui_##gf_##ext_##v_##a

#define BGF_SIZE GUI_BGF_SIZE
#define C_DEG    GUI_C_DEG
#define C_TERMS  GUI_C_TERMS


struct gui_cpoly {
	uint8_t alpha[GUI_BGF_SIZE*GUI_ALPHA_TERMS];
	uint8_t beta[GUI_BETA_TERMS][_V*GUI_BGF_SIZE];
	uint8_t gamma[GUI_GAMMA_TERMS][BGF_SIZE];
};

typedef struct gui_cpoly cpoly_t;

struct KEYNAME(_GF,_EXT,_V,_A) {
	uint8_t mat_t[_PUB_N * _PUB_N_BYTE];
	uint8_t vec_t[_PUB_N_BYTE];
	uint8_t mat_s[_SEC_M * _SEC_M_BYTE];
	uint8_t vec_s[_SEC_M_BYTE];

	cpoly_t cpoly;
};

typedef struct KEYNAME(_GF,_EXT,_V,_A) gui_key;


#define _SEC_KEY_LEN (sizeof(gui_key))

#define _SALT_SEC_KEY_LEN (_SEC_KEY_LEN+1)


/// algorithm 3
unsigned gui_secmap( uint8_t * w , const gui_key * sk , const uint8_t * z );

/// algorithm 7
unsigned InvHFEv_( uint8_t * z , const gui_key * sk , const uint8_t * w , const uint8_t * minus , const uint8_t * vinegar );


/// algorithm 1.
void gui_genkey( uint8_t * pk , gui_key * sk );


#define gui_pubmap mpkc_pub_map_gf2


#define NDEBUG

#define _DEBUG_GUI_

#ifdef _DEBUG_GUI_

#include "mpkc.h"


#define mpkc_interpolate mpkc_interpolate_gf2


void gui_central_map( uint8_t * r , const gui_key * key , const uint8_t * a );

/// algorithm 3
unsigned gui_ivs_central_map( uint8_t * r , const gui_key * key , const uint8_t * a , const uint8_t * vinegar );

void gui_pubmap_seckey( uint8_t * z , const gui_key * sk , const uint8_t * w );

void gui_genkey_debug( gui_key * pk , gui_key * sk );

#endif



#ifdef  __cplusplus
}
#endif


#endif
