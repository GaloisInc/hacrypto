
#ifndef _GUI_SIG_H_
#define _GUI_SIG_H_

#include "gui_config.h"

#include "gui.h"


#ifdef  __cplusplus
extern  "C" {
#endif

/// algorithm 2
unsigned gui_sign( uint8_t * signature , const uint8_t * sec_key , const uint8_t * digest );

/// algorithm 4
unsigned gui_verify( const uint8_t * pub_key , const uint8_t * signature , const uint8_t * digest );


/// algorithm 6
unsigned gui_sign_salt( uint8_t * signature , const uint8_t * sec_key , const uint8_t * digest );

/// algorithm 8
unsigned gui_verify_salt( const uint8_t * pub_key , const uint8_t * signature , const uint8_t * digest );





#ifdef  __cplusplus
}
#endif


#endif
