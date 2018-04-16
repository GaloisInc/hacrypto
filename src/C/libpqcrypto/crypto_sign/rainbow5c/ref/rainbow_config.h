#ifndef _RAINBOW_CONFIG_H_
#define _RAINBOW_CONFIG_H_


//#define _RAINBOW_256_40_20_20_
//#define _RAINBOW_256_68_36_36_
#define _RAINBOW_256_92_48_48_


#if defined _RAINBOW_256_40_20_20_
#define _V1 40
#define _O1 24
#define _O2 24
#define _HASH_LEN 32

#elif defined _RAINBOW_256_68_36_36_
#define _V1 68
#define _O1 36
#define _O2 36
#define _HASH_LEN 48

#elif defined _RAINBOW_256_92_48_48_
#define _V1 92
#define _O1 48
#define _O2 48
#define _HASH_LEN 64

#else
error
#endif


#define _GFSIZE 256

#define STR1(x) #x
#define THE_NAME(gf,v1,o1,o2) "RAINBOW(" STR1(gf) "," STR1(v1) "," STR1(o1) "," STR1(o2) ")"

#define _S_NAME THE_NAME(_GFSIZE,_V1,_O1,_O2)


#define _V2 ((_V1)+(_O1))

#define _RAINBOW_256


#ifdef _RAINBOW_256

#define _PUB_N  (_V1 + _O1 + _O2)
#define _PUB_M  (_O1 + _O2)
#define _SEC_N (_PUB_N)

#define _PUB_N_BYTE  _PUB_N
#define _PUB_M_BYTE  _PUB_M

#else

error

#endif


#define _SALT_BYTE 16

#define _SIGNATURE_BYTE (_PUB_N_BYTE + _SALT_BYTE)
//#define _SIGNATURE_BYTE (_PUB_N_BYTE )

#define TERMS_QUAD_POLY(N) (((N)*(N+1)/2)+N+1)

/// 1 for length of salt
#define _PUB_KEY_LEN ((TERMS_QUAD_POLY(_PUB_N)*(_PUB_M_BYTE)) + 1)

#endif
