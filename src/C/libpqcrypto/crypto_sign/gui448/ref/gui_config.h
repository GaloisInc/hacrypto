#ifndef _GUI_CONFIG_H_
#define _GUI_CONFIG_H_


//#define _GUI_2_240_D9_V16_A16
//#define _GUI_2_184_D33_V16_A16_K2
//#define _GUI_2_312_D129_V20_A24_K2
#define _GUI_2_448_D513_V28_A32_K2


#if defined _GUI_2_240_D9_V16_A16

#define _GF 2
#define _EXT 240
#define _A 16
#define _V 16
#define _K 3

#define GUI_C_DEG 9
#define _HASH_LEN (32)

#elif defined _GUI_2_184_D33_V16_A16_K2

#define _GF 2
#define _EXT 184
#define _A 16
#define _V 16
#define _K 2

#define GUI_C_DEG 33
#define _HASH_LEN (32)

#elif defined _GUI_2_312_D129_V20_A24_K2

#define _GF 2
#define _EXT 312
#define _A 24
#define _V 20
#define _K 2

#define GUI_C_DEG 129
#define _HASH_LEN (48)

#elif defined _GUI_2_448_D513_V28_A32_K2

#define _GF 2
#define _EXT 448
#define _A 32
#define _V 28
#define _K 2

#define GUI_C_DEG 513
#define _HASH_LEN (64)

#else

error here.

#endif



#if 9 == GUI_C_DEG
#define GUI_BETA_TERMS (4)
#define GUI_C_TERMS (1+GUI_BETA_TERMS+1+2+1)

#elif 17 == GUI_C_DEG
#define GUI_BETA_TERMS (5)
#define GUI_C_TERMS (1+GUI_BETA_TERMS+1+2+3+1)

#elif 33 == GUI_C_DEG
#define GUI_BETA_TERMS (6)
#define GUI_C_TERMS (1+GUI_BETA_TERMS+1+2+3+4+1)

#elif 129 == GUI_C_DEG
#define GUI_BETA_TERMS (8)
#define GUI_C_TERMS (1+GUI_BETA_TERMS+1+2+3+4+5+6+1)

#elif 513 == GUI_C_DEG
#define GUI_BETA_TERMS (10)
#define GUI_C_TERMS (1+GUI_BETA_TERMS+1+2+3+4+5+6+7+8+1)

#else
error in defining GUI_C_DEG.
#endif


#define GUI_ALPHA_TERMS (GUI_C_TERMS-2)
#define GUI_GAMMA_TERMS ((_V*(_V+1))/2)

#define GUI_BGF_SIZE (_EXT/8)



#define STR1(x) #x
#define THE_NAME(gf,ext,d,v,a,k) "GUI(" STR1(gf) "^" STR1(ext) ",D" STR1(d) ",V" STR1(v) ",A" STR1(a) ",K" STR1(k) ")"

#define _S_NAME THE_NAME(_GF,_EXT,GUI_C_DEG,_V,_A,_K)




#define _PUB_N  (_EXT+_V)
#define _PUB_M  (_EXT-_A)
#define _PUB_N_BYTE ((_PUB_N+7)/8)
#define _PUB_M_BYTE ((_PUB_M+7)/8)

#define _SEC_N _PUB_N
#define _SEC_M _EXT
#define _SEC_M_BYTE (_EXT/8)


#define _MINUS_BYTE (_SEC_M_BYTE-_PUB_M_BYTE)
#define _VINEGAR_BYTE (_PUB_N_BYTE-_SEC_M_BYTE)

#define _TAIL (_PUB_N-_PUB_M)
#define _TAIL_BYTE ((_TAIL+7)/8)


#define _SIGNATURE (_PUB_M+(_V+_A)*(_K))
#define _SIGNATURE_BYTE ((_SIGNATURE+7)/8)


//#define TERMS_QUAD_POLY(N) (((N)*(N+1)/2)+N)
#define TERMS_QUAD_POLY_GF2(N) (((N)*(N-1)/2)+N)


#define _PUB_KEY_LEN ((TERMS_QUAD_POLY_GF2(_PUB_N)+1)*(_PUB_M_BYTE))


#define _SALT_BYTE 16

#define _SALT_PUB_KEY_LEN (_PUB_KEY_LEN + 1)

#define _SALT_SIGNATURE_BYTE (_SIGNATURE_BYTE + _SALT_BYTE )

#endif
