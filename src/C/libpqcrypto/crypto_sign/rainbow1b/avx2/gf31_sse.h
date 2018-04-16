#ifndef _GF31_SSE_H_
#define _GF31_SSE_H_

#include <stdint.h>

#include "gf31.h"

#include "emmintrin.h"
#include "tmmintrin.h"

#include "gf31_table.h"

#ifdef  __cplusplus
extern  "C" {
#endif

static inline unsigned char gf31_inv_sse( unsigned char a )
{
	unsigned char temp[32] __attribute__((aligned(32)));
	temp[0] = a;
	__m128i aa = _mm_load_si128( (__m128i*)temp );
	__m128i aa_16 = _mm_sub_epi8( aa , _mm_set1_epi8(16) );
	__m128i inv_16p = _mm_shuffle_epi8( _mm_load_si128( (__m128i*)gf31_inv_tab2 ) , aa_16 );

	__m128i aa_16m = _mm_andnot_si128(aa_16,_mm_cmpeq_epi16(aa,aa));
	__m128i inv_16m = _mm_shuffle_epi8( _mm_load_si128( (__m128i*)(gf31_inv_tab2+16) ) , aa_16m );

	_mm_store_si128( (__m128i*)temp , inv_16p );
	_mm_store_si128( (__m128i*)(temp+16) , inv_16m );

	return temp[0]+temp[16];
}


#ifdef  __cplusplus
}
#endif


#endif
