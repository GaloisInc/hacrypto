#ifndef _BITMAT_PROD_SSE_H_
#define _BITMAT_PROD_SSE_H_

#include "stdint.h"

#include "emmintrin.h"
#include "tmmintrin.h"


#ifdef  __cplusplus
extern  "C" {
#endif


#define _ACCU_64_2_(inp64,len) do {\
	__m128i inp_run = _mm_set1_epi64x( inp64 ); \
	for(int i=len;i>0;i--) { \
		__m128i qq = _mm_cmpeq_epi8(mask_1,mask_1&_mm_shuffle_epi8(inp_run,zero)); \
		r0 ^= (qq & _mm_load_si128( (const __m128i *)idx) ); idx += 16; \
		r1 ^= (qq & _mm_load_si128( (const __m128i *)idx) ); idx += 16; \
		inp_run = _mm_srli_epi64(inp_run,1); \
	} \
} while(0)


#define _ACCU_64_3_(inp64,len) do {\
	__m128i inp_run = _mm_set1_epi64x( inp64 ); \
	for(int i=len;i>0;i--) { \
		__m128i qq = _mm_cmpeq_epi8(mask_1,mask_1&_mm_shuffle_epi8(inp_run,zero)); \
		r0 ^= (qq & _mm_load_si128( (const __m128i *)idx) ); idx += 16; \
		r1 ^= (qq & _mm_load_si128( (const __m128i *)idx) ); idx += 16; \
		r2 ^= (qq & _mm_load_si128( (const __m128i *)idx) ); idx += 16; \
		inp_run = _mm_srli_epi64(inp_run,1); \
	} \
} while(0)

#define _ACCU_64_4_(inp64,len) do {\
	__m128i inp_run = _mm_set1_epi64x( inp64 ); \
	for(int i=len;i>0;i--) { \
		__m128i qq = _mm_cmpeq_epi8(mask_1,mask_1&_mm_shuffle_epi8(inp_run,zero)); \
		r0 ^= (qq & _mm_load_si128( (const __m128i *)idx) ); idx += 16; \
		r1 ^= (qq & _mm_load_si128( (const __m128i *)idx) ); idx += 16; \
		r2 ^= (qq & _mm_load_si128( (const __m128i *)idx) ); idx += 16; \
		r3 ^= (qq & _mm_load_si128( (const __m128i *)idx) ); idx += 16; \
		inp_run = _mm_srli_epi64(inp_run,1); \
	} \
} while(0)



static inline
void bitmatrix_prod_2_sse( uint8_t * r , const uint64_t * mat , const uint8_t * a , unsigned len )
{
	__m128i zero = _mm_setzero_si128();
	__m128i mask_1 = _mm_set1_epi8(1);
	__m128i r0 = _mm_setzero_si128();
	__m128i r1 = _mm_setzero_si128();

	unsigned n_byte = (len+7)/8;

	const uint8_t * idx = (const uint8_t *)mat;
	uint64_t inp64;
	while( 64 <= len ) {
		len -= 64;
		inp64 = *(const uint64_t *)a;
		a += 8;
		_ACCU_64_2_(inp64,64);
	}
	if( len ) {
		unsigned rem_byte = (len+7)/8;
		for(int i=rem_byte-1;i>=0;i--) {
			inp64<<=8;
			inp64 |= a[i];
		}
		_ACCU_64_2_(inp64,len);
	}

	_mm_storeu_si128( (__m128i *) r , r0 );

	uint8_t _tmp[16] __attribute__((aligned(32))) = {0};
	_mm_store_si128( (__m128i *) _tmp , r1 );
	n_byte -= 16;
	for(unsigned i=0;i<(n_byte&0xf);i++) r[16+i] = _tmp[i];
}




static inline
void bitmatrix_prod_3_sse( uint8_t * r , const uint64_t * mat , const uint8_t * a , unsigned len )
{
	__m128i zero = _mm_setzero_si128();
	__m128i mask_1 = _mm_set1_epi8(1);
	__m128i r0 = _mm_setzero_si128();
	__m128i r1 = _mm_setzero_si128();
	__m128i r2 = _mm_setzero_si128();

	unsigned n_byte = (len+7)/8;

	const uint8_t * idx = (const uint8_t *)mat;
	uint64_t inp64;
	while( 64 <= len ) {
		len -= 64;
		inp64 = *(const uint64_t *)a;
		a += 8;
		_ACCU_64_3_(inp64,64);
	}
	if( len ) {
		unsigned rem_byte = (len+7)/8;
		for(int i=rem_byte-1;i>=0;i--) {
			inp64<<=8;
			inp64 |= a[i];
		}
		_ACCU_64_3_(inp64,len);
	}

	_mm_storeu_si128( (__m128i *) r , r0 );
	_mm_storeu_si128( (__m128i *) (r+16) , r1 );

	uint8_t _tmp[16] __attribute__((aligned(32))) = {0};
	_mm_store_si128( (__m128i *) _tmp , r2 );
	n_byte -= 32;
	for(unsigned i=0;i<(n_byte&0xf);i++) r[32+i] = _tmp[i];
}



static inline
void bitmatrix_prod_4_sse( uint8_t * r , const uint64_t * mat , const uint8_t * a , unsigned len )
{
	__m128i zero = _mm_setzero_si128();
	__m128i mask_1 = _mm_set1_epi8(1);
	__m128i r0 = _mm_setzero_si128();
	__m128i r1 = _mm_setzero_si128();
	__m128i r2 = _mm_setzero_si128();
	__m128i r3 = _mm_setzero_si128();

	unsigned n_byte = (len+7)/8;

	const uint8_t * idx = (const uint8_t *)mat;
	uint64_t inp64;
	while( 64 <= len ) {
		len -= 64;
		inp64 = *(const uint64_t *)a;
		a += 8;
		_ACCU_64_4_(inp64,64);
	}
	if( len ) {
		unsigned rem_byte = (len+7)/8;
		for(int i=rem_byte-1;i>=0;i--) {
			inp64<<=8;
			inp64 |= a[i];
		}
		_ACCU_64_4_(inp64,len);
	}

	_mm_storeu_si128( (__m128i *) r , r0 );
	_mm_storeu_si128( (__m128i *) (r+16) , r1 );
	_mm_storeu_si128( (__m128i *) (r+32) , r2 );

	uint8_t _tmp[16] __attribute__((aligned(32))) = {0};
	_mm_store_si128( (__m128i *) _tmp , r3 );
	n_byte -= 48;
	for(unsigned i=0;i<(n_byte&0xf);i++) r[48+i] = _tmp[i];
}




static inline
void bitmatrix_prod_sse( uint8_t * r , const uint64_t * mat , const uint8_t * a , unsigned len ){

	if( len <= 128 ) {
		exit(-1);
	} else if( len <= 256 ) {
		bitmatrix_prod_2_sse( r , mat , a , len );
	} else if( len <=384 ) {
		bitmatrix_prod_3_sse( r , mat , a , len );
	} else if( len <= 512 ) {
		bitmatrix_prod_4_sse( r , mat , a , len );
	} else {
		exit(-1);
	}
}




#ifdef  __cplusplus
}
#endif

#endif
