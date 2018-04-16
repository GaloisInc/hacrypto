
#include "rainbow_config.h"

#include "blas.h"

#include "blas_avx2.h"

#include "mpkc.h"

#include "mpkc_avx2.h"

#include "string.h"



static
void mq_gf16_n96_m64_vartime_avx2( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w )
{
	uint8_t _x0[96] __attribute__((aligned(32)));
	__m128i mask16 = _mm_set1_epi8( 0xf );
	__m128i w0,w1;
	w0 = _mm_loadu_si128( (__m128i*) w );
	w1 = _mm_srli_epi16( w0 , 4 ) & mask16;
	w0 &= mask16;
	_mm_store_si128( (__m128i*) _x0 , _mm_unpacklo_epi8(w0,w1) );
	_mm_store_si128( (__m128i*) (_x0+16) , _mm_unpackhi_epi8(w0,w1) );
	w0 = _mm_loadu_si128( (__m128i*) (w+16) );
	w1 = _mm_srli_epi16( w0 , 4 ) & mask16;
	w0 &= mask16;
	_mm_store_si128( (__m128i*) (_x0+32) , _mm_unpacklo_epi8(w0,w1) );
	_mm_store_si128( (__m128i*) (_x0+48) , _mm_unpackhi_epi8(w0,w1) );
	w0 = _mm_loadu_si128( (__m128i*) (w+32) );
	w1 = _mm_srli_epi16( w0 , 4 ) & mask16;
	w0 &= mask16;
	_mm_store_si128( (__m128i*) (_x0+64) , _mm_unpacklo_epi8(w0,w1) );
	_mm_store_si128( (__m128i*) (_x0+80) , _mm_unpackhi_epi8(w0,w1) );

        __m256i mask = _mm256_load_si256( (__m256i*) __mask_low );

	__m256i r0 = _mm256_setzero_si256();
	__m256i r1 = _mm256_setzero_si256();
	for(unsigned i=0;i<96;i++) {
		unsigned b = _x0[i];
		__m256i ml = _mm256_load_si256( (__m256i*) (__gf16_mulx2 + 32*b) );

		__m256i inp = _mm256_load_si256( (__m256i*)pk_mat ); pk_mat += 32;
		r0 ^= _mm256_shuffle_epi8( ml , inp&mask );
		r1 ^= _mm256_shuffle_epi8( ml , _mm256_srli_epi16(inp,4)&mask );
	}

	for(unsigned i=0;i<96;i++) {
		if( 0 == _x0[i] ) {
			pk_mat += 32*(i+1);
			continue;
		}
		__m256i temp0 = _mm256_setzero_si256();
		__m256i temp1 = _mm256_setzero_si256();
		__m256i ml;
		for(unsigned j=0;j<=i;j++) {
			unsigned b = _x0[j];
			ml = _mm256_load_si256( (__m256i*) (__gf16_mulx2 + 32*b) );
			__m256i inp = _mm256_load_si256( (__m256i*)pk_mat ); pk_mat += 32;

			temp0 ^= _mm256_shuffle_epi8( ml , inp&mask );
			temp1 ^= _mm256_shuffle_epi8( ml , _mm256_srli_epi16(inp,4)&mask );
		}
		r0 ^= _mm256_shuffle_epi8( ml , temp0 );
		r1 ^= _mm256_shuffle_epi8( ml , temp1 );
	}
	__m256i rr = r0^_mm256_slli_epi16(r1,4)^ _mm256_load_si256( (__m256i*)pk_mat );
	_mm256_storeu_si256( (__m256i*)z , rr );
}


static
void mq_gf16_n96_m64_vartime_avx2_unalign( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w )
{
	uint8_t _x0[96] __attribute__((aligned(32)));
	__m128i mask16 = _mm_set1_epi8( 0xf );
	__m128i w0,w1;
	w0 = _mm_loadu_si128( (__m128i*) w );
	w1 = _mm_srli_epi16( w0 , 4 ) & mask16;
	w0 &= mask16;
	_mm_store_si128( (__m128i*) _x0 , _mm_unpacklo_epi8(w0,w1) );
	_mm_store_si128( (__m128i*) (_x0+16) , _mm_unpackhi_epi8(w0,w1) );
	w0 = _mm_loadu_si128( (__m128i*) (w+16) );
	w1 = _mm_srli_epi16( w0 , 4 ) & mask16;
	w0 &= mask16;
	_mm_store_si128( (__m128i*) (_x0+32) , _mm_unpacklo_epi8(w0,w1) );
	_mm_store_si128( (__m128i*) (_x0+48) , _mm_unpackhi_epi8(w0,w1) );
	w0 = _mm_loadu_si128( (__m128i*) (w+32) );
	w1 = _mm_srli_epi16( w0 , 4 ) & mask16;
	w0 &= mask16;
	_mm_store_si128( (__m128i*) (_x0+64) , _mm_unpacklo_epi8(w0,w1) );
	_mm_store_si128( (__m128i*) (_x0+80) , _mm_unpackhi_epi8(w0,w1) );

        __m256i mask = _mm256_load_si256( (__m256i*) __mask_low );

	__m256i r0 = _mm256_setzero_si256();
	__m256i r1 = _mm256_setzero_si256();
	for(unsigned i=0;i<96;i++) {
		unsigned b = _x0[i];
		__m256i ml = _mm256_load_si256( (__m256i*) (__gf16_mulx2 + 32*b) );

		__m256i inp = _mm256_loadu_si256( (__m256i*)pk_mat ); pk_mat += 32;
		r0 ^= _mm256_shuffle_epi8( ml , inp&mask );
		r1 ^= _mm256_shuffle_epi8( ml , _mm256_srli_epi16(inp,4)&mask );
	}

	for(unsigned i=0;i<96;i++) {
		if( 0 == _x0[i] ) {
			pk_mat += 32*(i+1);
			continue;
		}
		__m256i temp0 = _mm256_setzero_si256();
		__m256i temp1 = _mm256_setzero_si256();
		__m256i ml;
		for(unsigned j=0;j<=i;j++) {
			unsigned b = _x0[j];
			ml = _mm256_load_si256( (__m256i*) (__gf16_mulx2 + 32*b) );
			__m256i inp = _mm256_loadu_si256( (__m256i*)pk_mat ); pk_mat += 32;

			temp0 ^= _mm256_shuffle_epi8( ml , inp&mask );
			temp1 ^= _mm256_shuffle_epi8( ml , _mm256_srli_epi16(inp,4)&mask );
		}
		r0 ^= _mm256_shuffle_epi8( ml , temp0 );
		r1 ^= _mm256_shuffle_epi8( ml , temp1 );
	}
	__m256i rr = r0^_mm256_slli_epi16(r1,4)^ _mm256_loadu_si256( (__m256i*)pk_mat );
	_mm256_storeu_si256( (__m256i*)z , rr );
}





void mpkc_pub_map_gf16_avx2( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w )
{
	if( (96==_PUB_N) && (64==_PUB_M) ) {
		if( 0==(((uint64_t)pk_mat)&0x1f) ) mq_gf16_n96_m64_vartime_avx2(z,pk_mat,w);
		else mq_gf16_n96_m64_vartime_avx2_unalign(z,pk_mat,w);
		return;
	}

	uint8_t x[((_PUB_N+31)/32)*32] __attribute__((aligned(32)));
	uint8_t r[((_PUB_M_BYTE+31)/32)*32] __attribute__((aligned(32))) = {0};
	uint8_t tmp[((_PUB_M_BYTE+31)/32)*32] __attribute__((aligned(32)));
	const unsigned n_var = _PUB_N;

	const uint8_t * linear_mat = pk_mat;
	gf16mat_prod( r , linear_mat , _PUB_M_BYTE , _PUB_N , w );

	const uint8_t * quad_mat = pk_mat + (_PUB_M_BYTE)*(_PUB_N);
	gf16v_split( x , w , _PUB_N );

	for(unsigned i=0;i<n_var;i++) {
		gf16mat_prod( tmp , quad_mat , _PUB_M_BYTE , i+1 , w );
		quad_mat += _PUB_M_BYTE*(i+1);
		gf16v_madd( r , tmp , x[i] , _PUB_M_BYTE );
	}
	gf256v_add( r , quad_mat , _PUB_M_BYTE );
	memcpy( z , r , _PUB_M_BYTE );
}

void mpkc_pub_map_gf16_n_m_avx2( uint8_t * z , const uint8_t * pk_mat , const uint8_t * w , unsigned n, unsigned m)
{
        assert( n <= 256 );
        assert( m <= 256 );
        uint8_t tmp[128] __attribute__((aligned(32)));
        unsigned m_byte = (m+1)/2;
        uint8_t *r = z;
        //memset(r,0,m_byte);

        gf16mat_prod( r , pk_mat , m_byte , n , w );
        pk_mat += n*m_byte;

        uint8_t _x[256] __attribute__((aligned(32)));
        gf16v_split( _x , w , n );

        for(unsigned i=0;i<n;i++) {
                memset( tmp , 0 , m_byte );
                for(unsigned j=0;j<=i;j++) {
                        gf16v_madd( tmp , pk_mat , _x[j] , m_byte );
                        pk_mat += m_byte;
                }
                gf16v_madd( r , tmp , _x[i] , m_byte );
        }
        gf256v_add( r , pk_mat , m_byte );

}




