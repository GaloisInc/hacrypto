#ifndef _BLAS_SSE_H_
#define _BLAS_SSE_H_

#include "gf16.h"


#include "emmintrin.h"
#include "tmmintrin.h"

#include "blas_config.h"
#include "assert.h"


#include "gf16_sse.h"

#ifdef  __cplusplus
extern  "C" {
#endif




/////////////////  GF( 16 ) /////////////////////////////////////


extern const unsigned char __mask_low[];
extern const unsigned char * __gf16_mul;
extern const unsigned char __gf256_mul[];

static inline
void gf16v_mul_scalar_sse( uint8_t * a, uint8_t gf16_b , unsigned _num_byte ) {
	unsigned b = gf16_b&0xf;
	__m128i ml = _mm_load_si128( (__m128i*) (__gf16_mul + 32*b) );
	__m128i mh = _mm_load_si128( (__m128i*) (__gf16_mul + 32*b + 16) );
	__m128i mask = _mm_set1_epi8(0xf);

	unsigned i=0;
	uint8_t temp[32] __attribute__((aligned(16)));
	for(;i<_num_byte;i+=16) {
		__m128i inp;
		if( i+16 <= _num_byte ) { inp = _mm_loadu_si128( (__m128i*)(a+i) ); }
		else {
			for(unsigned j=0;j+i<_num_byte;j++) temp[j] = a[i+j];
			inp = _mm_load_si128( (__m128i*) temp );
		}
		__m128i r0 = _mm_shuffle_epi8(ml, inp&mask );
		__m128i r1 = _mm_shuffle_epi8(mh, _mm_srli_epi16(_mm_andnot_si128(mask,inp),4) );
		r0 ^= r1;
		if( i+16 <= _num_byte ) _mm_storeu_si128( (__m128i*)(a+i) , r0 );
		else {
			_mm_store_si128( (__m128i*)temp , r0 );
			for(unsigned j=0;j+i<_num_byte;j++) a[i+j] = temp[j];
		}
	}
}



#if 1
static inline
void gf16v_madd_sse( uint8_t * accu_c, const uint8_t * a , uint8_t gf16_b, unsigned _num_byte ) {
	unsigned b = gf16_b&0xf;
	__m128i ml = _mm_load_si128( (__m128i*) (__gf16_mul + 32*b) );
	__m128i mh = _mm_load_si128( (__m128i*) (__gf16_mul + 32*b + 16) );
	__m128i mask = _mm_set1_epi8(0xf);

	unsigned i=0;
	uint8_t temp[32] __attribute__((aligned(16)));
	for(;i<_num_byte;i+=16) {
		__m128i inp;
		__m128i out;
		if( i+16 <= _num_byte ) {
			inp = _mm_loadu_si128( (__m128i*)(a+i) );
			out = _mm_loadu_si128( (__m128i*)(accu_c+i) );
		} else {
			for(unsigned j=0;j+i<_num_byte;j++) temp[j] = a[i+j];
			inp = _mm_load_si128( (__m128i*) temp );
			for(unsigned j=0;j+i<_num_byte;j++) temp[j] = accu_c[i+j];
			out = _mm_load_si128( (__m128i*) temp );
		}
		__m128i r0 = _mm_shuffle_epi8(ml, inp&mask );
		__m128i r1 = _mm_shuffle_epi8(mh, _mm_srli_epi16(_mm_andnot_si128(mask,inp),4) );
		r0 ^= r1^out;
		if( i+16 <= _num_byte ) _mm_storeu_si128( (__m128i*)(accu_c+i) , r0 );
		else {
			_mm_store_si128( (__m128i*)temp , r0 );
			for(unsigned j=0;j+i<_num_byte;j++) accu_c[i+j] = temp[j];
		}
	}
}


#else
static inline
void gf16v_madd_sse( uint8_t * accu_c, const uint8_t * a , uint8_t gf16_b, unsigned _num_byte ) {
	unsigned b = gf16_b&0xf;
	__m128i ml = _mm_load_si128( (__m128i*) (__gf16_mul + 32*b) );
	__m128i mh = _mm_load_si128( (__m128i*) (__gf16_mul + 32*b + 16) );
	__m128i mask = _mm_set1_epi8(0xf);

	unsigned i=0;
	uint8_t temp[32] __attribute__((aligned(16)));
	for(;(i+16)<=_num_byte;i+=16) {
		__m128i inp = _mm_loadu_si128( (__m128i*)(a+i) );
		__m128i out = _mm_loadu_si128( (__m128i*)(accu_c+i) );
		__m128i r0 = _mm_shuffle_epi8(ml, inp&mask );
		__m128i r1 = _mm_shuffle_epi8(mh, _mm_srli_epi16(_mm_andnot_si128(mask,inp),4) );
		r0 ^= r1^out;
		_mm_storeu_si128( (__m128i*)(accu_c+i) , r0 );
	}
	for(;i<_num_byte;i++) accu_c[i] ^= gf256_mul_gf16( a[i] , gf16_b );
}
#endif




static inline
void gf16v_generate_multab_16_sse( uint8_t * _multab_byte , const uint8_t * _x0 , unsigned n )
{
	assert( n <= 16 );

	uint8_t multab[16*16] __attribute__((aligned(32)));
	__m128i cc = _mm_load_si128( (__m128i*) (_x0) );
	for(unsigned j=0;j<16;j++) {
		__m128i mt = _mm_load_si128( (__m128i*) (__gf16_mulx2 + 32*j) );
		_mm_store_si128( (__m128i*)(multab + j*16) , _mm_shuffle_epi8( mt, cc ) );
	}
	for(unsigned j=0;j<n;j++)
		for(unsigned k=0;k<16;k++) _multab_byte[j*16+k] = multab[k*16+j];
}

static inline
void gf16v_split_sse( uint8_t * x_align , const uint8_t * _x , unsigned n )
{
	assert( n <= 512 ); /// for spliting gf256v
	uint8_t * x = x_align;
	unsigned n_xmm = ((n + 31)>>5);
	__m128i mask_f = _mm_set1_epi8(0xf);
	for(unsigned i=0;i<n_xmm;i++) {
		__m128i inp = _mm_loadu_si128( (__m128i*)_x ); _x += 16;
		__m128i il = inp&mask_f;
		__m128i ih = _mm_srli_epi16(inp,4)&mask_f;
		_mm_store_si128( (__m128i*)( x+ 32*i ) , _mm_unpacklo_epi8(il,ih) );
		_mm_store_si128( (__m128i*)( x+ 32*i + 16 ) , _mm_unpackhi_epi8(il,ih) );
	}

}

static inline
uint8_t gf16v_dot_sse( const uint8_t * a , const uint8_t * b , unsigned n )
{
	assert( n <= 128 );
	uint8_t v1[128] __attribute__((aligned(32)));
	uint8_t v2[128] __attribute__((aligned(32)));
	/// insane here: XXX
	gf16v_split_sse( v1 , a , n );
	gf16v_split_sse( v2 , b , n );
	/// should be better upper.

	unsigned n_xmm = (n>>4);
	__m128i r = _mm_setzero_si128();
	for(unsigned i=0;i<n_xmm;i++) {
		r ^= tbl_gf16_mul( _mm_load_si128(  (__m128i*)(v1+i*16) ) , _mm_load_si128( (__m128i*)(v2+i*16) ) );
	}
	if( n&15 ) {
		__m128i rr = tbl_gf16_mul( _mm_load_si128(  (__m128i*)(v1+n_xmm*16) ) , _mm_load_si128( (__m128i*)(v2+n_xmm*16) ) );
		for(unsigned i=(n&15);i<16;i++) rr = _mm_slli_si128(rr,1);
		r ^= rr;
	}
	r ^= _mm_srli_si128(r,8);
	r ^= _mm_srli_si128(r,4);
	r ^= _mm_srli_si128(r,2);
	r ^= _mm_srli_si128(r,1);
	r ^= _mm_srli_epi16(r,4);
	return _mm_extract_epi16(r,0)&0xf;
}

static inline
void _gf16v_generate_multab_sse( uint8_t * _multabs , const uint8_t * x , unsigned n )
{
	for(unsigned i=0;i<n;i+=16) {
		if( 16 <= (n-i) ) {
			gf16v_generate_multab_16_sse( _multabs , x+i , 16 );
			_multabs += 16*16;
		} else {
			gf16v_generate_multab_16_sse( _multabs , x+i , n-i );
		}
	}
}


static inline
void gf16v_generate_multab_sse( uint8_t * _multabs , const uint8_t * _x , unsigned n )
{
	assert( n <= 288 ); /// for spliting gf256v
	uint8_t x[288] __attribute__((aligned(32)));
	gf16v_split_sse( x , _x , n );

	_gf16v_generate_multab_sse( _multabs , x , n );
}

static inline
void gf16mat_prod_multab_sse( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * multab ) {
	assert( n_A_width <= 128 );
	assert( n_A_vec_byte <= 64 );

	__m128i mask_f = _mm_set1_epi8(0xf);

	__m128i r0[4];
	__m128i r1[4];
	unsigned n_xmm = ((n_A_vec_byte + 15)>>4);
	for(unsigned i=0;i<n_xmm;i++) r0[i] = _mm_setzero_si128();
	for(unsigned i=0;i<n_xmm;i++) r1[i] = _mm_setzero_si128();

	for(unsigned i=0;i<n_A_width;i++) {
		__m128i ml = _mm_load_si128( (__m128i*)( multab + i*16) );
		//__m128i mh = _mm_slli_epi16( ml , 4 );
		for(unsigned j=0;j<n_xmm;j++) {
			__m128i inp = _mm_loadu_si128( (__m128i*)(matA+j*16) );
			r0[j] ^= _mm_shuffle_epi8( ml , inp&mask_f );
			r1[j] ^= _mm_shuffle_epi8( ml , _mm_srli_epi16(inp,4)&mask_f );
		}
		matA += n_A_vec_byte;
	}
	uint8_t temp[64] __attribute__((aligned(32)));
	for(unsigned i=0;i<n_xmm;i++) _mm_store_si128( (__m128i*)(temp + i*16) , r0[i]^_mm_slli_epi16(r1[i],4) );
	for(unsigned i=0;i<n_A_vec_byte;i++) c[i] = temp[i];
}


#if 0
/// slower
static inline
void gf16mat_prod_sse( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * b ) {
	assert( n_A_width <= 128 );
	assert( n_A_vec_byte <= 64 );

	uint8_t multab[128*16] __attribute__((aligned(32)));
	gf16v_generate_multab_sse( multab , b , n_A_width );

	gf16mat_prod_multab_sse( c , matA , n_A_vec_byte , n_A_width , multab );
}
#else
/// faster
static inline
void gf16mat_prod_sse( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * b ) {
	assert( n_A_width <= 128 );
	assert( n_A_vec_byte <= 64 );

	__m128i mask_f = _mm_set1_epi8(0xf);

	__m128i r0[4];
	__m128i r1[4];
	unsigned n_xmm = ((n_A_vec_byte + 15)>>4);
	for(unsigned i=0;i<n_xmm;i++) r0[i] = _mm_setzero_si128();
	for(unsigned i=0;i<n_xmm;i++) r1[i] = _mm_setzero_si128();

	uint8_t x[160] __attribute__((aligned(32)));
	gf16v_split_sse( x , b , n_A_width );
	for(unsigned i=0;i< ((n_A_width+15)>>4);i++) {
		__m128i lx = tbl_gf16_log( _mm_load_si128((__m128i*)(x+i*16)) );
		_mm_store_si128((__m128i*)(x+i*16),lx);
	}

	for(unsigned i=0;i<n_A_width;i++) {
		__m128i ml = _mm_set1_epi8(x[i]);
		for(unsigned j=0;j<n_xmm;j++) {
			__m128i inp = _mm_loadu_si128( (__m128i*)(matA+j*16) );
			r0[j] ^= tbl_gf16_mul_log( inp&mask_f , ml , mask_f );
			r1[j] ^= tbl_gf16_mul_log( _mm_srli_epi16(inp,4)&mask_f , ml , mask_f );
		}
		matA += n_A_vec_byte;
	}
	uint8_t temp[64] __attribute__((aligned(32)));
	for(unsigned i=0;i<n_xmm;i++) _mm_store_si128( (__m128i*)(temp + i*16) , r0[i]^_mm_slli_epi16(r1[i],4) );
	for(unsigned i=0;i<n_A_vec_byte;i++) c[i] = temp[i];
}
#endif




static inline
unsigned _gf16mat_gauss_elim_sse( uint8_t * mat , unsigned h , unsigned w )
{
	assert( 0 == (w%16) );
	unsigned n_xmm = w>>4;

	__m128i mask_0 = _mm_setzero_si128();

	uint8_t rr8 = 1;
	for(unsigned i=0;i<h;i++) {
		unsigned char i_r = i&0xf;
		unsigned i_d = i>>4;

		uint8_t * mi = mat+i*w;

		for(unsigned j=i+1;j<h;j++) {
			__m128i piv_i = _mm_load_si128( (__m128i*)( mi + i_d*16 ) );
			uint8_t * mj = mat+j*w;
			__m128i piv_j = _mm_load_si128( (__m128i*)( mj + i_d*16 ) );

			__m128i is_madd = _mm_cmpeq_epi8( piv_i , mask_0 ) ^ _mm_cmpeq_epi8( piv_j , mask_0 );
			__m128i madd_mask = _mm_shuffle_epi8( is_madd , _mm_set1_epi8(i_r) );

			piv_i ^= madd_mask&piv_j;
			_mm_store_si128( (__m128i*)( mi+ i_d*16 ) , piv_i );
			for(unsigned k=i_d+1;k<n_xmm;k++) {
				piv_i = _mm_load_si128( (__m128i*)( mi + k*16 ) );
				piv_j = _mm_load_si128( (__m128i*)( mj + k*16 ) );

				piv_i ^= madd_mask&piv_j;
				_mm_store_si128( (__m128i*)( mi+ k*16 ) , piv_i );
			}
		}
		rr8 &= gf256_is_nonzero( mi[i] );

		__m128i _pivot = _mm_set1_epi8( mi[i] );
		__m128i _ip = tbl_gf16_inv( _pivot );
		for(unsigned k=i_d;k<n_xmm;k++) {
			__m128i rowi = _mm_load_si128( (__m128i*)(mi+k*16) );
			rowi = tbl_gf16_mul( rowi , _ip );
			_mm_store_si128( (__m128i*)(mi+k*16) , rowi );
		}

		for(unsigned j=0;j<h;j++) {
			if(i==j) continue;

			uint8_t * mj = mat+j*w;
			__m128i mm = _mm_set1_epi8( mj[i] );

			for(unsigned k=i_d;k<n_xmm;k++) {
				__m128i rowi = _mm_load_si128( (__m128i*)(mi+k*16) );
				rowi = tbl_gf16_mul( rowi , mm );
				rowi ^= _mm_load_si128( (__m128i*)(mj+k*16) );
				_mm_store_si128( (__m128i*)(mj+k*16) , rowi );
			}
		}
	}
	return rr8;
}


static inline
unsigned gf16mat_gauss_elim_sse( uint8_t * mat , unsigned h , unsigned w )
{
	assert( 512 >= w );
	assert( 256 >= h );

	uint8_t _mat[512*256] __attribute__((aligned(32)));
	unsigned w_16 = ((w+15)>>4) <<4;
	unsigned w_2 = (w+1)>>1;

	for(unsigned i=0;i<h;i++) gf16v_split_sse( _mat + i*w_16 , mat + i*w_2 , w );
	unsigned r = _gf16mat_gauss_elim_sse( _mat , h , w_16 );
	for(unsigned i=0;i<h;i++) {
		uint8_t * mi = _mat + i*w_16;
		for(unsigned j=0;j<w;j+=2) {
			uint8_t v = mi[j]|(mi[j+1]<<4);
			mat[i*w_2 + (j>>1)] = v;
		}
	}
	return r;
}





static inline
void gf16v_batch_madd_sse_16( uint8_t * accu_c, const uint8_t * a , uint8_t _b ) {
#if 1
	__m128i b0 = tbl_gf16_log( _mm_set1_epi8(_b&0xf) );
	__m128i b1 = tbl_gf16_log( _mm_set1_epi8((_b>>4)&0xf) );
	__m128i mask = _mm_set1_epi8(0xf);

	__m128i inp = _mm_load_si128( (__m128i*)a );
	__m128i out = _mm_load_si128( (__m128i*)accu_c );
	__m128i i0 = inp&mask;
	__m128i i1 = _mm_srli_epi16(inp,4)&mask;
	__m128i r0 = tbl_gf16_mul_log(i0,b0,mask);
	__m128i r1 = tbl_gf16_mul_log(i1,b1,mask);
	__m128i rr = r0 ^ r1 ^ out;

	_mm_store_si128( (__m128i*)accu_c , rr );
#else
	unsigned b = _b;
	__m128i ml = _mm_load_si128( (__m128i*) (__gf256_mul + 32*(b&0xf) ) );
	__m128i mh = _mm_load_si128( (__m128i*) (__gf256_mul + 32*( (b>>4)&0xf) ) );
	__m128i mask = _mm_set1_epi8(0xf);

	__m128i inp = _mm_load_si128( (__m128i*)a );
	__m128i out = _mm_load_si128( (__m128i*)accu_c );
	__m128i i0 = inp&mask;
	__m128i i1 = _mm_srli_epi16(inp,4)&mask;
	__m128i r0 = _mm_shuffle_epi8(ml, i0 );
	__m128i r1 = _mm_shuffle_epi8(mh, i1 );
	__m128i rr = r0 ^ r1 ^ out;

	_mm_store_si128( (__m128i*)accu_c , rr );
#endif
}






///////////////////////////////  GF( 256 ) ////////////////////////////////////////////////////



static inline
void gf256v_add_sse( uint8_t * accu_b, const uint8_t * a , unsigned _num_byte ) {
	//uint8_t temp[32] __attribute__((aligned(32)));
	unsigned n_xmm = (_num_byte)>>4;
	for(unsigned i=0;i<n_xmm;i++) {
		__m128i inp = _mm_loadu_si128( (__m128i*) (a+i*16) );
		__m128i out = _mm_loadu_si128( (__m128i*) (accu_b+i*16) );
		out ^= inp;
		_mm_storeu_si128( (__m128i*) (accu_b+i*16) , out );
	}
	if( 0 == (_num_byte&0xf) ) return;
	for(unsigned j=0;j<(_num_byte&0xf);j++) {
		accu_b[n_xmm*16+j] ^= a[n_xmm*16+j];
	}
}



static inline
void gf256v_generate_multab_sse( uint8_t * _multabs , const uint8_t * _x , unsigned n )
{
	assert( n <= 144 );
	gf16v_generate_multab_sse( _multabs , _x , 2*n );

	__m128i mul_8 = _mm_load_si128( (__m128i*)(__gf16_mulx2 + 32*8) );
	for(unsigned i=0;i<n;i++) {
		__m128i ml = _mm_load_si128( (__m128i*) (_multabs+32*i) );
		__m128i mh = _mm_load_si128( (__m128i*) (_multabs+32*i+16) );
		__m128i ml256 = _mm_slli_epi16( mh,4) | ml;
		__m128i mh256 = _mm_slli_epi16(ml^mh,4)|_mm_shuffle_epi8(mul_8,mh);
		_mm_store_si128( (__m128i*) (_multabs+32*i) , ml256 );
		_mm_store_si128( (__m128i*) (_multabs+32*i+16) , mh256 );
	}
}



static inline
void gf256mat_prod_multab_sse( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * multab ) {
	assert( n_A_width <= 144 );
	assert( n_A_vec_byte <= 80 );

	__m128i mask_f = _mm_set1_epi8(0xf);

	__m128i r[5];
	unsigned n_xmm = ((n_A_vec_byte + 15)>>4);
	for(unsigned i=0;i<n_xmm;i++) r[i] = _mm_setzero_si128();

	for(unsigned i=0;i<n_A_width;i++) {
		__m128i ml = _mm_load_si128( (__m128i*)( multab + i*32) );
		__m128i mh = _mm_load_si128( (__m128i*)( multab + i*32+16) );
		for(unsigned j=0;j<n_xmm;j++) {
			__m128i inp = _mm_loadu_si128( (__m128i*)(matA+j*16) );
			r[j] ^= _mm_shuffle_epi8( ml , inp&mask_f );
			r[j] ^= _mm_shuffle_epi8( mh , _mm_srli_epi16(inp,4)&mask_f );
		}
		matA += n_A_vec_byte;
	}
	uint8_t r8[80] __attribute__((aligned(32)));
	for(unsigned i=0;i<n_xmm;i++) _mm_store_si128( (__m128i*)(r8 + i*16) , r[i] );
	for(unsigned i=0;i<n_A_vec_byte;i++) c[i] = r8[i];
}


static inline
void gf256mat_prod_secure_sse( uint8_t * c , const uint8_t * matA , unsigned n_A_vec_byte , unsigned n_A_width , const uint8_t * b ) {
	assert( n_A_width <= 128 );
	assert( n_A_vec_byte <= 80 );

#if 1
/// faster !!!!!
	uint8_t multab[256*16] __attribute__((aligned(32)));
	gf256v_generate_multab_sse( multab , b , n_A_width );

	gf256mat_prod_multab_sse( c , matA , n_A_vec_byte , n_A_width , multab );
#else
	__m128i mask_f = _mm_load_si128( (__m128i*)__mask_low);

	__m128i r[5];
	unsigned n_xmm = ((n_A_vec_byte + 15)>>4);
	for(unsigned i=0;i<n_xmm;i++) r[i] = _mm_setzero_si128();

	uint8_t x0[128] __attribute__((aligned(32)));
	uint8_t x1[128] __attribute__((aligned(32)));
	for(unsigned i=0;i<n_A_width;i++) x0[i] = b[i];
	for(unsigned i=0;i< ((n_A_width+15)>>4);i++) {
		__m128i inp = _mm_load_si128((__m128i*)(x0+i*16));
		__m128i i0 = inp&mask_f;
		__m128i i1 = _mm_srli_epi16(inp,4)&mask_f;
		_mm_store_si128((__m128i*)(x0+i*16),tbl_gf16_log(i0));
		_mm_store_si128((__m128i*)(x1+i*16),tbl_gf16_log(i1));
	}

	for(unsigned i=0;i<n_A_width;i++) {
		__m128i m0 = _mm_set1_epi8( x0[i] );
		__m128i m1 = _mm_set1_epi8( x1[i] );
		for(unsigned j=0;j<n_xmm;j++) {
			__m128i inp = _mm_loadu_si128( (__m128i*)(matA+j*16) );
			__m128i l_i0 = tbl_gf16_log(inp&mask_f);
			__m128i l_i1 = tbl_gf16_log(_mm_srli_epi16(inp,4)&mask_f);

			__m128i ab0 = tbl_gf16_mul_log_log( l_i0 , m0 , mask_f );
			__m128i ab1 = tbl_gf16_mul_log_log( l_i1 , m0 , mask_f )^tbl_gf16_mul_log_log( l_i0 , m1 , mask_f );
			__m128i ab2 = tbl_gf16_mul_log_log( l_i1 , m1 , mask_f );
			__m128i ab2x8 = tbl_gf16_mul_0x8( ab2 );

			r[j] ^= ab0 ^ ab2x8 ^ _mm_slli_epi16( ab1^ab2 , 4 );
		}
		matA += n_A_vec_byte;
	}
	for(unsigned i=0;i<n_xmm;i++) _mm_store_si128( (__m128i*)(x0 + i*16) , r[i] );
	for(unsigned i=0;i<n_A_vec_byte;i++) c[i] = x0[i];

#endif

}





///////////////////////////////////////////////////////////////////////////




static inline
__m128i _load_xmm( const uint8_t *a , unsigned st_idx , unsigned _num_byte ) {
	uint8_t temp[16] __attribute__((aligned(16)));
	if( (st_idx + 15 )<_num_byte ) {
		return _mm_loadu_si128((__m128i*)(a+st_idx));
	} else {
		//for(unsigned i=st_idx;i<_num_byte;i++) temp[i-st_idx] = a[i];
		for(int i=((int)(_num_byte-st_idx))-1;i>=0;i--) temp[i] = a[i+st_idx];
		return _mm_load_si128((__m128i*)temp);
	}
}

static inline
void _store_xmm( uint8_t *a , unsigned st_idx , unsigned _num_byte , __m128i data ) {
	uint8_t temp[16] __attribute__((aligned(16)));
	if( (st_idx + 15 )<_num_byte ) {
		_mm_storeu_si128((__m128i*)(a+st_idx),data);
	} else {
		_mm_store_si128((__m128i*)temp,data);
		//for(unsigned i=0;i<_num_byte-st_idx;i++) a[st_idx+i] = temp[i];
		for(int i=((int)(_num_byte-st_idx))-1;i>=0;i--) a[st_idx+i] = temp[i];
	}
}

static inline
void gf256v_m0x10_add_sse( uint8_t * accu_c, const uint8_t * a , unsigned _num_byte ) {
	__m128i ml = _mm_load_si128( (__m128i*) (__gf16_mul + 32*8) );
	__m128i mask = _mm_set1_epi8(0xf);
	unsigned i=0;
	for(;i<_num_byte;i+=16) {
		__m128i inp = _load_xmm(a,i,_num_byte);
		__m128i out = _load_xmm(accu_c,i,_num_byte);
		__m128i i0 = inp&mask;
		__m128i i1 = _mm_andnot_si128(mask,inp);
		__m128i r = out ^ _mm_slli_epi16(i0,4) ^ i1 ^ _mm_shuffle_epi8(ml,_mm_srli_epi16(i1,4));
		_store_xmm( accu_c , i , _num_byte , r );
	}
}

static inline
void gf256v_m0x4_add_sse( uint8_t * accu_c, const uint8_t * a , unsigned _num_byte ) {
	__m128i ml = _mm_load_si128( (__m128i*) (__gf16_mul + 32*4) );
	__m128i mask = _mm_set1_epi8(0xf);
	unsigned i=0;
	for(;i<_num_byte;i+=16) {
		__m128i inp = _load_xmm(a,i,_num_byte);
		__m128i out = _load_xmm(accu_c,i,_num_byte);
		__m128i i0 = inp&mask;
		__m128i i1 = _mm_andnot_si128(mask,inp);
		__m128i r = out ^ _mm_slli_epi16( _mm_shuffle_epi8(ml,_mm_srli_epi16(i1,4)) ,4) ^ _mm_shuffle_epi8(ml,i0);
		_store_xmm( accu_c , i , _num_byte , r );
	}
}


static inline
void gf256v_mul_scalar_sse( uint8_t * a, uint8_t _b , unsigned _num_byte ) {
	unsigned b = _b;
	__m128i ml = _mm_load_si128( (__m128i*) (__gf256_mul + 32*b) );
	__m128i mh = _mm_load_si128( (__m128i*) (__gf256_mul + 32*b + 16) );
	__m128i mask = _mm_set1_epi8(0xf);

	unsigned i=0;
	for(;i<_num_byte;i+=16) {
		__m128i inp = _load_xmm(a,i,_num_byte);
		__m128i i0 = inp&mask;
		__m128i i1 = _mm_srli_epi16(_mm_andnot_si128(mask,inp),4);

		__m128i r0 = _mm_shuffle_epi8(ml, i0 );
		__m128i r1 = _mm_shuffle_epi8(mh, i1 );
		__m128i rr = r0 ^ r1;

		_store_xmm( a , i , _num_byte , rr );
	}
}

static inline
void gf256v_madd_sse( uint8_t * accu_c, const uint8_t * a , uint8_t _b, unsigned _num_byte ) {
	unsigned b = _b;
	__m128i ml = _mm_load_si128( (__m128i*) (__gf256_mul + 32*b) );
	__m128i mh = _mm_load_si128( (__m128i*) (__gf256_mul + 32*b + 16) );
	__m128i mask = _mm_set1_epi8(0xf);

	unsigned i=0;
	for(;i<_num_byte;i+=16) {
		__m128i inp = _load_xmm(a,i,_num_byte);
		__m128i out = _load_xmm(accu_c,i,_num_byte);
		__m128i i0 = inp&mask;
		__m128i i1 = _mm_srli_epi16(_mm_andnot_si128(mask,inp),4);

		__m128i r0 = _mm_shuffle_epi8(ml, i0 );
		__m128i r1 = _mm_shuffle_epi8(mh, i1 );
		__m128i rr = r0 ^ r1 ^ out;

		_store_xmm( accu_c , i , _num_byte , rr );
	}
}



static inline
unsigned _gf256mat_gauss_elim_sse( uint8_t * mat , unsigned h , unsigned w )
{
	assert( 0 == (w%16) );
	unsigned n_xmm = w>>4;

	__m128i mask_0 = _mm_setzero_si128();

	uint8_t rr8 = 1;
	for(unsigned i=0;i<h;i++) {
		unsigned char i_r = i&0xf;
		unsigned i_d = i>>4;

		uint8_t * mi = mat+i*w;

		for(unsigned j=i+1;j<h;j++) {
			__m128i piv_i = _mm_load_si128( (__m128i*)( mi + i_d*16 ) );
			uint8_t * mj = mat+j*w;
			__m128i piv_j = _mm_load_si128( (__m128i*)( mj + i_d*16 ) );

			__m128i is_madd = _mm_cmpeq_epi8( piv_i , mask_0 ) ^ _mm_cmpeq_epi8( piv_j , mask_0 );
			__m128i madd_mask = _mm_shuffle_epi8( is_madd , _mm_set1_epi8(i_r) );

			piv_i ^= madd_mask&piv_j;
			_mm_store_si128( (__m128i*)( mi+ i_d*16 ) , piv_i );
			for(unsigned k=i_d+1;k<n_xmm;k++) {
				piv_i = _mm_load_si128( (__m128i*)( mi + k*16 ) );
				piv_j = _mm_load_si128( (__m128i*)( mj + k*16 ) );

				piv_i ^= madd_mask&piv_j;
				_mm_store_si128( (__m128i*)( mi+ k*16 ) , piv_i );
			}
		}
		rr8 &= gf256_is_nonzero( mi[i] );

		__m128i _pivot = _mm_set1_epi8( mi[i] );
		__m128i _ip = tbl_gf256_inv( _pivot );
		for(unsigned k=i_d;k<n_xmm;k++) {
			__m128i rowi = _mm_load_si128( (__m128i*)(mi+k*16) );
			rowi = tbl_gf256_mul( rowi , _ip );
			_mm_store_si128( (__m128i*)(mi+k*16) , rowi );
		}

		for(unsigned j=0;j<h;j++) {
			if(i==j) continue;

			uint8_t * mj = mat+j*w;
			__m128i mm = _mm_set1_epi8( mj[i] );

			for(unsigned k=i_d;k<n_xmm;k++) {
				__m128i rowi = _mm_load_si128( (__m128i*)(mi+k*16) );
				rowi = tbl_gf256_mul( rowi , mm );
				rowi ^= _mm_load_si128( (__m128i*)(mj+k*16) );
				_mm_store_si128( (__m128i*)(mj+k*16) , rowi );
			}
		}
	}
	return rr8;
}


static inline
unsigned gf256mat_gauss_elim_sse( uint8_t * mat , unsigned h , unsigned w )
{
	assert( 512 >= w );
	assert( 256 >= h );

	uint8_t _mat[512*256] __attribute__((aligned(32)));
	unsigned w_16 = ((w+15)>>4) <<4;

	for(unsigned i=0;i<h;i++) for(unsigned j=0;j<w;j++) _mat[i*w_16+j] = mat[i*w+j];
	unsigned r = _gf256mat_gauss_elim_sse( _mat , h , w_16 );
	for(unsigned i=0;i<h;i++) for(unsigned j=0;j<w;j++) mat[i*w+j] = _mat[i*w_16+j];
	return r;
}







#ifdef  __cplusplus
}
#endif



#endif
