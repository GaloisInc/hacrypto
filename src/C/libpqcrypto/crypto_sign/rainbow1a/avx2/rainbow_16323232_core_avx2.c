

#include "gf16_sse.h"

#include "blas_avx2.h"

#include "rainbow_16.h"


static inline
void mq_gf16_multab_n_16byte_sse( uint8_t * z , const uint8_t * pk_mat , const uint8_t * multab , unsigned n )
{
	__m128i mask_f = _mm_set1_epi8(0xf);

	__m128i r0 = _mm_setzero_si128();
	__m128i r1 = _mm_setzero_si128();

	for(unsigned i=0;i<n;i++) {
		__m128i mt = _mm_load_si128( (__m128i*)( multab + i*16 ) );

		__m128i inp = _mm_loadu_si128( (__m128i*)( pk_mat ) ); pk_mat += 16;
		r0 ^= _mm_shuffle_epi8( mt , inp&mask_f );
		r1 ^= _mm_shuffle_epi8( mt , _mm_srli_epi16(inp,4)&mask_f );
	}
	for(unsigned i=0;i<n;i++) {
		__m128i temp0 = _mm_setzero_si128();
		__m128i temp1 = _mm_setzero_si128();
		__m128i mt;
		for(unsigned j=0;j<=i;j++) {
			mt = _mm_load_si128( (__m128i*)( multab + j*16 ) );

			__m128i inp = _mm_loadu_si128( (__m128i*)( pk_mat ) ); pk_mat += 16;
			temp0 ^= _mm_shuffle_epi8( mt , inp&mask_f );
			temp1 ^= _mm_shuffle_epi8( mt , _mm_srli_epi16(inp,4)&mask_f );
		}
		r0 ^= _mm_shuffle_epi8( mt , temp0 );
		r1 ^= _mm_shuffle_epi8( mt , temp1 );
	}

	__m128i rr = r0^_mm_slli_epi16(r1,4)^ _mm_loadu_si128( (__m128i*)( pk_mat ) );
	uint8_t temp[16] __attribute__((aligned(32)));
	_mm_store_si128( (__m128i*) temp , rr  );
	for(unsigned i=0;i<16;i++) z[i]=temp[i];
}


static inline
void gen_l1_mat_avx2( uint8_t * mat , const rainbow_ckey * k , const uint8_t * multab  ) {
	for(unsigned i=0;i<32;i++) {
		gf16mat_prod_multab_sse( mat + i*16 , k->l1_vo[i] , 16 , 32 , multab );
	}
	gf256v_add_sse( mat , k->l1_o , 16*32 );
}

static inline
void gen_l2_mat_avx2( uint8_t * mat , const rainbow_ckey * k , const uint8_t * multab  ) {
	for(unsigned i=0;i<32;i++) {
		gf16mat_prod_multab_sse( mat + i*16 , k->l2_vo[i] , 16 , 64 , multab );
	}
	gf256v_add_sse( mat , k->l2_o , 16*32 );
}


/////////////////////////////////////////////////////////////////

#if 1
static inline
uint8_t if_zero_then_0xf(uint8_t p ) {
	return (p-1)>>4;
}

static inline
unsigned linear_solver_32x32_avx2( uint8_t * r , const uint8_t * mat_32x32 , const uint8_t * cc )
{

	uint8_t mat[32*32] __attribute__((aligned(32)));
	for(unsigned i=0;i<32;i++) gf16v_split_sse( mat + i*32 , mat_32x32 + i*16 , 32 );

	__m256i mask_f = _mm256_load_si256((__m256i const *) __mask_low);

	uint8_t temp[32] __attribute__((aligned(32)));
	uint8_t pivots[32] __attribute__((aligned(32)));

	uint8_t rr8 = 1;
	for(unsigned i=0;i<32;i++) {
		for(unsigned j=0;j<32;j++) pivots[j] = mat[j*32+i];
			if( 0 == i ) {
				gf16v_split_sse( temp , cc , 32 );
				for(unsigned j=0;j<32;j++) mat[j*32] = temp[j];
			}
		__m256i rowi = _mm256_load_si256( (__m256i*)(mat+i*32) );
		for(unsigned j=i+1;j<32;j++) {
			temp[0] = if_zero_then_0xf( pivots[i] );
			__m256i mask_zero = _mm256_broadcastb_epi8(_mm_load_si128((__m128i*)temp));

			__m256i rowj = _mm256_load_si256( (__m256i*)(mat+j*32) );
			rowi ^= mask_zero&rowj;
			//rowi ^= predicate_zero&(*(__m256i*)(mat+j*32));
			pivots[i] ^= temp[0]&pivots[j];
		}
		uint8_t is_pi_nz = if_zero_then_0xf(pivots[i]);
		is_pi_nz = ~is_pi_nz;
		rr8 &= is_pi_nz;

		temp[0] = pivots[i];
		__m128i inv_rowi = tbl_gf16_inv( _mm_load_si128((__m128i*)temp) );
		pivots[i] = _mm_extract_epi8( inv_rowi , 0 );

		__m256i log_pivots = tbl32_gf16_log( _mm256_load_si256( (__m256i*)pivots ) );
		_mm256_store_si256( (__m256i*)pivots , log_pivots );

		temp[0] = pivots[i];
		__m256i logpi = _mm256_broadcastb_epi8( _mm_load_si128((__m128i*)temp) );
		rowi = tbl32_gf16_mul_log( rowi , logpi , mask_f );
		__m256i log_rowi = tbl32_gf16_log( rowi );
		for(unsigned j=0;j<32;j++) {
			if(i==j) {
				_mm256_store_si256( (__m256i*)(mat+j*32) , rowi );
				continue;
			}
			__m256i rowj = _mm256_load_si256( (__m256i*)(mat+j*32) );
			temp[0] = pivots[j];
			__m256i logpj = _mm256_broadcastb_epi8( _mm_load_si128((__m128i*)temp) );
			rowj ^= tbl32_gf16_mul_log_log( log_rowi , logpj , mask_f );
			_mm256_store_si256( (__m256i*)(mat+j*32) , rowj );
		}
	}

	for(unsigned i=0;i<32;i++) {
		gf16v_set_ele( r , i , mat[i*32] );
		//r[i] = gf256_mul( mat[i*32+20] , gf256_inv( mat[i*32+i] ) );
	}
	return rr8;
}
#else
static inline
unsigned linear_solver_32x32_avx2( uint8_t * r , const uint8_t * mat_32x32 , const uint8_t * cc )
{
        uint8_t mat[32*33] __attribute__((aligned(32)));
        for(unsigned i=0;i<32;i++) {
                gf16v_split( mat+i*33 , mat_32x32 + i*16 , 32 );
                mat[i*33+32] = gf16v_get_ele( cc , i );
        }

	unsigned r8 = _gf256mat_gauss_elim( mat , 32 , 33 );

        for(unsigned i=0;i<32;i++) {
                gf16v_set_ele( r ,  i , *(mat + i*33 + 32) );
        }
        return r8;
}

#endif


///////////////////////////////////////////////////////////


unsigned rainbow_ivs_central_map_16323232_avx2( uint8_t * r , const rainbow_ckey * k , const uint8_t * a ) {

	uint8_t mat1[32*16] __attribute__((aligned(32)));
	uint8_t temp[32] __attribute__((aligned(32)));

	uint8_t multab[64*16] __attribute__((aligned(32)));
	gf16v_generate_multab_sse( multab , r , 32 );

	mq_gf16_multab_n_16byte_sse( temp , k->l1_vv , multab , 32 );
//memset( temp , 0 , 16 );

	gf256v_add( temp  , a , 16 );
	gen_l1_mat_avx2( mat1 , k , multab );
	//gen_l1_mat( mat1 , k , r );
	unsigned r1 = linear_solver_32x32_avx2( r+16 , mat1 , temp );
	//if( 0 == r1 ) return 0;
	//unsigned r1 = linear_solver_32x32( r+16 , mat1 , temp );

	gf16v_generate_multab_sse( multab + 32*16 , r+16 , 32 );

	mq_gf16_multab_n_16byte_sse( temp , k->l2_vv , multab , 64 );
//memset( temp , 0 , 16 );

	gf256v_add( temp  , a+16 , 16 );
	gen_l2_mat_avx2( mat1 , k , multab );
	//gen_l2_mat( mat1 , k , r );
	unsigned r2 = linear_solver_32x32_avx2( r+32 , mat1 , temp );
	//unsigned r2 = linear_solver_32x32( r+32 , mat1 , temp );

	return r1&r2;
}


#include "hash_utils.h"
#include <string.h>

int rainbow_sign_16323232_avx2( uint8_t * signature , const uint8_t * _sk , const uint8_t * _digest )
{
	const rainbow_key * sk = (const rainbow_key *)_sk;
	const rainbow_ckey * k = &( sk->ckey);
//// line 1 - 5
	uint8_t mat_l1[32*16] __attribute__((aligned(32)));
	uint8_t mat_l2[32*16] __attribute__((aligned(32)));
	uint8_t temp_o1[32] __attribute__((aligned(32))) = {0};
	uint8_t temp_o2[32] __attribute__((aligned(32)));
	uint8_t multab[64*16] __attribute__((aligned(32)));
	uint8_t vinegar[_V1_BYTE] __attribute__((aligned(32)));
	unsigned l1_succ = 0;
	unsigned time = 0;
	while( !l1_succ ) {
		if( 512 == time ) break;
		gf256v_rand( vinegar , _V1_BYTE );
		gf16v_generate_multab_sse( multab , vinegar , 32 );
		gen_l1_mat_avx2( mat_l1 , k , multab );
		//gen_l1_mat( mat_l1 , k , vinegar );

		l1_succ = linear_solver_32x32_avx2( temp_o1 , mat_l1 , temp_o1 );
		//l1_succ = linear_solver_l1( temp_o1 , mat_l1 , temp_o1 );
		time ++;
	}
	uint8_t temp_vv1[32] __attribute__((aligned(32)));
	mq_gf16_multab_n_16byte_sse( temp_vv1 , k->l1_vv , multab , 32 );
	//mpkc_pub_map_gf16_n_m( temp_vv1 , k->l1_vv , vinegar , _V1 , _O1 );

	//// line 7 - 14
	uint8_t _z[_PUB_M_BYTE] __attribute__((aligned(32)));
	uint8_t y[_PUB_M_BYTE] __attribute__((aligned(32)));
	uint8_t x[_PUB_N_BYTE] __attribute__((aligned(32)));
	uint8_t w[_PUB_N_BYTE] __attribute__((aligned(32)));
	uint8_t digest_salt[_HASH_LEN + _SALT_BYTE] = {0};
	uint8_t * salt = digest_salt + _HASH_LEN;
	memcpy( digest_salt , _digest , _HASH_LEN );

	memcpy( x , vinegar , _V1_BYTE );
	unsigned succ = 0;
	while( !succ ) {
		if( 512 == time ) break;

		gf256v_rand( salt , _SALT_BYTE );  /// line 8
		sha2_chain_msg( _z , _PUB_M_BYTE , digest_salt , _HASH_LEN+_SALT_BYTE ); /// line 9

		gf256v_add(_z,sk->vec_s,_PUB_M_BYTE);
		gf16mat_prod(y,sk->mat_s,_PUB_M_BYTE,_PUB_M,_z); /// line 10

		memcpy( temp_o1 , temp_vv1 , _O1_BYTE );
		gf256v_add( temp_o1 , y , _O1_BYTE );
		linear_solver_32x32_avx2( x + _V1_BYTE , mat_l1 , temp_o1 );

		//linear_solver_l1( x + _V1_BYTE , mat_l1 , temp_o1 );
		gf16v_generate_multab_sse( multab + 32*16 , x+16 , 32 );

		gen_l2_mat_avx2( mat_l2 , k , multab );
		//gen_l2_mat( mat_l2 , k , x );
		mq_gf16_multab_n_16byte_sse( temp_o2 , k->l2_vv , multab , 64 );
		//mpkc_pub_map_gf16_n_m( temp_o2 , k->l2_vv , x , _V2 , _O2 );
		gf256v_add( temp_o2 , y+_O1_BYTE , _O2_BYTE );
		//succ = linear_solver_l2( x + _V2_BYTE , mat_l2 , temp_o2 );  /// line 13
		succ = linear_solver_32x32_avx2( x + _V2_BYTE , mat_l2 , temp_o2 );

		time ++;
	};
	gf256v_add(x,sk->vec_t,_PUB_N_BYTE);
	gf16mat_prod(w,sk->mat_t,_PUB_N_BYTE,_PUB_N,x);

	memset( signature , 0 , _SIGNATURE_BYTE );
        // return time;
	if( 256 <= time ) return -1;
	gf256v_add( signature , w , _PUB_N_BYTE );
	gf256v_add( signature + _PUB_N_BYTE , salt , _SALT_BYTE );
	return 0;



}
