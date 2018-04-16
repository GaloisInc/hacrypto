

#include "string.h"
#include "gui_config.h"

#include "blas.h"

#include "gui.h"



#ifndef _DEBUG_GUI_

#include "mpkc.h"

#define mpkc_interpolate mpkc_interpolate_gf2

static
void gui_central_map( uint8_t * r , const gui_key * key , const uint8_t * a );

/// algorithm 3
static
unsigned gui_ivs_central_map( uint8_t * r , const gui_key * key , const uint8_t * a , const uint8_t * vinegar );

static
void gui_pubmap_seckey( uint8_t * z , const gui_key * sk , const uint8_t * w );

static
void gui_genkey_debug( gui_key * pk , gui_key * sk );

#endif




#ifndef _DEBUG_GUI_
static inline
#endif
void gui_pubmap_seckey( uint8_t * z , const gui_key * sk , const uint8_t * w ) {

	uint8_t tt[_PUB_N_BYTE] __attribute__((aligned(16))) = {0};
	gf2mat_prod( tt , sk->mat_t , _PUB_N_BYTE , _SEC_N , w );
	gf256v_add( tt , sk->vec_t , _PUB_N_BYTE );

	uint8_t tt1[_SEC_M_BYTE] __attribute__((aligned(16))) = {0};
	gui_central_map( tt1 , sk , tt );

	uint8_t tt2[_SEC_M_BYTE] = {0};
	gf2mat_prod( tt2 , sk->mat_s , _SEC_M_BYTE , _SEC_M , tt1 );
	gf256v_add( tt2 , sk->vec_s , _SEC_M_BYTE );

	memcpy( z , tt2 , _SEC_M_BYTE ); /// option: add "minus" for simulation here.
}



#ifndef _DEBUG_GUI_
static inline
#endif
void gui_genkey_debug( gui_key * pk , gui_key * sk )
{
	gf2mat_rand_inv( pk->mat_t , sk->mat_t , _PUB_N );
	gf256v_rand( pk->vec_t , _PUB_N_BYTE );
	memcpy( sk->vec_t , pk->vec_t , _PUB_N_BYTE );
	//gf2mat_prod( sk->vec_t , sk->mat_t , _PUB_N_BYTE , _PUB_N , pk->vec_t );

	gf2mat_rand_inv( pk->mat_s , sk->mat_s , _SEC_M );
	gf256v_rand( pk->vec_s , _SEC_M_BYTE );
	memcpy( sk->vec_s , pk->vec_s , _SEC_M_BYTE );
	//gf2mat_prod( sk->vec_s , sk->mat_s , _SEC_M_BYTE , _SEC_M , pk->vec_s );

	gf256v_rand( (uint8_t *)&(pk->cpoly) , sizeof(cpoly_t) );
	memcpy( & (sk->cpoly) , & (pk->cpoly) , sizeof(cpoly_t) );

}



static inline
void gui_pubmap_wrapper( void * z, const void* pk_key, const void * w) {
	uint8_t tt[_SEC_M_BYTE] __attribute__((aligned(16))) ={0};
	gui_pubmap_seckey( tt , (const gui_key *)pk_key, (const uint8_t *)w );
	memcpy( (uint8_t *)z , tt , _PUB_M_BYTE );
}



void gui_genkey( uint8_t * pk , gui_key * sk )
{
	gui_key _pk;
	gui_genkey_debug( &_pk , sk );

	mpkc_interpolate_gf2( pk , gui_pubmap_wrapper , (const void*) &_pk );
}


/////////////////////////////



#include "prng_utils.h"



/// algorithm 3.
unsigned gui_secmap( uint8_t * w , const gui_key * sk , const uint8_t * z )
{
	uint8_t _z[_SEC_M_BYTE] __attribute__((aligned(16)))= {0};
	//uint8_t _y[_SEC_M_BYTE] __attribute__((aligned(16)))= {0};
	uint8_t x[_PUB_N_BYTE] __attribute__((aligned(16)));

	uint8_t temp_t[_PUB_N_BYTE] __attribute__((aligned(16))) = {0};
	uint8_t Y[_SEC_M_BYTE] __attribute__((aligned(16))) = {0};
	uint8_t vinegar[(_VINEGAR_BYTE)] __attribute__((aligned(16))) = {0};

	memcpy( _z , sk->vec_s , _SEC_M_BYTE );
	/// minus
	prng_bytes( temp_t , _MINUS_BYTE );

	gf256v_add( _z , z , _PUB_M_BYTE );
	gf256v_add( _z + _PUB_M_BYTE , temp_t , _MINUS_BYTE );

	gf2mat_prod(Y, sk->mat_s , _SEC_M_BYTE, _SEC_M , _z );

	unsigned fail = 0;
	unsigned time = 0;
	do {
		/// vinegar
		prng_bytes( vinegar , _VINEGAR_BYTE );

		fail = gui_ivs_central_map( x , sk , Y , vinegar );

		if( 0 == fail  ) break;
		/// check if ivsQ sucess here
		time++;
	} while( time < 1024 );
	gf256v_add( x , sk->vec_t , _PUB_N_BYTE );
	gf2mat_prod(w , sk->mat_t , _PUB_N_BYTE,_SEC_N,x);

	return (time<1024)?1:0;
}



/// algorithm 7
unsigned InvHFEv_( uint8_t * z , const gui_key * sk , const uint8_t * w , const uint8_t * minus , const uint8_t * vinegar )
{
	uint8_t _w[_SEC_M_BYTE] __attribute__((aligned(16)))= {0};
	uint8_t X[_PUB_N_BYTE] __attribute__((aligned(16)));
	uint8_t y[_PUB_N_BYTE] __attribute__((aligned(16))) = {0};
	memset( z , 0 , _PUB_N_BYTE );

	memcpy( _w , sk->vec_s , _SEC_M_BYTE );
	gf256v_add( _w , w , _PUB_M_BYTE );
	gf256v_add( _w + _PUB_M_BYTE , minus , _MINUS_BYTE );
	gf2mat_prod(X, sk->mat_s , _SEC_M_BYTE, _SEC_M , _w );

	unsigned fail = gui_ivs_central_map( y , sk , X , vinegar );

	if( 0 == fail  ) {
		gf256v_add( y , sk->vec_t , _PUB_N_BYTE );
		gf2mat_prod(z , sk->mat_t , _PUB_N_BYTE,_SEC_N,y);
		return 1;
	}
	return 0;
}



///////////////////////////////////////



#define _GF_EXT_ BGF_SIZE

#include "gfext.h"

#include "gfext_poly_gf2.h"




/// alpha
///         X^2 , X^4 , X^8 , (X^16) , X^3 , X^5 , X^6 , X^9 , X^10 , X^12 , X^17
/// gamma, beta
/// 1 , X , X^2 , X^4 , X^8 , (X^16) ,
/// 0   1   2     3     4      5       6     7     8     9     10     11      12    <-- idx in array

static inline
void gui_vinegar_eval( uint8_t * poly, const cpoly_t * sk , const uint8_t * _vinegar )
{
	/// alpha
	memset(poly,0,BGF_SIZE*2);  /// 0 , X
	memcpy(poly+2*BGF_SIZE,(uint8_t*)(sk->alpha),BGF_SIZE*GUI_ALPHA_TERMS);

	// beta
	uint8_t vinegar[_V] __attribute__((aligned(16)));;
	for(unsigned i=0;i<_V;i++) vinegar[i] = gf2v_get_ele( _vinegar , i );

	for(unsigned i=0;i<GUI_BETA_TERMS;i++) {
		const uint8_t * ptr = sk->beta[i];
		for(int j=0;j<_V;j++) { gf2v_madd( poly+BGF_SIZE*(i+1) , ptr , vinegar[j] , BGF_SIZE ); ptr += BGF_SIZE; }
	}

	// gamma
	unsigned idx = 0;
	for(unsigned i=0;i<_V;i++) {
		for(unsigned j=0;j<=i;j++) {
			uint8_t vv = vinegar[i] & vinegar[j];
			gf2v_madd( poly , sk->gamma[idx] , vv , BGF_SIZE );
			idx++;
		}
	}

	/// field isomorphism:  GF(2)^n --> GF(2^n)
	for(unsigned i=0;i<GUI_C_TERMS;i++) {
		ISO( poly+i*BGF_SIZE , poly+i*BGF_SIZE , BGF_SIZE*8 );
	}

}




static inline
void _cpoly_eval( uint8_t *val , const uint8_t * cpoly , const uint8_t * a )
{
	uint8_t r0[BGF_SIZE] __attribute__((aligned(16)));
	memcpy( r0 , cpoly , BGF_SIZE );

	uint8_t temp[BGF_SIZE] __attribute__((aligned(16)));

	uint8_t a_linear[GUI_BETA_TERMS][BGF_SIZE];
	///memcpy( a_linear[0] , a , BGF_SIZE );
	ISO( a_linear[0] , a , BGF_SIZE*8 ); /// field isomorphism
	BGFMUL( temp , a_linear[0] , cpoly+BGF_SIZE );
	BGFADD( r0 , temp );

	unsigned idx = 2;
	for(unsigned i=1; (1<<i) <= GUI_C_DEG ;i++) {
		BGFSQU( a_linear[i] , a_linear[i-1] );
		BGFMUL( temp , a_linear[i] , cpoly+idx*BGF_SIZE );
		BGFADD( r0 , temp );
		idx++;
	}

	for(unsigned i=1; (1<<i) < GUI_C_DEG ; i++) {
		for(unsigned j=0;j<i;j++) {
			unsigned deg = (1<<i)+(1<<j);
			if( deg > GUI_C_DEG ) break;
			BGFMUL( temp , a_linear[i] , a_linear[j] );
			BGFMUL( temp , temp , cpoly+BGF_SIZE*(idx) );
			BGFADD( r0 , temp );
			idx++;
		}
	}
	///memcpy( val , r0 , BGF_SIZE );
	IVSISO( val , r0 , BGF_SIZE*8 );
}


static inline
void _gui_cpoly_to_sp_poly( unsigned * degree , uint8_t * poly , const uint8_t * c_poly )
{
	memset( poly , 0 , BGF_SIZE*(C_TERMS) );
	memcpy( poly , c_poly , 2*BGF_SIZE ); /// degree: 0, 1
	degree[0] = 0;
	degree[1] = 1;

	unsigned beta_idx = 2;
	unsigned alpha_idx = 1+GUI_BETA_TERMS;
	unsigned idx = 2;

	for(unsigned i=1; (1<<i) <= GUI_C_DEG ; i++ ) {
		/// "linear terms" , terms with degree X^2^i
		degree[idx] = (1<<i);
		memcpy( poly + idx*BGF_SIZE , c_poly + beta_idx*BGF_SIZE , BGF_SIZE );
		idx++;
		beta_idx++;

		/// "quadratic terms" , terms with degree X^(2^i + 2^j)
		for(unsigned j=0; j<i; j++ ) {
			unsigned deg = (1<<i)+(1<<j);
			if(  deg > GUI_C_DEG ) break;
			degree[idx] = deg;

			memcpy( poly + idx*BGF_SIZE , c_poly + alpha_idx*BGF_SIZE , BGF_SIZE );
			idx++;
			alpha_idx++;
		}
	}
}





#ifndef _DEBUG_GUI_
static inline
#endif
void gui_central_map( uint8_t * y , const gui_key * sk , const uint8_t * x ) {
#ifdef _DEBUG_MPKC_
	memcpy(y,x,_SEC_M_BYTE);
	return;
#endif

	const uint8_t *v = x+BGF_SIZE;
	uint8_t c_poly[BGF_SIZE*C_TERMS] __attribute__((aligned(16)));
	gui_vinegar_eval( c_poly , & sk->cpoly , v );

	_cpoly_eval( y , c_poly , x );
}






#ifndef _DEBUG_GUI_
static inline
#endif
unsigned gui_ivs_central_map( uint8_t * x , const gui_key * sk , const uint8_t * y , const uint8_t * vinegar ) {
#ifdef _DEBUG_MPKC_
	memcpy(x,y,_SEC_M_BYTE);
	return 0;
#endif
	//const uint8_t *v = x+BGF_SIZE;
	uint8_t c_poly[BGF_SIZE*C_TERMS] __attribute__((aligned(16)));
	gui_vinegar_eval( c_poly , & sk->cpoly , vinegar );
	uint8_t _y[BGF_SIZE] __attribute__((aligned(16)));
	ISO( _y , y , BGF_SIZE*8 );
	BGFADD( c_poly , _y );

	uint8_t sp_c_poly[BGF_SIZE*C_TERMS] __attribute__((aligned(16)));
	unsigned degree[C_TERMS];
	_gui_cpoly_to_sp_poly( degree , sp_c_poly , c_poly );

	uint8_t _x[BGF_SIZE] __attribute__((aligned(16)));
	unsigned ret = 0;
	ret = find_unique_root_sparse_poly( _x , sp_c_poly , degree , C_TERMS );
	///memcpy( x , _x , BGF_SIZE );
	IVSISO( x , _x , BGF_SIZE*8 );
	memcpy( x + BGF_SIZE , vinegar , _VINEGAR_BYTE );

#ifdef _DEBUG_GUI_
	uint8_t temp[BGF_SIZE] __attribute__((aligned(16)));
	_cpoly_eval( temp , c_poly , x );

	if( 1 == ret ) {
		if( !gf256v_is_zero( temp , BGF_SIZE ) ) { /// XXX:
			printf("ret succ but not zero.!!!!\n");
			return 999;
		}
		return 0;
	} else {
		if( gf256v_is_zero( temp , BGF_SIZE ) ) { /// XXX:
			printf("ret !succ but zero.!!!!\n");
			return 0;
		}
		return -1;
	}
#endif

	return (ret)? 0 : -1;
}




