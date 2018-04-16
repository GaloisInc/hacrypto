

#include "blas.h"

#include "gui_config.h"

//#define NDEBUG
#include "assert.h"


#include "gfext_poly_gf2.h"


#define _GFSIZE  GUI_BGF_SIZE
#define _DEG  GUI_C_DEG
#define _MAX_TERMS (((_DEG+7)/8)*8)


#define _GF_EXT_ _GFSIZE

#include "gfext.h"

#define _TERMS (_DEG+1)
#define _DEG_1 (_DEG-1)




///////////////////////////////////
/// tool functions for polynomails
///////////////////////////////////


#ifndef _DEBUG_GFEXT_POLY_
static inline
#endif
void poly_eval( uint8_t *val , const uint8_t * poly , unsigned deg , const uint8_t * a )
{
	assert( deg < _MAX_TERMS );

	uint8_t a_deg[_MAX_TERMS*_GFSIZE] __attribute__((aligned(16))) = {0};
	memcpy( a_deg + _GFSIZE , a , _GFSIZE );
	for(unsigned i=2;i<=deg;i++) BGFMUL( a_deg + i*_GFSIZE , a_deg + (i-1)*_GFSIZE , a );

	memcpy(val,poly,_GFSIZE);
	uint8_t temp[_GFSIZE] __attribute__((aligned(16)));
	for(unsigned i=1;i<=deg;i++) {
		BGFMUL( temp , a_deg + i*_GFSIZE , poly + i*_GFSIZE );
		gf256v_add( val , temp , _GFSIZE );
	}
}


#ifndef _DEBUG_GFEXT_POLY_
static inline
#endif
void poly_fdump(FILE *fp, const uint8_t *poly, unsigned deg ){
	for(unsigned i=deg+1;i!=0;i--){
		gf256v_fdump(fp,poly+(i-1)*_GFSIZE,_GFSIZE);
		fprintf(fp,"X(%d)\n",i-1);
		if(1!=i) fprintf(fp,"+");
	}
}


#ifndef _DEBUG_GFEXT_POLY_
static inline
#endif
void poly_normalize( uint8_t * rp , const uint8_t * p , unsigned deg )
{

	uint8_t temp[_GFSIZE] __attribute__((aligned(16)));
	/// normalize
	BGFINV( temp , p + deg*_GFSIZE );
	for( unsigned i=0;i<deg;i++) {
		BGFMUL( rp + i*_GFSIZE , p + i*_GFSIZE , temp );
	}
	memset( rp + deg*_GFSIZE , 0 , _GFSIZE );
	rp[deg*_GFSIZE] = 1;
}


static inline void poly_mul( uint8_t *p3, const uint8_t *p1 , unsigned deg , const uint8_t *c )
{
	for(unsigned i=0;i<=deg;i++) BGFMUL(p3+i*_GFSIZE,p1+i*_GFSIZE,c);
}

static inline void poly_muladd( uint8_t *p3, const uint8_t *p1 , unsigned p1deg , unsigned p1raise , const uint8_t *c )
{
	uint8_t tmp[_GFSIZE] __attribute__((aligned(16)));
	for(unsigned i=0;i<=p1deg;i++) {
		BGFMUL(tmp,p1+i*_GFSIZE,c);
		gf256v_add( p3+(i+p1raise)*_GFSIZE , tmp , _GFSIZE );
	}
}

static inline void poly_add( uint8_t *p3, const uint8_t *p1 , unsigned p1deg , unsigned p1raise )
{
	gf256v_add( p3 + p1raise*_GFSIZE , p1 , (p1deg+1)*_GFSIZE );
}



///////////////////////////////////////////////
/// tool functions for sparse polynomails
///////////////////////////////////////////////


static inline void poly_muladd_sp_poly( uint8_t * poly , const uint8_t * sparse_poly , const unsigned * degree , unsigned n_sp_terms , unsigned sp_raise ,
		const uint8_t * c )
{
	uint8_t tmp[_GFSIZE] __attribute__((aligned(16)));
	for(unsigned i=0;i<n_sp_terms;i++) {
		BGFMUL(tmp,sparse_poly+i*_GFSIZE,c);
		gf256v_add( poly + (degree[i]+sp_raise)*_GFSIZE , tmp , _GFSIZE );
	}
}

static inline void poly_add_sp_poly( uint8_t * poly , const uint8_t * sparse_poly , const unsigned * degree , unsigned n_sp_terms , unsigned sp_raise )
{
	for(unsigned i=0;i<n_sp_terms;i++) {
		gf256v_add( poly + (degree[i]+sp_raise)*_GFSIZE , sparse_poly + i*_GFSIZE , _GFSIZE );
	}
}

/// normalized sparse polynomial
static inline void poly_mod_nsp_poly( uint8_t * poly , unsigned deg_poly , const uint8_t * nsp_poly , const unsigned * degree , unsigned nsp_terms )
{
       unsigned sp_max_deg = degree[nsp_terms-1];
       for(unsigned i=deg_poly;i>=sp_max_deg;i--) {
               uint8_t * term = poly + i*_GFSIZE;
               poly_muladd_sp_poly( poly + (i-sp_max_deg)*_GFSIZE, nsp_poly , degree , nsp_terms-1 ,0 , term );
       }
}


/// normalized sparse polynomial
static inline void poly_square_mod_nsp_poly( uint8_t * rpoly , const uint8_t * poly , unsigned deg_poly ,
                                       const uint8_t * nsp_poly , const unsigned * degree , unsigned nsp_terms )
{
       BGFSQU(rpoly,poly);
       for(unsigned i=1;i<=deg_poly;i++) {
               gf256v_add( rpoly+(i*2-1)*_GFSIZE , rpoly+(i*2-1)*_GFSIZE , _GFSIZE );
               BGFSQU(rpoly+(i*2)*_GFSIZE,poly+i*_GFSIZE);
       }

       poly_mod_nsp_poly( rpoly , deg_poly*2 , nsp_poly , degree , nsp_terms );
}




/////////////////////////  Polynomial GCD   ///////////////////////



#ifndef _DEBUG_GFEXT_POLY_
static inline
#endif
unsigned _get_deg1poly_gcd( uint8_t * gcd , const uint8_t * p1 , const uint8_t * p2 , unsigned deg )
{
	uint8_t buf1[_GFSIZE*_MAX_TERMS] __attribute__((aligned(16)));
	uint8_t buf2[_GFSIZE*_MAX_TERMS] __attribute__((aligned(16)));

	memcpy( buf1 , p1 , (deg+1)*_GFSIZE );
	memcpy( buf2 , p2 , (deg+1)*_GFSIZE );
	uint8_t h1[_GFSIZE] __attribute__((aligned(16)));
	uint8_t h2[_GFSIZE] __attribute__((aligned(16)));

	for(unsigned d=deg;d>=1;d--){
		memcpy(h1,buf1+d*_GFSIZE,_GFSIZE);
		memcpy(h2,buf2+d*_GFSIZE,_GFSIZE);
		poly_mul(buf1,buf1,d,h2);
		poly_mul(buf2,buf2,d,h1);
		poly_add(buf1,buf2,d,0);
		if(1==d) break;
		memcpy(h1,buf1+(d-1)*_GFSIZE,_GFSIZE);
		memcpy(h2,buf2+d*_GFSIZE,_GFSIZE);
		poly_mul(buf1,buf1,d-1,h2);
		poly_mul(buf2,buf2,d,h1);
		poly_add(buf2,buf1,d-1,1); /// here. deal with ht of buf2 for success check.
	}
	memcpy(gcd,buf2,2*_GFSIZE);
	unsigned succ1 = gf256v_is_zero(buf1,2*_GFSIZE);
	unsigned succ2 = gf256v_is_zero(buf2+2*_GFSIZE,_GFSIZE);
	unsigned succ3 = (gf256v_is_zero(buf2,_GFSIZE))?0:1;
	unsigned succ4 = (gf256v_is_zero(buf2+_GFSIZE,_GFSIZE))?0:1;
	return succ1&succ2&succ3&succ4;
}


////////////////////////////////////////////////////////////////
/// extend X to the power for field size in a polynomial ring
////////////////////////////////////////////////////////////////


#if _DEG > 130
#define _SPARSE_POLY_REDUCE_
#endif

#if defined( _SPARSE_POLY_REDUCE_ )

//static inline void poly_mod_nsp_poly( uint8_t * poly , unsigned deg_poly , const uint8_t * nsp_poly , const unsigned * degree , unsigned nsp_terms )
/// normalized sparse polynomial
//static inline void poly_square_mod_nsp_poly( uint8_t * rpoly , const uint8_t * poly , unsigned deg_poly ,
//                                        const uint8_t * nsp_poly , const unsigned * degree , unsigned nsp_terms )

static
void Calc_X_to_2_to_pow_in_ideal( uint8_t * Xext_X , unsigned pow , const uint8_t * nor_sparse_poly , const unsigned * degree , unsigned n_sp_terms )
{

       uint8_t * buf1 = (uint8_t *) malloc( _DEG*_GFSIZE*2 );
       uint8_t * buf2 = (uint8_t *) malloc( _DEG*_GFSIZE*2 );

       memset( buf1 , 0 , _DEG*_GFSIZE*2 );
       unsigned st_deg = 0;
       while( (1<<st_deg)<=_DEG ) st_deg++;
       buf1[(1<<st_deg)*_GFSIZE] = 1;
       poly_mod_nsp_poly( buf1 , 1<<st_deg , nor_sparse_poly , degree , n_sp_terms );

       uint8_t * ptr1 = buf1;
       uint8_t * ptr2 = buf2;
       for(unsigned i= st_deg;i<pow;i++) {
               poly_square_mod_nsp_poly( ptr2 , ptr1 , _DEG_1 , nor_sparse_poly , degree , n_sp_terms );
               uint8_t * ptr_tmp=ptr1;
               ptr1=ptr2;
               ptr2=ptr_tmp;
       }
       memcpy( Xext_X , ptr1 , _GFSIZE*_DEG );

       // clean
       free( buf1 );
       free( buf2 );
}


#else


#if defined( _GUI_2_184_D33_V16_A16_K2 )
#define _STEP 4
#elif defined( _GUI_2_312_D129_V20_A24_K2 )
#define _STEP 6
#elif defined( _GUI_2_448_D513_V28_A32_K2 )
#define _STEP 7
#else
error.
#endif

//#if defined( _STEP )

static inline
void _generate_squ_table( uint8_t * X_squ[] , const uint8_t * nor_sparse_poly , const unsigned * degree , unsigned n_sp_terms )
{
	unsigned i=0;
	for( ;i*(1<<_STEP) < _DEG;i++ ) { ; }

	uint8_t * temp1 = (uint8_t*)malloc( _GFSIZE*(_DEG+(1<<_STEP)) );
	uint8_t * temp2 = (uint8_t*)malloc( _GFSIZE*(_DEG+(1<<_STEP)) );
	memset( temp2 , 0 , _GFSIZE*(_DEG+(1<<_STEP)) );
	if( 0 == i ) { temp2[0] = 1; }
	else { temp2[ (i-1)*(1<<_STEP)*_GFSIZE] = 1; }

	for(;i<_DEG;i++) {
		memset( temp1 , 0 , _GFSIZE*(1<<_STEP) );
		memcpy( temp1 + _GFSIZE*(1<<_STEP) , temp2 , _GFSIZE*_DEG );

		for(unsigned j=0;j<(1<<_STEP);j++) {
			poly_muladd_sp_poly( temp1 , nor_sparse_poly , degree , n_sp_terms - 1 , (1<<_STEP)-1-j , temp1 + _GFSIZE*(_DEG+((1<<_STEP)-1-j)) );
		}

		X_squ[i] = (uint8_t*)malloc(_GFSIZE*_DEG);
		memcpy( X_squ[i] , temp1 , _GFSIZE*_DEG );

		uint8_t * tmp_ptr = temp1;
		temp1 = temp2;
		temp2 = tmp_ptr;
	}
	free( temp1 );
	free( temp2 );
}


static
void _poly_squ_in_ideal( uint8_t * p2 , const uint8_t * p1 , const uint8_t **squ_tab )
{
	memset( p2 , 0 , _GFSIZE*_DEG );
	unsigned i=0;
	for( ;i*(1<<_STEP) < _DEG; i++ ) {
		BGFSQU( &p2[(i*(1<<_STEP))*_GFSIZE] , &p1[i*_GFSIZE] ); /// constant
		for(unsigned j=1;j<_STEP;j++) {
			BGFSQU( &p2[(i*(1<<_STEP))*_GFSIZE] , &p2[(i*(1<<_STEP))*_GFSIZE] ); /// constant
		}
	}

	uint8_t temp[_GFSIZE] __attribute__((aligned(16)));
	for(;i<_DEG;i++) {
		BGFSQU( temp , p1+i*_GFSIZE );
		for(unsigned j=1;j<_STEP;j++) {
			BGFSQU( temp , temp );
		}
		poly_muladd( p2 , squ_tab[i] , _DEG_1 , 0 , temp );
	}
}


static
void Calc_X_to_2_to_pow_in_ideal( uint8_t * Xext_X , unsigned pow , const uint8_t * nor_sparse_poly , const unsigned * degree , unsigned n_sp_terms )
{
	assert( 3 <= pow );

	uint8_t ** squ_tab = (uint8_t **) malloc( sizeof(uint8_t*)* (_DEG) );
	for(unsigned i=0;i<_DEG;i++) squ_tab[i] = NULL;

	_generate_squ_table( squ_tab , nor_sparse_poly , degree , n_sp_terms );

	uint8_t * buf1 = (uint8_t *) malloc( _DEG*_GFSIZE );
	uint8_t * buf2 = (uint8_t *) malloc( _DEG*_GFSIZE );

	unsigned start_2_pow = 0;
	for( ; _DEG > (1<<(start_2_pow+_STEP)) ; start_2_pow+=_STEP ) {;}
#if 0==(_EXT%_STEP)
	memcpy( buf1 , squ_tab[(1<<start_2_pow)] , _DEG*_GFSIZE );
	start_2_pow += _STEP;
#else
	memcpy( buf1 , squ_tab[1<<(_EXT%_STEP)] , _DEG*_GFSIZE );
	start_2_pow = _STEP + (_EXT%_STEP);
#endif

	uint8_t * ptr1 = buf1;
	uint8_t * ptr2 = buf2;
	for(unsigned i= start_2_pow;i<pow;i+=_STEP) {
		_poly_squ_in_ideal( ptr2 , ptr1 , (const uint8_t **) squ_tab );
		uint8_t * ptr_tmp=ptr1;
		ptr1=ptr2;
		ptr2=ptr_tmp;
	}
	memcpy( Xext_X , ptr1 , _GFSIZE*_DEG );

	// clean
	free( buf1 );
	free( buf2 );
	for(unsigned i=0;i<_DEG;i++) {
		if( NULL != squ_tab[i] ) free( squ_tab[i] );
	}
	free( squ_tab );
}


#endif   /// definned( _SPARSE_POLY_REDUCE_ )



///////////////////////////////////////////////////////


unsigned find_unique_root_sparse_poly( uint8_t * root , const uint8_t * sparse_poly , const unsigned * degree , unsigned n_sp_terms )
{

	uint8_t ncpoly[ _TERMS*_GFSIZE] __attribute__((aligned(16)));
	poly_normalize( ncpoly , sparse_poly , n_sp_terms - 1 );

	uint8_t Xext_X[_DEG*_GFSIZE] __attribute__((aligned(16)));
	Calc_X_to_2_to_pow_in_ideal( Xext_X , _GFSIZE*8 , ncpoly , degree , n_sp_terms );
	Xext_X[_GFSIZE] ^= 1;  /// X^2^ext ``+ X''

	/// GCD start:
	/// residue_poly = 1X^deg + ....
	/// Xext_X = ?X^(deg-1) + .....

	uint8_t residue_poly[_TERMS*_GFSIZE] __attribute__((aligned(16))) = {0};
	poly_add_sp_poly( residue_poly , ncpoly , degree , n_sp_terms , 0 );
	poly_mul( residue_poly , residue_poly , _DEG_1 , Xext_X+_DEG_1*_GFSIZE ); /// omit the term of max degree
	poly_add( residue_poly , Xext_X , _DEG_1 , 1 );

	uint8_t deg1_poly[2*_GFSIZE] __attribute__((aligned(16)));
	unsigned r = _get_deg1poly_gcd( deg1_poly , residue_poly , Xext_X , _DEG_1 );

	uint8_t temp[_GFSIZE] __attribute__((aligned(16)));
	BGFINV( temp , deg1_poly + _GFSIZE );
	BGFMUL( root , temp , deg1_poly );

	return r;
}


//////////////////////////////////////////////////////////////







