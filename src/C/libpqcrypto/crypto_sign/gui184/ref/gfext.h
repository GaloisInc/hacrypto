#ifndef _GF_EXT_H_
#define _GF_EXT_H_


#include "gf16.h"

#include "blas.h"

#include "string.h"

#include "gfext_config.h"


#ifndef _GF_EXT_
#define _GF_EXT_ 56
#endif

#if 30 == _GF_EXT_

#define ISO identity
#define IVSISO identity
#define BGFADD gf256ext_30_xor
#define BGFMUL gf256ext_30_mul
#define BGFMUL_256  BGFMUL
#define BGFSQU gf256ext_30_squ
#define BGFINV gf256ext_30_inv
#define BGFPOW8 gf256ext_30_pow_8
#define BGFPOW16 gf256ext_30_pow_16
#define BGFPOW32 gf256ext_30_pow_32

#elif 23 == _GF_EXT_

#define ISO identity
#define IVSISO identity
#define BGFADD gf256ext_23_xor
#define BGFMUL gf256ext_23_mul
#define BGFMUL_256  BGFMUL
#define BGFSQU gf256ext_23_squ
#define BGFINV gf256ext_23_inv
#define BGFPOW8 gf256ext_23_pow_8
#define BGFPOW16 gf256ext_23_pow_16
#define BGFPOW32 gf256ext_23_pow_32

#elif 39 == _GF_EXT_

#define ISO identity
#define IVSISO identity
#define BGFADD gf256ext_39_xor
#define BGFMUL gf256ext_39_mul
#define BGFMUL_256  BGFMUL
#define BGFSQU gf256ext_39_squ
#define BGFINV gf256ext_39_inv
#define BGFPOW8 gf256ext_39_pow_8
#define BGFPOW16 gf256ext_39_pow_16
#define BGFPOW32 gf256ext_39_pow_32

#elif 56 == _GF_EXT_

#define ISO identity
#define IVSISO identity
#define BGFADD gf256ext_56_xor
#define BGFMUL gf256ext_56_mul
#define BGFMUL_256  BGFMUL
#define BGFSQU gf256ext_56_squ
#define BGFINV gf256ext_56_inv
#define BGFPOW8 gf256ext_56_pow_8
#define BGFPOW16 gf256ext_56_pow_16
#define BGFPOW32 gf256ext_56_pow_32

#else
!!! error here

#endif






#ifdef  __cplusplus
extern  "C" {
#endif


static inline void identity( uint8_t * r , const uint8_t * a , unsigned len_bit ) { memcpy(r,a,(len_bit+7)/8); }



//////////////////////  GF(256^30)   /////////////////////////


static inline
void identity_240( uint8_t * r , const uint8_t * a ) { memcpy(r,a,30); }

static inline
void gf256ext_30_xor( uint8_t * b , const uint8_t * a ) { gf256v_add( b , a , 30 ); }


///    x^30 + 0x10 x^3 + x^2 + x + 1,
static inline
void gf256ext_30_mul( uint8_t * c , const uint8_t * a , const uint8_t * b )
{
	static const unsigned W = 30;
#define W30 30
	uint8_t tmp_mul[W30*2] = {0};
	for(unsigned i=0;i<W;i++) {
		gf256v_madd( tmp_mul+i , a , b[i] , W );
		//for( unsigned j=0;j<W;j++) tmp_mul[i+j] ^= gf256_mul( a[i] , b[j] );
	}

	for(unsigned i = (W-1)*2;i>=W;i--) {
		tmp_mul[i-W+0] ^= tmp_mul[i];
		tmp_mul[i-W+1] ^= tmp_mul[i];
		tmp_mul[i-W+2] ^= tmp_mul[i];
		tmp_mul[i-W+3] ^= gf256_mul_0x10(tmp_mul[i]);
	}

	for(unsigned i=0;i<W;i++) c[i] = tmp_mul[i];
}

static inline
void gf256ext_30_squ( uint8_t * c , const uint8_t * a )
{
	static const unsigned W = 30;
	uint8_t tmp_mul[W30*2] = {0};

	for(unsigned i=0;i<W;i++) tmp_mul[i<<1] = gf256_squ( a[i] );

	for(unsigned i = (W-1)*2;i>=W;i--) {
		tmp_mul[i-W+0] ^= tmp_mul[i];
		tmp_mul[i-W+1] ^= tmp_mul[i];
		tmp_mul[i-W+2] ^= tmp_mul[i];
		tmp_mul[i-W+3] ^= gf256_mul_0x10(tmp_mul[i]);
	}

	for(unsigned i=0;i<W;i++) c[i] = tmp_mul[i];
}

static inline
void gf256ext_30_pow_2_i(uint8_t *b, unsigned i, const uint8_t * a ) {
	gf256ext_30_squ(b,a);
	for(unsigned j=1;j<i;j++) gf256ext_30_squ(b,b);
}

static inline
void gf256ext_30_pow_16( uint8_t * b , const uint8_t * a ) { gf256ext_30_pow_2_i(b,4,a); }

static inline
void gf256ext_30_pow_32( uint8_t * b , const uint8_t * a ) { gf256ext_30_pow_2_i(b,5,a); }

static inline
void gf256ext_30_pow_64( uint8_t * b , const uint8_t * a ) { gf256ext_30_pow_2_i(b,6,a); }

static inline
void gf256ext_30_pow_256_1( uint8_t * b , const uint8_t * a ) { gf256ext_30_pow_2_i(b,8,a); }


/// 256^28 - 2 = 0xFFFF .... FFFE
static inline
void gf256ext_30_inv( uint8_t * b , const uint8_t * a )
{
	static const unsigned W = 30;
	uint8_t tmp[W30] = {0};

	gf256ext_30_squ(tmp,a);
	uint8_t a3[W30]; gf256ext_30_mul(a3,tmp,a);
	gf256ext_30_squ(tmp,a3);
	gf256ext_30_squ(tmp,tmp);
	uint8_t aF[W30]; gf256ext_30_mul(aF,tmp,a3);
	gf256ext_30_squ(tmp,aF);
	gf256ext_30_squ(tmp,tmp);
	gf256ext_30_squ(tmp,tmp);
	gf256ext_30_squ(tmp,tmp);
	uint8_t aFF[W30]; gf256ext_30_mul(aFF,tmp,aF);

	memcpy( tmp , aFF , W );
	//for(unsigned i=0;i<W;i++) tmp[i]=aFF[i];
	for(unsigned i=0;i<28;i++) {
		gf256ext_30_pow_256_1(tmp,tmp);
		gf256ext_30_mul(tmp,tmp,aFF);
	}
	gf256ext_30_squ(tmp,tmp);
	gf256ext_30_squ(tmp,tmp);
	gf256ext_30_squ(tmp,tmp);
	gf256ext_30_squ(tmp,tmp);
	gf256ext_30_mul(tmp,tmp,aF);
	gf256ext_30_squ(tmp,tmp);
	gf256ext_30_squ(tmp,tmp);
	gf256ext_30_mul(tmp,tmp,a3);
	gf256ext_30_squ(tmp,tmp);
	gf256ext_30_mul(tmp,tmp,a);
	gf256ext_30_squ(b,tmp);

}







//////////////////////  GF(256^23)   /////////////////////////


static inline
void identity_184( uint8_t * r , const uint8_t * a ) { memcpy(r,a,23); }

static inline
void gf256ext_23_xor( uint8_t * b , const uint8_t * a ) { gf256v_add( b , a , 23 ); }


///    x^23 + x^3 + x + 0x2,
static inline
void gf256ext_23_mul( uint8_t * c , const uint8_t * a , const uint8_t * b )
{
	static const unsigned W = 23;
#define W23 23
	uint8_t tmp_mul[W23*2] = {0};
	for(unsigned i=0;i<W;i++) {
		gf256v_madd( tmp_mul+i , a , b[i] , W );
		//for( unsigned j=0;j<W;j++) tmp_mul[i+j] ^= gf256_mul( a[i] , b[j] );
	}

	for(unsigned i = (W-1)*2;i>=W;i--) {
		tmp_mul[i-W+0] ^= gf256_mul_0x2( tmp_mul[i] );
		tmp_mul[i-W+1] ^= tmp_mul[i];
		tmp_mul[i-W+3] ^= tmp_mul[i];
	}

	for(unsigned i=0;i<W;i++) c[i] = tmp_mul[i];
}

static inline
void gf256ext_23_squ( uint8_t * c , const uint8_t * a )
{
	static const unsigned W = 23;
	uint8_t tmp_mul[W23*2] = {0};

	for(unsigned i=0;i<W;i++) tmp_mul[i<<1] = gf256_squ( a[i] );

	/// XXX: check this
	for(unsigned i = (W-1)*2;i>=W;i-=2) {
		tmp_mul[i-W+0] ^= gf256_mul_0x2( tmp_mul[i] );
		tmp_mul[i-W+1] ^= tmp_mul[i];
		tmp_mul[i-W+3] ^= tmp_mul[i];
	}

	for(unsigned i=0;i<W;i++) c[i] = tmp_mul[i];
}

static inline
void gf256ext_23_pow_2_i(uint8_t *b, unsigned i, const uint8_t * a ) {
	gf256ext_23_squ(b,a);
	for(unsigned j=1;j<i;j++) gf256ext_23_squ(b,b);
}

static inline
void gf256ext_23_pow_16( uint8_t * b , const uint8_t * a ) { gf256ext_23_pow_2_i(b,4,a); }

static inline
void gf256ext_23_pow_32( uint8_t * b , const uint8_t * a ) { gf256ext_23_pow_2_i(b,5,a); }

static inline
void gf256ext_23_pow_64( uint8_t * b , const uint8_t * a ) { gf256ext_23_pow_2_i(b,6,a); }

static inline
void gf256ext_23_pow_256_1( uint8_t * b , const uint8_t * a ) { gf256ext_23_pow_2_i(b,8,a); }


static inline
void gf256ext_23_inv( uint8_t * b , const uint8_t * a )
{
	static const unsigned W = 23;
	uint8_t tmp[W23] = {0};

	gf256ext_23_squ(tmp,a);
	uint8_t a3[W23]; gf256ext_23_mul(a3,tmp,a);
	gf256ext_23_squ(tmp,a3);
	gf256ext_23_squ(tmp,tmp);
	uint8_t aF[W23]; gf256ext_23_mul(aF,tmp,a3);
	gf256ext_23_squ(tmp,aF);
	gf256ext_23_squ(tmp,tmp);
	gf256ext_23_squ(tmp,tmp);
	gf256ext_23_squ(tmp,tmp);
	uint8_t aFF[W23]; gf256ext_23_mul(aFF,tmp,aF);

	memcpy( tmp , aFF , W );
	//for(unsigned i=0;i<W;i++) tmp[i]=aFF[i];
	for(unsigned i=0;i<21;i++) {
		gf256ext_23_pow_256_1(tmp,tmp);
		gf256ext_23_mul(tmp,tmp,aFF);
	}
	gf256ext_23_squ(tmp,tmp);
	gf256ext_23_squ(tmp,tmp);
	gf256ext_23_squ(tmp,tmp);
	gf256ext_23_squ(tmp,tmp);
	gf256ext_23_mul(tmp,tmp,aF);
	gf256ext_23_squ(tmp,tmp);
	gf256ext_23_squ(tmp,tmp);
	gf256ext_23_mul(tmp,tmp,a3);
	gf256ext_23_squ(tmp,tmp);
	gf256ext_23_mul(tmp,tmp,a);
	gf256ext_23_squ(b,tmp);

}





//////////////////////  GF(256^39)   /////////////////////////


static inline
void identity_312( uint8_t * r , const uint8_t * a ) { memcpy(r,a,39); }

static inline
void gf256ext_39_xor( uint8_t * b , const uint8_t * a ) { gf256v_add( b , a , 39 ); }


///    x^39 + x^2 + x + 0x2,
static inline
void gf256ext_39_mul( uint8_t * c , const uint8_t * a , const uint8_t * b )
{
	static const unsigned W = 39;
#define W39 39
	uint8_t tmp_mul[W39*2] = {0};
	for(unsigned i=0;i<W;i++) {
		gf256v_madd( tmp_mul+i , a , b[i] , W );
		//for( unsigned j=0;j<W;j++) tmp_mul[i+j] ^= gf256_mul( a[i] , b[j] );
	}

	for(unsigned i = (W-1)*2;i>=W;i--) {
		tmp_mul[i-W+0] ^= gf256_mul_0x2( tmp_mul[i] );
		tmp_mul[i-W+1] ^= tmp_mul[i];
		tmp_mul[i-W+2] ^= tmp_mul[i];
	}

	for(unsigned i=0;i<W;i++) c[i] = tmp_mul[i];
}

static inline
void gf256ext_39_squ( uint8_t * c , const uint8_t * a )
{
	static const unsigned W = 39;
	uint8_t tmp_mul[W39*2] = {0};

	for(unsigned i=0;i<W;i++) tmp_mul[i<<1] = gf256_squ( a[i] );

	/// XXX: check this
	for(unsigned i = (W-1)*2;i>=W;i-=2) {
		tmp_mul[i-W+0] ^= gf256_mul_0x2( tmp_mul[i] );
		tmp_mul[i-W+1] ^= tmp_mul[i];
		tmp_mul[i-W+2] ^= tmp_mul[i];
	}
	for(unsigned i=39;i>=W;i--){
		tmp_mul[i-W+0] ^= gf256_mul_0x2( tmp_mul[i] );
		tmp_mul[i-W+1] ^= tmp_mul[i];
		tmp_mul[i-W+2] ^= tmp_mul[i];
	}

	for(unsigned i=0;i<W;i++) c[i] = tmp_mul[i];
}

static inline
void gf256ext_39_pow_2_i(uint8_t *b, unsigned i, const uint8_t * a ) {
	gf256ext_39_squ(b,a);
	for(unsigned j=1;j<i;j++) gf256ext_39_squ(b,b);
}

static inline
void gf256ext_39_pow_16( uint8_t * b , const uint8_t * a ) { gf256ext_39_pow_2_i(b,4,a); }

static inline
void gf256ext_39_pow_32( uint8_t * b , const uint8_t * a ) { gf256ext_39_pow_2_i(b,5,a); }

static inline
void gf256ext_39_pow_64( uint8_t * b , const uint8_t * a ) { gf256ext_39_pow_2_i(b,6,a); }

static inline
void gf256ext_39_pow_256_1( uint8_t * b , const uint8_t * a ) { gf256ext_39_pow_2_i(b,8,a); }


static inline
void gf256ext_39_inv( uint8_t * b , const uint8_t * a )
{
	static const unsigned W = 39;
	uint8_t tmp[W39] = {0};

	gf256ext_39_squ(tmp,a);
	uint8_t a3[W39]; gf256ext_39_mul(a3,tmp,a);
	gf256ext_39_squ(tmp,a3);
	gf256ext_39_squ(tmp,tmp);
	uint8_t aF[W39]; gf256ext_39_mul(aF,tmp,a3);
	gf256ext_39_squ(tmp,aF);
	gf256ext_39_squ(tmp,tmp);
	gf256ext_39_squ(tmp,tmp);
	gf256ext_39_squ(tmp,tmp);
	uint8_t aFF[W39]; gf256ext_39_mul(aFF,tmp,aF);

	memcpy( tmp , aFF , W );
	//for(unsigned i=0;i<W;i++) tmp[i]=aFF[i];
	for(unsigned i=0;i<37;i++) {
		gf256ext_39_pow_256_1(tmp,tmp);
		gf256ext_39_mul(tmp,tmp,aFF);
	}
	gf256ext_39_squ(tmp,tmp);
	gf256ext_39_squ(tmp,tmp);
	gf256ext_39_squ(tmp,tmp);
	gf256ext_39_squ(tmp,tmp);
	gf256ext_39_mul(tmp,tmp,aF);
	gf256ext_39_squ(tmp,tmp);
	gf256ext_39_squ(tmp,tmp);
	gf256ext_39_mul(tmp,tmp,a3);
	gf256ext_39_squ(tmp,tmp);
	gf256ext_39_mul(tmp,tmp,a);
	gf256ext_39_squ(b,tmp);

}






//////////////////////  GF(256^56)   /////////////////////////


static inline
void identity_448( uint8_t * r , const uint8_t * a ) { memcpy(r,a,56); }

static inline
void gf256ext_56_xor( uint8_t * b , const uint8_t * a ) { gf256v_add( b , a , 56 ); }


///    x^56 + 0x2 x^3 + x + 0x10,
static inline
void gf256ext_56_mul( uint8_t * c , const uint8_t * a , const uint8_t * b )
{
	static const unsigned W = 56;
#define W56 56
	uint8_t tmp_mul[W56*2] = {0};
	for(unsigned i=0;i<W;i++) {
		gf256v_madd( tmp_mul+i , a , b[i] , W );
		//for( unsigned j=0;j<W;j++) tmp_mul[i+j] ^= gf256_mul( a[i] , b[j] );
	}

	for(unsigned i = (W-1)*2;i>=W;i--) {
		tmp_mul[i-W+0] ^= gf256_mul_0x10( tmp_mul[i] );
		tmp_mul[i-W+1] ^= tmp_mul[i];
		tmp_mul[i-W+3] ^= gf256_mul_0x2( tmp_mul[i] );
	}

	for(unsigned i=0;i<W;i++) c[i] = tmp_mul[i];
}

static inline
void gf256ext_56_squ( uint8_t * c , const uint8_t * a )
{
	static const unsigned W = 56;
	uint8_t tmp_mul[W56*2] = {0};

	for(unsigned i=0;i<W;i++) tmp_mul[i<<1] = gf256_squ( a[i] );

	for(unsigned i = (W-1)*2;i>=W;i-=2) {
		tmp_mul[i-W+0] ^= gf256_mul_0x10( tmp_mul[i] );
		tmp_mul[i-W+1] ^= tmp_mul[i];
		tmp_mul[i-W+3] ^= gf256_mul_0x2( tmp_mul[i] );
	}
	for(unsigned i = 57;i>=W;i-=2) {
		tmp_mul[i-W+0] ^= gf256_mul_0x10( tmp_mul[i] );
		tmp_mul[i-W+1] ^= tmp_mul[i];
		tmp_mul[i-W+3] ^= gf256_mul_0x2( tmp_mul[i] );
	}
	for(unsigned i=0;i<W;i++) c[i] = tmp_mul[i];
}

static inline
void gf256ext_56_pow_2_i(uint8_t *b, unsigned i, const uint8_t * a ) {
	gf256ext_56_squ(b,a);
	for(unsigned j=1;j<i;j++) gf256ext_56_squ(b,b);
}

static inline
void gf256ext_56_pow_16( uint8_t * b , const uint8_t * a ) { gf256ext_56_pow_2_i(b,4,a); }

static inline
void gf256ext_56_pow_32( uint8_t * b , const uint8_t * a ) { gf256ext_56_pow_2_i(b,5,a); }

static inline
void gf256ext_56_pow_64( uint8_t * b , const uint8_t * a ) { gf256ext_56_pow_2_i(b,6,a); }

static inline
void gf256ext_56_pow_256_1( uint8_t * b , const uint8_t * a ) { gf256ext_56_pow_2_i(b,8,a); }


static inline
void gf256ext_56_inv( uint8_t * b , const uint8_t * a )
{
	static const unsigned W = 56;
	uint8_t tmp[W56] = {0};

	gf256ext_56_squ(tmp,a);
	uint8_t a3[W56]; gf256ext_56_mul(a3,tmp,a);
	gf256ext_56_squ(tmp,a3);
	gf256ext_56_squ(tmp,tmp);
	uint8_t aF[W56]; gf256ext_56_mul(aF,tmp,a3);
	gf256ext_56_squ(tmp,aF);
	gf256ext_56_squ(tmp,tmp);
	gf256ext_56_squ(tmp,tmp);
	gf256ext_56_squ(tmp,tmp);
	uint8_t aFF[W56]; gf256ext_56_mul(aFF,tmp,aF);

	memcpy( tmp , aFF , W );
	//for(unsigned i=0;i<W;i++) tmp[i]=aFF[i];
	for(unsigned i=0;i<54;i++) {
		gf256ext_56_pow_256_1(tmp,tmp);
		gf256ext_56_mul(tmp,tmp,aFF);
	}
	gf256ext_56_squ(tmp,tmp);
	gf256ext_56_squ(tmp,tmp);
	gf256ext_56_squ(tmp,tmp);
	gf256ext_56_squ(tmp,tmp);
	gf256ext_56_mul(tmp,tmp,aF);
	gf256ext_56_squ(tmp,tmp);
	gf256ext_56_squ(tmp,tmp);
	gf256ext_56_mul(tmp,tmp,a3);
	gf256ext_56_squ(tmp,tmp);
	gf256ext_56_mul(tmp,tmp,a);
	gf256ext_56_squ(b,tmp);

}






#ifdef  __cplusplus
}
#endif




#endif
