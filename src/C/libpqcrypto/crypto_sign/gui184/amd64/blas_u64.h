#ifndef _BLAS_U64_H_
#define _BLAS_U64_H_

#include <stdint.h>
#include <stdio.h>

#include "gf16.h"

#include "blas_config.h"
#include "assert.h"


#ifdef  __cplusplus
extern  "C" {
#endif


//////////////////////////////////////////
/// u64 library
/////////////////////////////////////////


static inline
void _gf16v_mul_scalar_u64( uint8_t * a, uint8_t b , unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	uint64_t * a64 = (uint64_t*) a;
	for(unsigned i=0;i<_num;i++) {
		a64[i] = gf16_mul_u64(a64[i],b);
	}

	unsigned _num_b = _num_byte&0x7;
	unsigned st = _num<<3;

	uint64_t temp;
	uint8_t * ptr_p  = (uint8_t *)&temp;
	for(unsigned j=0;j<_num_b;j++) ptr_p[j] = a[st+j];
	uint64_t temp2 = gf16_mul_u64( temp , b );
	ptr_p  = (uint8_t *)&temp2;
	for(unsigned j=0;j<_num_b;j++) a[st+j] = ptr_p[j];
}

static inline
void _gf16v_madd_u64( uint8_t * accu_c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	const uint64_t * a64 = (const uint64_t*) a;
	uint64_t * c64 = (uint64_t*) accu_c;
	for(unsigned i=0;i<_num;i++) {
		c64[i] ^= gf16_mul_u64(a64[i],b);
	}

	unsigned _num_b = _num_byte&0x7;
	unsigned st = _num<<3;

	uint64_t temp;
	uint8_t * ptr_p  = (uint8_t *)&temp;
	for(unsigned j=0;j<_num_b;j++) ptr_p[j] = a[st+j];
	uint64_t temp2 = gf16_mul_u64( temp , b );
	ptr_p  = (uint8_t *)&temp2;
	for(unsigned j=0;j<_num_b;j++) accu_c[st+j] ^= ptr_p[j];
}



static inline
void _gf256v_add_u64( uint8_t * accu_c, const uint8_t * a , unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	const uint64_t * a64 = (const uint64_t*) a;
	uint64_t * c64 = (uint64_t*) accu_c;
	for(unsigned i=0;i<_num;i++) {
		c64[i] ^= a64[i];
	}
	unsigned _num_b = _num_byte&0x7;
	unsigned st = _num<<3;
	for(unsigned i=0;i<_num_b;i++) accu_c[st+i] ^= a[st+i];
}

static inline
void _gf256v_mul_scalar_u64( uint8_t *a, uint8_t b, unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	uint64_t * a64 = (uint64_t*) a;
	for(unsigned i=0;i<_num;i++) {
		a64[i] = gf256_mul_u64(a64[i],b);
	}
	uint64_t temp;
	uint8_t * ptr_p  = (uint8_t *)&temp;

	unsigned _num_b = _num_byte&0x7;
	unsigned st = _num<<3;

	for(unsigned j=0;j<_num_b;j++) ptr_p[j] = a[st+j];
	temp = gf256_mul_u64( temp , b );
	for(unsigned j=0;j<_num_b;j++) a[st+j] = ptr_p[j];
}

static inline
void _gf256v_madd_u64( uint8_t * accu_c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	const uint64_t * a64 = (const uint64_t*) a;
	uint64_t * c64 = (uint64_t*) accu_c;
	for(unsigned i=0;i<_num;i++) {
		c64[i] ^= gf256_mul_u64(a64[i],b);
	}
	uint64_t temp;
	uint8_t * ptr_p  = (uint8_t *)&temp;

	unsigned _num_b = _num_byte&0x7;
	unsigned st = _num<<3;

	for(unsigned j=0;j<_num_b;j++) ptr_p[j] = a[st+j];
	temp = gf256_mul_u64( temp , b );
	for(unsigned j=0;j<_num_b;j++) accu_c[st+j] ^= ptr_p[j];
}

static inline
void _gf256v_m0x10_add_u64( uint8_t * accu_c, const uint8_t * a , unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	const uint64_t * a64 = (const uint64_t*) a;
	uint64_t * c64 = (uint64_t*) accu_c;
	for(unsigned i=0;i<_num;i++) {
		c64[i] ^= gf256_mul_0x10_u64(a64[i]);
	}
	uint64_t temp;
	uint8_t * ptr_p  = (uint8_t *)&temp;

	unsigned _num_b = _num_byte&0x7;
	unsigned st = _num<<3;

	for(unsigned j=0;j<_num_b;j++) ptr_p[j] = a[st+j];
	temp = gf256_mul_0x10_u64( temp );
	for(unsigned j=0;j<_num_b;j++) accu_c[st+j] ^= ptr_p[j];
}





//////////////////////////////////////////
/// u32 library
/////////////////////////////////////////


static inline
void _gf16v_mul_scalar_u32( uint8_t * a, uint8_t b , unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	uint32_t * a32 = (uint32_t*) a;

	for(unsigned i=0;i<_num;i++) {
		uint64_t aa = a32[i<<1];
		aa <<= 32;
		aa |= a32[(i<<1)+1];

		uint64_t cc = gf16_mul_u64(aa,b);

		uint32_t tt2 = (uint32_t)(cc&0xffffffff);
		uint32_t tt1 = (uint32_t)(cc>>32);
		a32[i<<1] = tt1;
		a32[(i<<1)+1] = tt2;
	}
	for(unsigned i=(_num<<3);i<_num_byte;i++) a[i] = gf256_mul_gf16(a[i],b);
}

static inline
void _gf16v_madd_u32( uint8_t * accu_c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	const uint32_t * a32 = (const uint32_t*) a;
	uint32_t * c32 = (uint32_t*) accu_c;
	for(unsigned i=0;i<_num;i++) {
		uint64_t cc = c32[i<<1];
		cc <<= 32;
		cc |= c32[(i<<1)+1];

		uint64_t aa = a32[i<<1];
		aa <<= 32;
		aa |= a32[(i<<1)+1];

		cc ^= gf16_mul_u64(aa,b);

		uint32_t tt2 = (uint32_t)(cc&0xffffffff);
		uint32_t tt1 = (uint32_t)(cc>>32);
		c32[i<<1] = tt1;
		c32[(i<<1)+1] = tt2;
	}
	for(unsigned i=(_num<<3);i<_num_byte;i++) accu_c[i] ^= gf256_mul_gf16(a[i],b);
}

static inline
void _gf256v_add_u32( uint8_t * accu_c, const uint8_t * a , unsigned _num_byte ) {
	unsigned _num = _num_byte>>2;
	const uint32_t * a32 = (const uint32_t*) a;
	uint32_t * c32 = (uint32_t*) accu_c;
	for(unsigned i=0;i<_num;i++) {
		c32[i] ^= a32[i];
	}
	for(unsigned i=_num<<2;i<_num_byte;i++) accu_c[i] ^= a[i];
}

static inline
void _gf256v_mul_scalar_u32( uint8_t *a, uint8_t b, unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	uint32_t * a32 = (uint32_t*) a;

	for(unsigned i=0;i<_num;i++) {
		uint64_t aa = a32[i<<1];
		aa <<= 32;
		aa |= a32[(i<<1)+1];

		uint64_t cc = gf256_mul_u64(aa,b);

		uint32_t tt2 = (uint32_t)(cc&0xffffffff);
		uint32_t tt1 = (uint32_t)(cc>>32);
		a32[i<<1] = tt1;
		a32[(i<<1)+1] = tt2;
	}
	for(unsigned i=(_num<<3);i<_num_byte;i++) a[i] = gf256_mul(a[i],b);
}

static inline
void _gf256v_madd_u32( uint8_t * accu_c, const uint8_t * a , uint8_t b, unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	const uint32_t * a32 = (const uint32_t*) a;
	uint32_t * c32 = (uint32_t*) accu_c;
	for(unsigned i=0;i<_num;i++) {
		uint64_t cc = c32[i<<1];
		cc <<= 32;
		cc |= c32[(i<<1)+1];

		uint64_t aa = a32[i<<1];
		aa <<= 32;
		aa |= a32[(i<<1)+1];

		cc ^= gf256_mul_u64(aa,b);

		uint32_t tt2 = (uint32_t)(cc&0xffffffff);
		uint32_t tt1 = (uint32_t)(cc>>32);
		c32[i<<1] = tt1;
		c32[(i<<1)+1] = tt2;
	}
	for(unsigned i=(_num<<3);i<_num_byte;i++) accu_c[i] ^= gf256_mul(a[i],b);
}

static inline
void _gf256v_m0x10_add_u32( uint8_t * accu_c, const uint8_t * a , unsigned _num_byte ) {
	unsigned _num = _num_byte>>3;
	const uint32_t * a32 = (const uint32_t*) a;
	uint32_t * c32 = (uint32_t*) accu_c;
	for(unsigned i=0;i<_num;i++) {
		uint64_t cc = c32[i<<1];
		cc <<= 32;
		cc |= c32[(i<<1)+1];

		uint64_t aa = a32[i<<1];
		aa <<= 32;
		aa |= a32[(i<<1)+1];

		cc ^= gf256_mul_0x10_u64(aa);

		uint32_t tt2 = (uint32_t)(cc&0xffffffff);
		uint32_t tt1 = (uint32_t)(cc>>32);
		c32[i<<1] = tt1;
		c32[(i<<1)+1] = tt2;
	}
	for(unsigned i=(_num<<3);i<_num_byte;i++) accu_c[i] ^= gf256_mul_0x10(a[i]);
}






#ifdef  __cplusplus
}
#endif



#endif

