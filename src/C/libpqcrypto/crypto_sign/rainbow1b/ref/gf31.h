#ifndef _GF31_H_
#define _GF31_H_

#include <stdint.h>


#ifdef  __cplusplus
extern  "C" {
#endif

static inline unsigned char gf31_is_nonzero( unsigned char a )
{
	unsigned char a5 = (a&0x1f)-1;                                                                                                                                                 a5 = ~a5;
	return (a5>>7)&1;
}


static inline unsigned char gf31_add( unsigned char a , unsigned char b )
{
	return ((a+b)%31);
}

static inline unsigned char gf31_sub( unsigned char a , unsigned char b )
{
	return ((31+a-b)%31);
}

static inline unsigned char gf31_mul( unsigned char _a , unsigned char _b )
{

	unsigned a = _a;
	unsigned b = _b;

	return ((a*b)%31);
}

static inline unsigned char gf31_squ( unsigned char a )
{
	return gf31_mul(a,a);
}

static inline unsigned char gf31_inv( unsigned char a )
{
	unsigned char a2 = gf31_squ(a);
	unsigned char a4 = gf31_squ(a2);
	unsigned char a8 = gf31_squ(a4);
	unsigned char a16 = gf31_squ(a8);

	unsigned char r0 = gf31_mul(a16,a8);
	unsigned char r1 = gf31_mul(a4,a);
	return gf31_mul(r0,r1);
}


#ifdef  __cplusplus
}
#endif


#endif
