
#include "gf31_convert.h"

int gf31_sanity_check( const unsigned char * gf31v , unsigned n )
{
	int r = 0;
	for(unsigned i=0;i<n;i++) {
		r += ((gf31v[i]>30)?1:0);
	}
	return r;
}


int gf31_quick_pack( unsigned char * pack_bitstring , const unsigned char * gf31v , unsigned n_gf31 )
{
	int r = 0;
	union a{
	unsigned u32;
	unsigned char u8[4];
	} b;

	while( 2 < n_gf31 ) {
		b.u32 = gf31v[2];
		b.u32 <<= 5;
		b.u32 |= gf31v[1];
		b.u32 <<= 5;
		b.u32 |= gf31v[0];
		pack_bitstring[r] = b.u8[0];
		pack_bitstring[r+1] = b.u8[1];

		r += 2;
		gf31v += 3;
		n_gf31 -= 3;
	}
	while( n_gf31 ) {
		pack_bitstring[r] = gf31v[0];

		r++;
		n_gf31--;
		gf31v += 1;
	}
	return r;
}

int gf31_quick_unpack( unsigned char * gf31v , const unsigned char * pack_bitstring , unsigned n_gf31 )
{
	int r = 0;
	union a{
	unsigned u32;
	unsigned char u8[4];
	} b;
	b.u32 = 0;

	while( 2 < n_gf31 ) {
		b.u8[0] = pack_bitstring[r];
		b.u8[1] = pack_bitstring[r+1];

		gf31v[0] = b.u32&0x1f;
		b.u32 >>= 5;
		gf31v[1] = b.u32&0x1f;
		b.u32 >>= 5;
		gf31v[2] = b.u32;

		r += 2;
		gf31v += 3;
		n_gf31 -= 3;
	}
	while( n_gf31 ) {
		gf31v[0] = pack_bitstring[r];

		r++;
		n_gf31--;
		gf31v += 1;
	}
	return r;
}


int gf31_from_digest( unsigned char * gf31v , const unsigned char * digest , unsigned n_gf31 )
{
	int r = 0;
	union a{
	unsigned u32;
	unsigned char u8[4];
	} b;

	b.u32 = 0;
	while( 4 < n_gf31 ) {
		b.u8[0] = digest[r];
		b.u8[1] = digest[r+1];
		b.u8[2] = digest[r+2];

		for(unsigned i=0;i<4;i++) {
			gf31v[i] = (b.u32%31);
			b.u32 /= 31;
		}
		gf31v[4] = b.u32;

		r += 3;
		gf31v += 5;
		n_gf31 -= 5;
	}
	while( 2 <= n_gf31 ) {
		b.u8[0] = digest[r];
		gf31v[0] = b.u8[0]&0xf;
		gf31v[1] = b.u8[0]>>4;

		r++;
		n_gf31-=2;
		gf31v += 2;
	}
	while( n_gf31 ) {
		gf31v[0] = digest[r]&0xf;

		r++;
		n_gf31--;
		gf31v += 1;
	}

	return r;
}

