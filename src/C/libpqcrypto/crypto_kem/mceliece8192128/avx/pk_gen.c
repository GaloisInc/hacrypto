#include "pk_gen.h"

#include "params.h"
#include "vec256.h"
#include "benes.h"
#include "util.h"
#include "fft.h"
#include "gf.h"

#include <stdint.h>

typedef union
{
	vec256 d256[ GFBITS * SYS_T ][ 32 ];
	uint64_t d64[ GFBITS * SYS_T ][ 128 ];
} mat;

int pk_gen(unsigned char * pk, const unsigned char * sk)
{
	int i, j, k;
	int row, c;

	mat m;
	vec256 (* mat256)[32] = m.d256;
	uint64_t (* mat)[128] = m.d64;

	uint64_t mask;	

	vec128 sk_int[ GFBITS ];

	u256 consts[ 32 ][ GFBITS ] = 
	{
#include "points13.data"
	};

	vec256 eval[ 32 ][ GFBITS ];
	vec256 prod[ 32 ][ GFBITS ];
	vec256 tmp[ GFBITS ];

	// compute the inverses 

	irr_load(sk_int, sk);

	fft(eval, sk_int);

	vec256_copy(prod[0], eval[0]);

	for (i = 1; i < 32; i++)
		vec256_mul(prod[i], prod[i-1], eval[i]);

	vec256_inv(tmp, prod[31]);

	for (i = 30; i >= 0; i--)
	{
		vec256_mul(prod[i+1], prod[i], tmp);
		vec256_mul(tmp, tmp, eval[i+1]);
	}

	vec256_copy(prod[0], tmp);

	// fill matrix 

	for (j = 0; j < 32; j++)
	{
		for (k = 0; k < GFBITS; k++)
			mat256[ k ][ j ] = prod[ j ][ k ];
	}

	for (i = 1; i < SYS_T; i++)
	{
		for (j = 0; j < 32; j++)
		{
			vec256_mul(prod[j], prod[j], (vec256 *) consts[j]);

			for (k = 0; k < GFBITS; k++)
				mat256[ i*GFBITS + k ][ j ] = prod[ j ][ k ];
		}
	}

	// permute

	for (i = 0; i < GFBITS * SYS_T; i++)
		benes((vec128 *) mat[ i ], sk + IRR_BYTES, 0);

	// gaussian elimination 

	for (i = 0; i < (GFBITS * SYS_T) / 64; i++)
	for (j = 0; j < 64; j++)
	{
		row = i*64 + j;			

		for (k = row + 1; k < GFBITS * SYS_T; k++)
		{
			mask = mat[ row ][ i ] >> j;
			mask &= 1;
			mask -= 1;

			for (c = i; c < 128; c++)
				mat[ row ][ c ] ^= mat[ k ][ c ] & mask;
		}

		if ( ((mat[ row ][ i ] >> j) & 1) == 0 ) // return if not invertible 
		{
			return -1;
		}

		for (k = 0; k < GFBITS * SYS_T; k++)
		{
			if (k != row)
			{
				mask = mat[ k ][ i ] >> j;
				mask &= 1;
				mask = -mask;

				for (c = i; c < 128; c++)
					mat[ k ][ c ] ^= mat[ row ][ c ] & mask;
			}
		}
	}

	// store pk

	for (i = 0; i < GFBITS * SYS_T; i++)
	{
		for (j = (GFBITS * SYS_T) / 64; j < 128; j++)
		{
			store8(pk, mat[i][j]);

			pk += 8;		
		}
	}

	return 0;
}

