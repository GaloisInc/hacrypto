#include <stdio.h>
#include "decrypt.h"

#include "params.h"
#include "vec256.h"
#include "fft_tr.h"
#include "benes.h"
#include "util.h"
#include "fft.h"
#include "bm.h"

#include <stdint.h>

static void scaling(vec256 out[][GFBITS], vec256 inv[][GFBITS], const unsigned char *sk, vec256 *recv)
{
	int i, j;

	vec128 sk_int[ GFBITS ];
	vec256 eval[32][ GFBITS ];
	vec256 tmp[ GFBITS ];

	// computing inverses

	irr_load(sk_int, sk);

	fft(eval, sk_int);

	for (i = 0; i < 32; i++)
		vec256_sq(eval[i], eval[i]);

	vec256_copy(inv[0], eval[0]);

	for (i = 1; i < 32; i++)
		vec256_mul(inv[i], inv[i-1], eval[i]);

	vec256_inv(tmp, inv[31]);

	for (i = 30; i >= 0; i--)
	{
		vec256_mul(inv[i+1], tmp, inv[i]);
		vec256_mul(tmp, tmp, eval[i+1]);
	}

	vec256_copy(inv[0], tmp);
	
	//

	for (i = 0; i < 32; i++)
	for (j = 0; j < GFBITS; j++)
		out[i][j] = vec256_and(inv[i][j], recv[i]);
}

static void scaling_inv(vec256 out[][GFBITS], vec256 inv[][GFBITS], vec256 *recv)
{
	int i, j;

	for (i = 0; i < 32; i++)
	for (j = 0; j < GFBITS; j++)
		out[i][j] = vec256_and(inv[i][j], recv[i]);
}

static void preprocess(vec128 *recv, const unsigned char *s)
{
	int i;

	recv[0] = vec128_setbits(0);

	for (i = 1; i < 64; i++)
		recv[i] = recv[0];

	for (i = 0; i < SYND_BYTES/16; i++)
		recv[i] = load16(s + i*16);
}

static int weight(vec256 *v)
{
	int i, w = 0;

	for (i = 0; i < 32; i++)
	{
		w += __builtin_popcountll( vec256_extract(v[i], 0) );
		w += __builtin_popcountll( vec256_extract(v[i], 1) );
		w += __builtin_popcountll( vec256_extract(v[i], 2) );
		w += __builtin_popcountll( vec256_extract(v[i], 3) );
	}

	return w;
}

static uint64_t synd_cmp(vec256 *s0 , vec256 *s1)
{
	int i;
	vec256 diff;

	diff = vec256_xor(s0[0], s1[0]);

	for (i = 1; i < GFBITS; i++)
		diff = vec256_or(diff, vec256_xor(s0[i], s1[i]));
	
	return vec256_testz(diff);
}

int decrypt(unsigned char *e, const unsigned char *sk, const unsigned char *s)
{
	int i;
	
	uint16_t check_synd;
	uint16_t check_weight;

	vec256 inv[ 64 ][ GFBITS ];
	vec256 scaled[ 64 ][ GFBITS ];
	vec256 eval[ 64 ][ GFBITS ];

	vec256 error[ 32 ];

	vec256 s_priv[ GFBITS ];
	vec256 s_priv_cmp[ GFBITS ];
	vec128 locator[ GFBITS ];

	vec256 recv[ 32 ];
	vec256 allone;

	//

	preprocess((vec128*) recv, s);
	benes((vec128 *) recv, sk + IRR_BYTES, 1);

	scaling(scaled, inv, sk, recv); // scaling
	fft_tr(s_priv, scaled); // transposed FFT
	bm(locator, s_priv); // Berlekamp Massey

	fft(eval, locator); // FFT

	// reencryption and weight check

	allone = vec256_set1_16b(0xFFFF);

	for (i = 0; i < 32; i++)
	{
		error[i] = vec256_or_reduce(eval[i]);
		error[i] = vec256_xor(error[i], allone);
	}

	check_weight = weight(error) ^ SYS_T;
	check_weight -= 1;
	check_weight >>= 15;

	scaling_inv(scaled, inv, error);
	fft_tr(s_priv_cmp, scaled);

	check_synd = synd_cmp(s_priv, s_priv_cmp);

	//

	benes((vec128 *) error, sk + IRR_BYTES, 0);

	for (i = 0; i < 32; i++)
		store32(e + i*32, error[i]);

#ifdef KAT
  {
    int k;
    printf("decrypt e: positions");
    for (k = 0;k < 8192;++k)
      if (e[k/8] & (1 << (k&7)))
        printf(" %d",k);
    printf("\n");
  }
#endif

	return 1 - (check_synd & check_weight);
}

