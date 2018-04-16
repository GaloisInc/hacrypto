
#include "fft.h"

#include "transpose.h"
#include "vec256.h"

#include <stdint.h>

static void radix_conversions(vec128 *in)
{
	int i, j, k;
	vec128 t;
	uint64_t v0, v1;

	const u128 mask[5][2] = 
	{
		{{{0x8888888888888888, 0x8888888888888888}},
		 {{0x4444444444444444, 0x4444444444444444}}},
		{{{0xC0C0C0C0C0C0C0C0, 0xC0C0C0C0C0C0C0C0}},
		 {{0x3030303030303030, 0x3030303030303030}}},
		{{{0xF000F000F000F000, 0xF000F000F000F000}},
		 {{0x0F000F000F000F00, 0x0F000F000F000F00}}},
		{{{0xFF000000FF000000, 0xFF000000FF000000}},
		 {{0x00FF000000FF0000, 0x00FF000000FF0000}}},
		{{{0xFFFF000000000000, 0xFFFF000000000000}},
		 {{0x0000FFFF00000000, 0x0000FFFF00000000}}}
	};

	const u128 s[5][GFBITS] = 
	{
#include "scalars13_2x.data"
	};
	
	//

	for (j = 0; j <= 5; j++)
	{
		for (i = 0; i < GFBITS; i++)
		{
			v1 = vec128_extract(in[i], 1); 
			v1 ^= v1 >> 32;
			v0 = vec128_extract(in[i], 0); 
			v0 ^= v1 << 32;
			in[i] = vec128_set2x(v0, v1);
		}

		for (i = 0; i < GFBITS; i++)
		for (k = 4; k >= j; k--)
		{
			t = vec128_and(in[i], mask[k][0].v);
			t = vec128_srl_2x(t, 1 << k);
			in[i] = vec128_xor(in[i], t);

			t = vec128_and(in[i], mask[k][1].v);
			t = vec128_srl_2x(t, 1 << k);
			in[i] = vec128_xor(in[i], t);
		}

		if (j < 5)
			vec128_mul(in, in, (vec128 *) s[j]); // scaling
	}
}

static void butterflies(vec256 out[][ GFBITS ], vec128 *in)
{
	int i, j, k, s, b;

	vec128 tmp[ GFBITS ];
	vec256 tmp0[ GFBITS ];
	vec256 tmp1[ GFBITS ];
	vec128 t[ GFBITS ];
	vec128 pre[8][ GFBITS ];
	vec128 buf[64];

	uint64_t v0, v1;

	u256 consts128[ GFBITS ] =
	{
		{{{{0XA55A5AA55AA5A55A, 0XA55A5AA55AA5A55A}}, {{0XA55A5AA55AA5A55A, 0XA55A5AA55AA5A55A}}}},
		{{{{0X6969696996969696, 0X6969696996969696}}, {{0X6969696996969696, 0X6969696996969696}}}},
		{{{{0X5AA55AA5A55AA55A, 0X5AA55AA5A55AA55A}}, {{0X5AA55AA5A55AA55A, 0X5AA55AA5A55AA55A}}}},
		{{{{0X9999999966666666, 0X6666666699999999}}, {{0X9999999966666666, 0X6666666699999999}}}},
		{{{{0X3C3CC3C3C3C33C3C, 0XC3C33C3C3C3CC3C3}}, {{0X3C3CC3C3C3C33C3C, 0XC3C33C3C3C3CC3C3}}}},
		{{{{0XFFFF0000FFFF0000, 0X0000FFFF0000FFFF}}, {{0XFFFF0000FFFF0000, 0X0000FFFF0000FFFF}}}},
		{{{{0X0000000000000000, 0X0000000000000000}}, {{0X0000000000000000, 0X0000000000000000}}}},
		{{{{0XCC33CC3333CC33CC, 0X33CC33CCCC33CC33}}, {{0XCC33CC3333CC33CC, 0X33CC33CCCC33CC33}}}},
		{{{{0X0000000000000000, 0X0000000000000000}}, {{0X0000000000000000, 0X0000000000000000}}}},
		{{{{0X3C3C3C3C3C3C3C3C, 0X3C3C3C3C3C3C3C3C}}, {{0X3C3C3C3C3C3C3C3C, 0X3C3C3C3C3C3C3C3C}}}},
		{{{{0XAA5555AAAA5555AA, 0XAA5555AAAA5555AA}}, {{0XAA5555AAAA5555AA, 0XAA5555AAAA5555AA}}}},
		{{{{0XC33C3CC33CC3C33C, 0XC33C3CC33CC3C33C}}, {{0XC33C3CC33CC3C33C, 0XC33C3CC33CC3C33C}}}},
		{{{{0X00FFFF0000FFFF00, 0XFF0000FFFF0000FF}}, {{0X00FFFF0000FFFF00, 0XFF0000FFFF0000FF}}}}
	};

	u256 consts[ 31 ][ GFBITS ] =
	{
#include "consts13.data"
	};

	u256 powers[ 32 ][ GFBITS ] =
	{
#include "powers13.data"
	};

	uint64_t consts_ptr = 0;

	const unsigned char reversal[64] = 
	{ 
	  0, 32, 16, 48,  8, 40, 24, 56, 
	  4, 36, 20, 52, 12, 44, 28, 60, 
	  2, 34, 18, 50, 10, 42, 26, 58, 
	  6, 38, 22, 54, 14, 46, 30, 62, 
	  1, 33, 17, 49,  9, 41, 25, 57, 
	  5, 37, 21, 53, 13, 45, 29, 61, 
	  3, 35, 19, 51, 11, 43, 27, 59, 
	  7, 39, 23, 55, 15, 47, 31, 63
	};

	const uint16_t beta[8] = {2522, 7827, 7801, 8035, 6897, 8167, 3476, 0};

	// boradcast

	for (j = 0; j < GFBITS; j++)
		t[j] = vec128_unpack_high(in[j], in[j]);

	for (i = 0; i < 8; i+=2)
	{
		for (j = 0; j < GFBITS; j++)
		{
			v0 = (beta[i+0] >> j) & 1; v0 = -v0;
			v1 = (beta[i+1] >> j) & 1; v1 = -v1;

			tmp[j] = vec128_set2x(v0, v1);
		}

		vec128_mul(tmp, t, tmp);

		for (j = 0; j < GFBITS; j++)
		{
			pre[i+0][j] = vec128_unpack_low(tmp[j], tmp[j]);
			pre[i+1][j] = vec128_unpack_high(tmp[j], tmp[j]);
		}
	}

	for (i = 0; i < GFBITS; i++)
	{
		buf[0] = vec128_set2x(vec128_extract(in[i], 0), 
                                      vec128_extract(in[i], 0) ^ vec128_extract(pre[6][i], 0));

#define xor vec128_xor

		buf[1] = xor(buf[0], pre[0][i]);    buf[16] = xor(buf[0], pre[4][i]);
		buf[3] = xor(buf[1], pre[1][i]);    buf[48] = xor(buf[16], pre[5][i]);
                                                    buf[49] = xor(buf[48], pre[0][i]);
		buf[2] = xor(buf[0], pre[1][i]);    buf[51] = xor(buf[49], pre[1][i]);
		buf[6] = xor(buf[2], pre[2][i]);    buf[50] = xor(buf[51], pre[0][i]);
		buf[7] = xor(buf[6], pre[0][i]);    buf[54] = xor(buf[50], pre[2][i]);
		buf[5] = xor(buf[7], pre[1][i]);    buf[55] = xor(buf[54], pre[0][i]);
                                                    buf[53] = xor(buf[55], pre[1][i]);
		buf[4] = xor(buf[0], pre[2][i]);    buf[52] = xor(buf[53], pre[0][i]);
		buf[12] = xor(buf[4], pre[3][i]);   buf[60] = xor(buf[52], pre[3][i]);
		buf[13] = xor(buf[12], pre[0][i]);  buf[61] = xor(buf[60], pre[0][i]);
		buf[15] = xor(buf[13], pre[1][i]);  buf[63] = xor(buf[61], pre[1][i]);
		buf[14] = xor(buf[15], pre[0][i]);  buf[62] = xor(buf[63], pre[0][i]);
		buf[10] = xor(buf[14], pre[2][i]);  buf[58] = xor(buf[62], pre[2][i]);
		buf[11] = xor(buf[10], pre[0][i]);  buf[59] = xor(buf[58], pre[0][i]);
		buf[9] = xor(buf[11], pre[1][i]);   buf[57] = xor(buf[59], pre[1][i]);
                                                    buf[56] = xor(buf[57], pre[0][i]);
		buf[8] = xor(buf[0], pre[3][i]);    buf[40] = xor(buf[56], pre[4][i]);
		buf[24] = xor(buf[8], pre[4][i]);   buf[41] = xor(buf[40], pre[0][i]);
		buf[25] = xor(buf[24], pre[0][i]);  buf[43] = xor(buf[41], pre[1][i]);
		buf[27] = xor(buf[25], pre[1][i]);  buf[42] = xor(buf[43], pre[0][i]);
		buf[26] = xor(buf[27], pre[0][i]);  buf[46] = xor(buf[42], pre[2][i]);
		buf[30] = xor(buf[26], pre[2][i]);  buf[47] = xor(buf[46], pre[0][i]);
		buf[31] = xor(buf[30], pre[0][i]);  buf[45] = xor(buf[47], pre[1][i]);
		buf[29] = xor(buf[31], pre[1][i]);  buf[44] = xor(buf[45], pre[0][i]);
		buf[28] = xor(buf[29], pre[0][i]);  buf[36] = xor(buf[44], pre[3][i]);
		buf[20] = xor(buf[28], pre[3][i]);  buf[37] = xor(buf[36], pre[0][i]);
		buf[21] = xor(buf[20], pre[0][i]);  buf[39] = xor(buf[37], pre[1][i]);
		buf[23] = xor(buf[21], pre[1][i]);  buf[38] = xor(buf[39], pre[0][i]);
		buf[22] = xor(buf[23], pre[0][i]);  buf[34] = xor(buf[38], pre[2][i]);
		buf[18] = xor(buf[22], pre[2][i]);  buf[35] = xor(buf[34], pre[0][i]);
		buf[19] = xor(buf[18], pre[0][i]);  buf[33] = xor(buf[35], pre[1][i]);
		buf[17] = xor(buf[19], pre[1][i]);  buf[32] = xor(buf[33], pre[0][i]);

#undef xor

		// transpose

		transpose_64x128_sp(buf);
	
		for (j = 0; j < 32; j++)
		{
			out[j][i] = vec256_set4x ( vec128_extract(buf[ reversal[2*j+0] ], 0), 
			                           vec128_extract(buf[ reversal[2*j+0] ], 1), 
			                           vec128_extract(buf[ reversal[2*j+1] ], 0), 
			                           vec128_extract(buf[ reversal[2*j+1] ], 1)  );
		}
	}

	// butterflies

	for (k = 0; k < 32; k+=2)
	{
		for (b = 0; b < GFBITS; b++) tmp0[b] = vec256_unpack_low (out[k][b], out[k+1][b]);
		for (b = 0; b < GFBITS; b++) tmp1[b] = vec256_unpack_high (out[k][b], out[k+1][b]); 

		vec256_maa_asm(tmp0, tmp1, (vec256 *) consts128);

		for (b = 0; b < GFBITS; b++) out[k][b] = vec256_unpack_low (tmp0[b], tmp1[b]);
		for (b = 0; b < GFBITS; b++) out[k+1][b] = vec256_unpack_high (tmp0[b], tmp1[b]);
	}

	for (i = 0; i <= 4; i++)
	{
		s = 1 << i;

		for (j = 0; j < 32; j += 2*s)
		for (k = j; k < j+s; k++)
		{
			vec256_maa_asm(out[k], out[k+s], (vec256 *) consts[ consts_ptr + (k-j) ]);
		}

		consts_ptr += (1 << i);
	}

	//

	for (i = 0; i <     32; i++)
	for (b = 0; b < GFBITS; b++) 
		out[i][b] = vec256_xor(out[i][b], powers[i][b].v);
}

void fft(vec256 out[][GFBITS], vec128 *in)
{
	radix_conversions(in);
	butterflies(out, in);
}

