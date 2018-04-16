#include "fft_tr.h"

#include "transpose.h"

#include <stdint.h>

static void radix_conversions_tr(vec128 in[][ GFBITS ])
{
	int i, j, k;
	vec128 t, x0, x1;

	uint64_t v0, v1, v2, v3;

	const u128 mask[6][2] = 
	{
		{{{0x2222222222222222, 0x2222222222222222}},
		 {{0x4444444444444444, 0x4444444444444444}}},
		{{{0x0C0C0C0C0C0C0C0C, 0x0C0C0C0C0C0C0C0C}},
		 {{0x3030303030303030, 0x3030303030303030}}},
		{{{0x00F000F000F000F0, 0x00F000F000F000F0}},
		 {{0x0F000F000F000F00, 0x0F000F000F000F00}}},
		{{{0x0000FF000000FF00, 0x0000FF000000FF00}},
		 {{0x00FF000000FF0000, 0x00FF000000FF0000}}},
		{{{0x00000000FFFF0000, 0x00000000FFFF0000}},
		 {{0x0000FFFF00000000, 0x0000FFFF00000000}}},
		{{{0xFFFFFFFF00000000, 0xFFFFFFFF00000000}},
		 {{0x00000000FFFFFFFF, 0x00000000FFFFFFFF}}}
	};

	const u128 s[6][2][GFBITS] = 
	{
#include "scalars13_4x.data"
	};
	
	//

	for (j = 6; j >= 0; j--)
	{
		if (j < 6)
		{
			vec128_mul(in[0], in[0], (vec128 *) s[j][0]); // scaling
			vec128_mul(in[1], in[1], (vec128 *) s[j][1]); // scaling
		}

		for (k = j; k <= 4; k++)
		for (i = 0; i < GFBITS; i++)
		{
			t = vec128_and(in[0][i], mask[k][0].v);
			t = vec128_sll_2x(t, 1 << k);
			in[0][i] = vec128_xor(in[0][i], t);

			t = vec128_and(in[0][i], mask[k][1].v);
			t = vec128_sll_2x(t, 1 << k);
			in[0][i] = vec128_xor(in[0][i], t);

			t = vec128_and(in[1][i], mask[k][0].v);
			t = vec128_sll_2x(t, 1 << k);
			in[1][i] = vec128_xor(in[1][i], t);

			t = vec128_and(in[1][i], mask[k][1].v);
			t = vec128_sll_2x(t, 1 << k);
			in[1][i] = vec128_xor(in[1][i], t);
		}

		if (j <= 5)
		for (i = 0; i < GFBITS; i++)
		{
			x0 = vec128_unpack_low(in[0][i], in[1][i]);
			x1 = vec128_unpack_high(in[0][i], in[1][i]);

			x1 = vec128_xor(x1, vec128_srl_2x(x0, 32));
			x1 = vec128_xor(x1, vec128_sll_2x(x1, 32));

			in[0][i] = vec128_unpack_low(x0, x1);
			in[1][i] = vec128_unpack_high(x0, x1);
		}

		for (i = 0; i < GFBITS; i++)
		{
			v0 = vec128_extract(in[0][i], 0);
			v1 = vec128_extract(in[0][i], 1);
			v2 = vec128_extract(in[1][i], 0);
			v3 = vec128_extract(in[1][i], 1);

			v3 ^= v2 ^= v1;
			
			in[0][i] = vec128_set2x(v0, v1);
			in[1][i] = vec128_set2x(v2, v3);
		}

	}
}

static void butterflies_tr(vec128 out[][ GFBITS ], vec128 in[][ GFBITS ])
{
	int i, j, k, s, b;

	vec128 tmp0[ GFBITS ];
	vec128 tmp1[ GFBITS ];
	vec128 tmp[ GFBITS ];

	vec128 pre[ 6  ][ GFBITS ];
	vec128 buf[ 64 ];

	u128 consts64[ GFBITS ] =
	{
		{{0X6969969669699696, 0X6969969669699696}},
		{{0X9966669966999966, 0X9966669966999966}},
		{{0X9966669966999966, 0X9966669966999966}},
		{{0XFF0000FF00FFFF00, 0XFF0000FF00FFFF00}},
		{{0XCC3333CCCC3333CC, 0XCC3333CCCC3333CC}},
		{{0X9966669966999966, 0X9966669966999966}},
		{{0X6666666666666666, 0X6666666666666666}},
		{{0XA55AA55AA55AA55A, 0XA55AA55AA55AA55A}},
		{{0XCCCC33333333CCCC, 0XCCCC33333333CCCC}},
		{{0X5A5A5A5A5A5A5A5A, 0X5A5A5A5A5A5A5A5A}},
		{{0X55AAAA55AA5555AA, 0X55AAAA55AA5555AA}},
		{{0X0FF0F00FF00F0FF0, 0X0FF0F00FF00F0FF0}},
		{{0X5AA55AA5A55AA55A, 0X5AA55AA5A55AA55A}}
	};

	u128 consts[ 63 ][ GFBITS ] =
	{
#include "consts13.data"
	};

	uint64_t consts_ptr = 63;

	const unsigned char reversal[] = 
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

	const uint16_t beta[6] = {5246, 5306, 6039, 6685, 4905, 6755};

	//

	for (i = 5; i >= 0; i--)
	{
		s = 1 << i;
		consts_ptr -= s;

		for (j = 0; j < 64; j += 2*s)
		for (k = j; k < j+s; k++)
		{
			for (b = 0; b < GFBITS; b++) 
				in[k][b] = vec128_xor(in[k][b], in[k+s][b]);

			vec128_mul(tmp, in[k], (vec128 *) consts[ consts_ptr + (k-j) ]);

			for (b = 0; b < GFBITS; b++) 
				in[k+s][b] = vec128_xor(in[k+s][b], tmp[b]);
		}
	}

	for (j = 0; j < 64; j+=2)
	{
		for (i = 0; i < GFBITS; i++)
		{
			tmp0[i] = vec128_unpack_low(in[j][i], in[j+1][i]);
			tmp1[i] = vec128_unpack_high(in[j][i], in[j+1][i]);
		}

		for (b = 0; b < GFBITS; b++) 
			tmp0[b] = vec128_xor(tmp0[b], tmp1[b]);

		vec128_mul(tmp, tmp0, (vec128 *) consts64);

		for (b = 0; b < GFBITS; b++) 
			tmp1[b] = vec128_xor(tmp1[b], tmp[b]);

		for (i = 0; i < GFBITS; i++)
		{
			in[j+0][i] = vec128_unpack_low(tmp0[i], tmp1[i]);
			in[j+1][i] = vec128_unpack_high(tmp0[i], tmp1[i]);
		}
	}

	for (i = 0; i < GFBITS; i++)
	{
		for (k = 0; k < 64; k++)
			buf[k] = in[ reversal[k] ][i];

		transpose_64x128_sp(buf);

#define xor vec128_xor

		pre[0][i] = buf[32]; buf[33] = xor(buf[33], buf[32]);
		pre[1][i] = buf[33]; buf[35] = xor(buf[35], buf[33]);
		pre[0][i] = xor(pre[0][i], buf[35]); buf[34] = xor(buf[34], buf[35]);
		pre[2][i] = buf[34]; buf[38] = xor(buf[38], buf[34]);
		pre[0][i] = xor(pre[0][i], buf[38]); buf[39] = xor(buf[39], buf[38]);
		pre[1][i] = xor(pre[1][i], buf[39]); buf[37] = xor(buf[37], buf[39]);
		pre[0][i] = xor(pre[0][i], buf[37]); buf[36] = xor(buf[36], buf[37]);
		pre[3][i] = buf[36]; buf[44] = xor(buf[44], buf[36]);
		pre[0][i] = xor(pre[0][i], buf[44]); buf[45] = xor(buf[45], buf[44]);
		pre[1][i] = xor(pre[1][i], buf[45]); buf[47] = xor(buf[47], buf[45]);
		pre[0][i] = xor(pre[0][i], buf[47]); buf[46] = xor(buf[46], buf[47]);
		pre[2][i] = xor(pre[2][i], buf[46]); buf[42] = xor(buf[42], buf[46]);
		pre[0][i] = xor(pre[0][i], buf[42]); buf[43] = xor(buf[43], buf[42]);
		pre[1][i] = xor(pre[1][i], buf[43]); buf[41] = xor(buf[41], buf[43]);
		pre[0][i] = xor(pre[0][i], buf[41]); buf[40] = xor(buf[40], buf[41]);
		pre[4][i] = buf[40]; buf[56] = xor(buf[56], buf[40]);
		pre[0][i] = xor(pre[0][i], buf[56]); buf[57] = xor(buf[57], buf[56]);
		pre[1][i] = xor(pre[1][i], buf[57]); buf[59] = xor(buf[59], buf[57]);
		pre[0][i] = xor(pre[0][i], buf[59]); buf[58] = xor(buf[58], buf[59]);
		pre[2][i] = xor(pre[2][i], buf[58]); buf[62] = xor(buf[62], buf[58]);
		pre[0][i] = xor(pre[0][i], buf[62]); buf[63] = xor(buf[63], buf[62]);
		pre[1][i] = xor(pre[1][i], buf[63]); buf[61] = xor(buf[61], buf[63]);
		pre[0][i] = xor(pre[0][i], buf[61]); buf[60] = xor(buf[60], buf[61]);
		pre[3][i] = xor(pre[3][i], buf[60]); buf[52] = xor(buf[52], buf[60]);
		pre[0][i] = xor(pre[0][i], buf[52]); buf[53] = xor(buf[53], buf[52]);
		pre[1][i] = xor(pre[1][i], buf[53]); buf[55] = xor(buf[55], buf[53]);
		pre[0][i] = xor(pre[0][i], buf[55]); buf[54] = xor(buf[54], buf[55]);
		pre[2][i] = xor(pre[2][i], buf[54]); buf[50] = xor(buf[50], buf[54]);
		pre[0][i] = xor(pre[0][i], buf[50]); buf[51] = xor(buf[51], buf[50]);
		pre[1][i] = xor(pre[1][i], buf[51]); buf[49] = xor(buf[49], buf[51]);
		pre[0][i] = xor(pre[0][i], buf[49]); buf[48] = xor(buf[48], buf[49]);
		pre[5][i] = buf[48]; buf[16] = xor(buf[16], buf[48]);
		pre[0][i] = xor(pre[0][i], buf[16]); buf[17] = xor(buf[17], buf[16]);
		pre[1][i] = xor(pre[1][i], buf[17]); buf[19] = xor(buf[19], buf[17]);
		pre[0][i] = xor(pre[0][i], buf[19]); buf[18] = xor(buf[18], buf[19]);
		pre[2][i] = xor(pre[2][i], buf[18]); buf[22] = xor(buf[22], buf[18]);
		pre[0][i] = xor(pre[0][i], buf[22]); buf[23] = xor(buf[23], buf[22]);
		pre[1][i] = xor(pre[1][i], buf[23]); buf[21] = xor(buf[21], buf[23]);
		pre[0][i] = xor(pre[0][i], buf[21]); buf[20] = xor(buf[20], buf[21]);
		pre[3][i] = xor(pre[3][i], buf[20]); buf[28] = xor(buf[28], buf[20]);
		pre[0][i] = xor(pre[0][i], buf[28]); buf[29] = xor(buf[29], buf[28]);
		pre[1][i] = xor(pre[1][i], buf[29]); buf[31] = xor(buf[31], buf[29]);
		pre[0][i] = xor(pre[0][i], buf[31]); buf[30] = xor(buf[30], buf[31]);
		pre[2][i] = xor(pre[2][i], buf[30]); buf[26] = xor(buf[26], buf[30]);
		pre[0][i] = xor(pre[0][i], buf[26]); buf[27] = xor(buf[27], buf[26]);
		pre[1][i] = xor(pre[1][i], buf[27]); buf[25] = xor(buf[25], buf[27]);
		pre[0][i] = xor(pre[0][i], buf[25]); buf[24] = xor(buf[24], buf[25]);
		pre[4][i] = xor(pre[4][i], buf[24]); buf[8] = xor(buf[8], buf[24]);
		pre[0][i] = xor(pre[0][i], buf[8]); buf[9] = xor(buf[9], buf[8]);
		pre[1][i] = xor(pre[1][i], buf[9]); buf[11] = xor(buf[11], buf[9]);
		pre[0][i] = xor(pre[0][i], buf[11]); buf[10] = xor(buf[10], buf[11]);
		pre[2][i] = xor(pre[2][i], buf[10]); buf[14] = xor(buf[14], buf[10]);
		pre[0][i] = xor(pre[0][i], buf[14]); buf[15] = xor(buf[15], buf[14]);
		pre[1][i] = xor(pre[1][i], buf[15]); buf[13] = xor(buf[13], buf[15]);
		pre[0][i] = xor(pre[0][i], buf[13]); buf[12] = xor(buf[12], buf[13]);
		pre[3][i] = xor(pre[3][i], buf[12]); buf[4] = xor(buf[4], buf[12]);
		pre[0][i] = xor(pre[0][i], buf[4]); buf[5] = xor(buf[5], buf[4]);
		pre[1][i] = xor(pre[1][i], buf[5]); buf[7] = xor(buf[7], buf[5]);
		pre[0][i] = xor(pre[0][i], buf[7]); buf[6] = xor(buf[6], buf[7]);
		pre[2][i] = xor(pre[2][i], buf[6]); buf[2] = xor(buf[2], buf[6]);
		pre[0][i] = xor(pre[0][i], buf[2]); buf[3] = xor(buf[3], buf[2]);
		pre[1][i] = xor(pre[1][i], buf[3]); buf[1] = xor(buf[1], buf[3]);
	
		pre[0][i] = xor(pre[0][i], buf[1]); out[0][i] = xor(buf[0], buf[1]);
#undef xor

	}	

	for (j = 0; j < GFBITS; j++) tmp[j] = vec128_setbits((beta[0] >> j) & 1);

	vec128_mul(out[1], pre[0], tmp);

	for (i = 1; i < 6; i++)
	{
		for (j = 0; j < GFBITS; j++) tmp[j] = vec128_setbits((beta[i] >> j) & 1);

		vec128_mul(tmp, pre[i], tmp);

		for (b = 0; b < GFBITS; b++) out[1][b] = vec128_xor(out[1][b], tmp[b]);
	}
}

void fft_tr(vec128 out[][GFBITS], vec128 in[][ GFBITS ])
{
	butterflies_tr(out, in);

	radix_conversions_tr(out);
}

