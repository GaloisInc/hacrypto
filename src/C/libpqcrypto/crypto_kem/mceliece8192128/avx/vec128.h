#ifndef VEC128_H
#define VEC128_H

#include "params.h"

#include <stdint.h>
#include <smmintrin.h>

typedef __m128i vec128;

static inline vec128 vec128_set1_16b(uint16_t a)
{
	return _mm_set1_epi16(a);
}

static inline vec128 vec128_setzero() 
{
	return _mm_setzero_si128();
}

static inline uint64_t vec128_extract(vec128 a, int i) 
{
	return _mm_extract_epi64(a, i);
}

static inline vec128 vec128_and(vec128 a, vec128 b) 
{
	return _mm_and_si128(a, b);
}

static inline vec128 vec128_xor(vec128 a, vec128 b) 
{
	return _mm_xor_si128(a, b);
}

static inline vec128 vec128_or(vec128 a, vec128 b) 
{
	return _mm_or_si128(a, b);
}

static inline vec128 vec128_sll_2x(vec128 a, int s) 
{
	return _mm_slli_epi64(a, s);
}

static inline vec128 vec128_srl_2x(vec128 a, int s) 
{
	return _mm_srli_epi64(a, s);
}

static inline vec128 vec128_set2x(uint64_t a0, uint64_t a1)
{
	return _mm_set_epi64x(a1, a0);
}

static inline vec128 vec128_unpack_low(vec128 a, vec128 b)
{
	return _mm_unpacklo_epi64(a, b);
}

static inline vec128 vec128_unpack_high(vec128 a, vec128 b)
{
	return _mm_unpackhi_epi64(a, b);
}

static inline vec128 vec128_setbits(uint64_t a)
{
	return _mm_set1_epi64x(-a);
}

static inline void vec128_copy(vec128 *dest, vec128 *src)
{
	int i;

	for (i = 0; i < GFBITS; i++)
		dest[i] = src[i];
}

static inline void vec128_add(vec128 *c, vec128 *a, vec128 *b)
{
	int i;

	for (i = 0; i < GFBITS; i++)
		c[i] = vec128_xor(a[i], b[i]);
}

static inline vec128 vec128_or_reduce(vec128 * a) 
{
	int i;
	vec128 ret;		

	ret = a[0];
	for (i = 1; i < GFBITS; i++)
		ret = vec128_or(ret, a[i]);

	return ret;
}

void vec128_mul(vec128 *, vec128 *, vec128 *);
void vec128_sq(vec128 *, vec128 *);
void vec128_inv(vec128 *, vec128 *);

typedef union
{
	uint64_t s[2];
	vec128 v;
} u128;

#endif

