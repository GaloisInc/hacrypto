#include <assert.h>
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "fips202.h"
#include "gf31.h"

/* Given a vector of N elements in the range [0, 31], this reduces the elements
   to the range [0, 30] by mapping 31 to 0 (i.e reduction mod 31) */
void vgf31_unique(gf31 *out, gf31 *in)
{
    __m256i x;
    __m256i _w31 = _mm256_set1_epi16(31);
    int i;

    for (i = 0; i < (N >> 4); ++i) {
        x = _mm256_loadu_si256((__m256i const *) (in + 16*i));
        x = _mm256_xor_si256(x, _mm256_and_si256(_w31, _mm256_cmpeq_epi16(x, _w31)));
        _mm256_storeu_si256((__m256i*)(out + i*16), x);
    }
}

/* This function acts on vectors with 64 gf31 elements.
It performs one reduction step and guarantees output in [0, 30],
but requires input to be in [0, 32768). */
void vgf31_shorten_unique(gf31 *out, gf31 *in)
{
    __m256i x;
    __m256i _w2114 = _mm256_set1_epi32(2114*65536 + 2114);
    __m256i _w31 = _mm256_set1_epi16(31);
    int i;

    for (i = 0; i < (N >> 4); ++i) {
        x = _mm256_loadu_si256((__m256i const *) (in + 16*i));
        x = _mm256_sub_epi16(x, _mm256_mullo_epi16(_w31, _mm256_mulhi_epi16(x, _w2114)));
        x = _mm256_xor_si256(x, _mm256_and_si256(_w31, _mm256_cmpeq_epi16(x, _w31)));
        _mm256_storeu_si256((__m256i*)(out + i*16), x);
    }
}

/* Given a seed, samples len gf31 elements (in the range [0, 30]), and places
   them in a vector of 16-bit elements */
void gf31_nrand(gf31 *out, const int len, const unsigned char *seed, const int seedlen)
{
    int i = 0, j;
    uint64_t shakestate[25] = {0};
    unsigned char shakeblock[SHAKE256_RATE];

    shake256_absorb(shakestate, seed, seedlen);

    while (i < len) {
        shake256_squeezeblocks(shakeblock, 1, shakestate);
        for (j = 0; j < SHAKE256_RATE && i < len; j++) {
            if ((shakeblock[j] & 31) != 31) {
                out[i] = (shakeblock[j] & 31);
                i++;
            }
        }
    }
}

/* Given a seed, samples len gf31 elements, transposed into unsigned range,
   i.e. in the range [-15, 15], and places them in an array of 8-bit integers.
   This is used for the expansion of F, which wants packed elements. */
void gf31_nrand_schar(signed char *out, const int len, const unsigned char *seed, const int seedlen)
{
    int i = 0, j;
    uint64_t shakestate[25] = {0};
    unsigned char shakeblock[SHAKE256_RATE];

    shake256_absorb(shakestate, seed, seedlen);

    while (i < len) {
        shake256_squeezeblocks(shakeblock, 1, shakestate);
        for (j = 0; j < SHAKE256_RATE && i < len; j++) {
            if ((shakeblock[j] & 31) != 31) {
                out[i] = (shakeblock[j] & 31) - 15;
                i++;
            }
        }
    }
}

/* Unpacks an array of packed GF31 elements to one element per gf31.
   Assumes that there is sufficient empty space available at the end of the
   array to unpack. Can perform in-place. */
void gf31_nunpack(gf31 *out, const unsigned char *in, const int n)
{
    int i;
    int j = ((n * 5) >> 3) - 1;
    int d = 0;

    for (i = n-1; i >= 0; i--) {
        out[i] = (in[j] >> d) & 31;
        d += 5;
        if (d > 8) {
            d -= 8;
            j--;
            out[i] ^= (in[j] << (5 - d)) & 31;
        }
    }
}

/* Packs an array of GF31 elements from gf31's to concatenated 5-bit values.
   Assumes that there is sufficient space available to unpack.
   Can perform in-place. */
void gf31_npack(unsigned char *out, const gf31 *in, const int n)
{
    int i = 0;
    int j;
    int d = 3;

    for (j = 0; j < n; j++) {
        assert(in[j] < 31);
    }

    /* There will be ceil(5n / 8) output blocks */
    memset(out, 0, ((5 * n + 7) & ~7) >> 3);

    for (j = 0; j < n; j++) {
        if (d < 0) {
            d += 8;
            out[i] = (out[i] & (255 << (d - 3))) |
                      ((in[j] >> (8 - d)) & ~(255 << (d - 3)));
            i++;
        }
        out[i] = (out[i] & ~(31 << d)) | ((in[j] << d) & (31 << d));
        d -= 5;
    }
}
