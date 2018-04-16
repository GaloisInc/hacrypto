#include <stdio.h>
#include <immintrin.h>
#include "mq.h"
#include "params.h"

static inline __m256i reduce_16(__m256i r, __m256i _w31, __m256i _w2114)
{
    __m256i exp = _mm256_mulhi_epi16(r, _w2114);
    return _mm256_sub_epi16(r, _mm256_mullo_epi16(_w31, exp));
}

/* Computes all products x_i * x_j, returns in reduced form */
inline static
void generate_quadratic_terms( unsigned char * xij , const gf31 * x )
{
    __m256i mask_2114 = _mm256_set1_epi16( 2114 );
    __m256i mask_31 = _mm256_set1_epi16( 31 );
    __m256i xi[4];
    xi[0] = _mm256_loadu_si256((__m256i const *) (x));
    xi[1] = _mm256_loadu_si256((__m256i const *) (x+16));
    xi[2] = _mm256_loadu_si256((__m256i const *) (x+32));
#if 64 == N
    xi[3] = _mm256_loadu_si256((__m256i const *) (x+48));
#elif 48 == N
    xi[3] = _mm256_setzero_si256();
#else
Compiler error. Un-supported parameter: N
#endif

    __m256i xixj[4];
    xixj[0] = _mm256_setzero_si256();
    xixj[1] = _mm256_setzero_si256();
    xixj[2] = _mm256_setzero_si256();
    xixj[3] = _mm256_setzero_si256();

    int i, j, k;
    k=0;
    for(i=0;i<32;i++) {
        __m256i br_xi = _mm256_set1_epi16( x[i] );
        for(j=0;j<=(i >> 4);j++) {
            xixj[j] = _mm256_mullo_epi16( xi[j] , br_xi );
            xixj[j] = reduce_16( xixj[j] , mask_31 , mask_2114 );
        }

        __m256i r = _mm256_packs_epi16(xixj[0], xixj[1]);
        r = _mm256_permute4x64_epi64(r, 0xd8);  // 3,1,2,0
        _mm256_storeu_si256( (__m256i*)( xij + k ) , r );
        k += i+1;
    }

    for(i=32;i<N;i++) {
        __m256i br_xi = _mm256_set1_epi16( x[i] );
        for(j=0;j<=(i >> 4);j++) {
            xixj[j] = _mm256_mullo_epi16( xi[j] , br_xi );
            xixj[j] = reduce_16( xixj[j] , mask_31 , mask_2114 );
        }

        __m256i r0 = _mm256_packs_epi16(xixj[0], xixj[1]);
        r0 = _mm256_permute4x64_epi64(r0, 0xd8);  // 3,1,2,0
        _mm256_storeu_si256( (__m256i*)( xij + k ) , r0 );
        __m256i r1 = _mm256_packs_epi16(xixj[2], xixj[3]);
        r1 = _mm256_permute4x64_epi64(r1, 0xd8);  // 3,1,2,0
        _mm256_storeu_si256( (__m256i*)( xij + 32 + k ) , r1 );
        k += i+1;
    }
}

/* Computes all terms (x_i * y_j) + (x_j * y_i), returns in reduced form */
inline static
void generate_xiyj_p_xjyi_terms( unsigned char * xij , const gf31 * x , const gf31 * y )
{
    __m256i mask_2114 = _mm256_set1_epi16( 2114 );
    __m256i mask_31 = _mm256_set1_epi16( 31 );
    __m256i xiyi[4];
    xiyi[0] = _mm256_loadu_si256((__m256i const *) (x)) ^ _mm256_slli_si256( _mm256_loadu_si256((__m256i const *) (y)) , 1 );
    xiyi[1] = _mm256_loadu_si256((__m256i const *) (x+16)) ^ _mm256_slli_si256( _mm256_loadu_si256((__m256i const *) (y+16)) , 1 );
    xiyi[2] = _mm256_loadu_si256((__m256i const *) (x+32)) ^ _mm256_slli_si256( _mm256_loadu_si256((__m256i const *) (y+32)) , 1 );
#if 64 == N
    xiyi[3] = _mm256_loadu_si256((__m256i const *) (x+48)) ^ _mm256_slli_si256( _mm256_loadu_si256((__m256i const *) (y+48)) , 1 );
#elif 48 == N
    xiyi[3] = _mm256_setzero_si256();
#else
Compiler error. Un-supported parameter: N
#endif

    __m256i xixj[4];
    xixj[0] = _mm256_setzero_si256();
    xixj[1] = _mm256_setzero_si256();
    xixj[2] = _mm256_setzero_si256();
    xixj[3] = _mm256_setzero_si256();

    int i, j, k;
    k=0;
    for(i=0;i<32;i++) {
        __m256i br_yixi = _mm256_set1_epi16( (x[i]<<8)^y[i] );
        for(j=0;j<=(i >> 4);j++) {
            xixj[j] = _mm256_maddubs_epi16( xiyi[j] , br_yixi );
            xixj[j] = reduce_16( xixj[j] , mask_31 , mask_2114 );
        }

        __m256i r = _mm256_packs_epi16(xixj[0], xixj[1]);
        r = _mm256_permute4x64_epi64(r, 0xd8);  // 3,1,2,0
        _mm256_storeu_si256( (__m256i*)( xij + k ) , r );
        k += i+1;
    }

    for(i=32;i<N;i++) {
        __m256i br_yixi = _mm256_set1_epi16( (x[i]<<8)^y[i] );
        for(j=0;j<=(i >> 4);j++) {
            xixj[j] = _mm256_maddubs_epi16( xiyi[j] , br_yixi );
            xixj[j] = reduce_16( xixj[j] , mask_31 , mask_2114 );
        }

        __m256i r0 = _mm256_packs_epi16(xixj[0], xixj[1]);
        r0 = _mm256_permute4x64_epi64(r0, 0xd8);  // 3,1,2,0
        _mm256_storeu_si256( (__m256i*)( xij + k ) , r0 );
        __m256i r1 = _mm256_packs_epi16(xixj[2], xixj[3]);
        r1 = _mm256_permute4x64_epi64(r1, 0xd8);  // 3,1,2,0
        _mm256_storeu_si256( (__m256i*)( xij + 32 + k ) , r1 );
        k += i+1;
    }
}

#define EVAL_YMM_0(xx) {\
    __m128i tmp = _mm256_castsi256_si128(xx); \
    for (int i = 0; i < 8; i++) { \
        __m256i _xi = _mm256_broadcastw_epi16(tmp); \
        tmp = _mm_srli_si128(tmp, 2); \
        for (int j = 0; j < (N/16); j++) { \
            __m256i coeff = _mm256_loadu_si256((__m256i const *) F); \
            F += 32; \
            yy[j] = _mm256_add_epi16(yy[j], _mm256_maddubs_epi16(_xi, coeff)); \
        } \
    } \
}

#define EVAL_YMM_1(xx) {\
    __m128i tmp = _mm256_extracti128_si256(xx, 1); \
    for (int i = 0; i < 8; i++) { \
        __m256i _xi = _mm256_broadcastw_epi16(tmp); \
        tmp = _mm_srli_si128(tmp, 2); \
        for (int j = 0; j < (N/16); j++) { \
            __m256i coeff = _mm256_loadu_si256((__m256i const *) F); \
            F += 32; \
            yy[j] = _mm256_add_epi16(yy[j], _mm256_maddubs_epi16(_xi, coeff)); \
        } \
    } \
}

#if (64 == N )
#define REDUCE_(yy) { \
    yy[0] = reduce_16(yy[0], mask_reduce, mask_2114); \
    yy[1] = reduce_16(yy[1], mask_reduce, mask_2114); \
    yy[2] = reduce_16(yy[2], mask_reduce, mask_2114); \
    yy[3] = reduce_16(yy[3], mask_reduce, mask_2114); \
}

#elif (48==N)
#define REDUCE_(yy) { \
    yy[0] = reduce_16(yy[0], mask_reduce, mask_2114); \
    yy[1] = reduce_16(yy[1], mask_reduce, mask_2114); \
    yy[2] = reduce_16(yy[2], mask_reduce, mask_2114); \
}
#else
error.
#endif

/* Evaluates the MQ function on a vector of N gf31 elements x (expected to be
   in reduced 5-bit representation). Expects the coefficients in F to be in
   signed representation (i.e. [-15, 15], packed bytewise).
   Outputs M gf31 elements in unique 16-bit representation as fx. */
void MQ(gf31 *fx, const gf31 *x, const signed char *F)
{
    int i;

    __m256i mask_2114 = _mm256_set1_epi32(2114*65536 + 2114);
    __m256i mask_reduce = _mm256_srli_epi16(_mm256_cmpeq_epi16(mask_2114, mask_2114), 11);

    __m256i xi[4];
    xi[0] = _mm256_loadu_si256((__m256i const *) (x));
    xi[1] = _mm256_loadu_si256((__m256i const *) (x+16));
    xi[2] = _mm256_loadu_si256((__m256i const *) (x+32));
#if (64 == N)
    xi[3] = _mm256_loadu_si256((__m256i const *) (x+48));
#elif (48==N)
    xi[3] = _mm256_setzero_si256();
#else
error.
#endif

    __m256i _zero = _mm256_setzero_si256();
    xi[0] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[0]), xi[0]);
    xi[1] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[1]), xi[1]);
    xi[2] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[2]), xi[2]);
#if (64 == N)
    xi[3] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[3]), xi[3]);
#endif

    __m256i x1 = _mm256_packs_epi16(xi[0], xi[1]);
    x1 = _mm256_permute4x64_epi64(x1, 0xd8);  // 3,1,2,0
    __m256i x2 = _mm256_packs_epi16(xi[2], xi[3]);
    x2 = _mm256_permute4x64_epi64(x2, 0xd8);  // 3,1,2,0

    __m256i yy[M/16];
    yy[0] = _zero;
    yy[1] = _zero;
    yy[2] = _zero;
#if (64 == M)
    yy[3] = _zero;
#endif

    EVAL_YMM_0(x1)
    EVAL_YMM_1(x1)
    EVAL_YMM_0(x2)
#if 64 == N
    EVAL_YMM_1(x2)
#endif
    REDUCE_(yy)

#if (64 == N)
    __m256i xixj[65];
    generate_quadratic_terms( (unsigned char *) xixj , x );
    for(i = 0 ; i < 64 ; i+=2) {
        EVAL_YMM_0(xixj[i])
        EVAL_YMM_1(xixj[i])
        EVAL_YMM_0(xixj[i+1])
        EVAL_YMM_1(xixj[i+1])
        REDUCE_(yy)
    }
    EVAL_YMM_0(xixj[64])
    EVAL_YMM_1(xixj[64])
    REDUCE_(yy)
#elif (48==N)
    __m256i xixj[38];
    generate_quadratic_terms( (unsigned char *) xixj , x );
    for(i = 0 ; i < 36 ; i+=2) {
        EVAL_YMM_0(xixj[i])
        EVAL_YMM_1(xixj[i])
        EVAL_YMM_0(xixj[i+1])
        EVAL_YMM_1(xixj[i+1])
        REDUCE_(yy)
    }
    EVAL_YMM_0(xixj[36])
    {
    __m128i tmp = _mm256_extracti128_si256(xixj[36], 1);
    for (int i = 0; i < 4; i++) {
        __m256i _xi = _mm256_broadcastw_epi16(tmp);
        tmp = _mm_srli_si128(tmp, 2);
        for (int j = 0; j < (N/16); j++) {
            __m256i coeff = _mm256_loadu_si256((__m256i const *) F);
            F += 32;
            yy[j] = _mm256_add_epi16(yy[j], _mm256_maddubs_epi16(_xi, coeff));
        }
    }
    }
    REDUCE_(yy)
#else
error.
#endif

    yy[0] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_mm256_setzero_si256(), yy[0]), yy[0]);
    yy[1] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_mm256_setzero_si256(), yy[1]), yy[1]);
    yy[2] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_mm256_setzero_si256(), yy[2]), yy[2]);
#if 64 == N
    yy[3] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_mm256_setzero_si256(), yy[3]), yy[3]);
#endif

    for (i = 0; i < (N/16); ++i) {
        _mm256_storeu_si256((__m256i*)(fx+i*16), yy[i]);
    }
}

/* Evaluates the bilinear polar form of the MQ function (i.e. G) on a vector of
   N gf31 elements x (expected to be in reduced 5-bit representation). Expects
   the coefficients in F to be in signed representation (i.e. [-15, 15], packed
   bytewise). Outputs M gf31 elements in unique 16-bit representation as fx. */
void G(gf31 *fx, const gf31 *x, const gf31 *y, const signed char *F)
{
    int i;

    __m256i mask_2114 = _mm256_set1_epi32(2114*65536 + 2114);
    __m256i mask_reduce = _mm256_srli_epi16(_mm256_cmpeq_epi16(mask_2114, mask_2114), 11);
    __m256i _zero = _mm256_setzero_si256();

    __m256i xi[4];
    xi[0] = _mm256_loadu_si256((__m256i const *) (x));
    xi[1] = _mm256_loadu_si256((__m256i const *) (x+16));
    xi[2] = _mm256_loadu_si256((__m256i const *) (x+32));
#if (64 == N)
    xi[3] = _mm256_loadu_si256((__m256i const *) (x+48));
#elif 48 == N
    xi[3] = _mm256_setzero_si256();;
#else
error. Un-supported parameter: N
#endif
    xi[0] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[0]), xi[0]);
    xi[1] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[1]), xi[1]);
    xi[2] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[2]), xi[2]);
#if 64 == N
    xi[3] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[3]), xi[3]);
#endif

    __m256i x1 = _mm256_packs_epi16(xi[0], xi[1]);
    x1 = _mm256_permute4x64_epi64(x1, 0xd8);  // 3,1,2,0
    __m256i x2 = _mm256_packs_epi16(xi[2], xi[3]);
    x2 = _mm256_permute4x64_epi64(x2, 0xd8);  // 3,1,2,0

    xi[0] = _mm256_loadu_si256((__m256i const *) (y));
    xi[1] = _mm256_loadu_si256((__m256i const *) (y+16));
    xi[2] = _mm256_loadu_si256((__m256i const *) (y+32));
#if 64 == N
    xi[3] = _mm256_loadu_si256((__m256i const *) (y+48));
#endif
    xi[0] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[0]), xi[0]);
    xi[1] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[1]), xi[1]);
    xi[2] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[2]), xi[2]);
#if 64 == N
    xi[3] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_zero, xi[3]), xi[3]);
#endif

    __m256i y1 = _mm256_packs_epi16(xi[0], xi[1]);
    y1 = _mm256_permute4x64_epi64(y1, 0xd8);  // 3,1,2,0
    __m256i y2 = _mm256_packs_epi16(xi[2], xi[3]);
    y2 = _mm256_permute4x64_epi64(y2, 0xd8);  // 3,1,2,0

    __m256i yy[(M/16)];
    yy[0] = _zero;
    yy[1] = _zero;
    yy[2] = _zero;
#if 64 == M
    yy[3] = _zero;
#endif

    F += N*M;

#if 64 == N
    __m256i xixj[65];
    generate_xiyj_p_xjyi_terms( (unsigned char *) xixj , x , y );
    for(i = 0 ; i < 64 ; i+=2) {
        EVAL_YMM_0(xixj[i])
        EVAL_YMM_1(xixj[i])
        EVAL_YMM_0(xixj[i+1])
        EVAL_YMM_1(xixj[i+1])
        REDUCE_(yy)
    }
    EVAL_YMM_0(xixj[64])
    EVAL_YMM_1(xixj[64])
    REDUCE_(yy)
#elif 48 == N
    __m256i xixj[38];
    generate_xiyj_p_xjyi_terms( (unsigned char *) xixj , x , y );
    for(i = 0 ; i < 36 ; i+=2) {
        EVAL_YMM_0(xixj[i])
        EVAL_YMM_1(xixj[i])
        EVAL_YMM_0(xixj[i+1])
        EVAL_YMM_1(xixj[i+1])
        REDUCE_(yy)
    }
    EVAL_YMM_0(xixj[36])
    {
    __m128i tmp = _mm256_extracti128_si256(xixj[36], 1);
    for (int i = 0; i < 4; i++) {
        __m256i _xi = _mm256_broadcastw_epi16(tmp);
        tmp = _mm_srli_si128(tmp, 2);
        for (int j = 0; j < (N/16); j++) {
            __m256i coeff = _mm256_loadu_si256((__m256i const *) F);
            F += 32;
            yy[j] = _mm256_add_epi16(yy[j], _mm256_maddubs_epi16(_xi, coeff));
        }
    }
    }
    REDUCE_(yy)
#else
error.
#endif

    yy[0] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_mm256_setzero_si256(), yy[0]), yy[0]);
    yy[1] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_mm256_setzero_si256(), yy[1]), yy[1]);
    yy[2] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_mm256_setzero_si256(), yy[2]), yy[2]);
#if 64 == N
    yy[3] = _mm256_add_epi16(mask_reduce&_mm256_cmpgt_epi16(_mm256_setzero_si256(), yy[3]), yy[3]);
#endif

    for (i = 0; i < (N/16); ++i) {
        _mm256_storeu_si256((__m256i*)(fx+i*16), yy[i]);
    }
}
