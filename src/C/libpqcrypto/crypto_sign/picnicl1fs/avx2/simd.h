/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef SIMD_H
#define SIMD_H


#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#include <x86intrin.h>
#elif defined(__GNUC__) && defined(__ARM_NEON)
#include <arm_neon.h>
#endif

/* backwards compatibility macros for GCC 4.8 and 4.9
 *
 * bs{l,r}i was introduced in GCC 5 and in clang as macros sometime in 2015.
 * */
#if (!defined(__clang__) && defined(__GNUC__) && __GNUC__ < 5) ||                                  \
    (defined(__clang__) && !defined(_mm_bslli_si128))
#define _mm_bslli_si128(a, imm) _mm_slli_si128((a), (imm))
#define _mm_bsrli_si128(a, imm) _mm_srli_si128((a), (imm))
#endif

#include "cpu.h"

#define FN_ATTRIBUTES_AVX2 __attribute__((__always_inline__, target("avx2"), pure))
#define FN_ATTRIBUTES_SSE2 __attribute__((__always_inline__, target("sse2"), pure))

#define FN_ATTRIBUTES_AVX2_NP __attribute__((__always_inline__, target("avx2")))
#define FN_ATTRIBUTES_SSE2_NP __attribute__((__always_inline__, target("sse2")))

#if defined(__x86_64__) || defined(__i386__)
#if defined(__GNUC__) && !(defined(__APPLE__) && (__clang_major__ <= 8))
#define CPU_SUPPORTS_AVX2 __builtin_cpu_supports("avx2")
#define CPU_SUPPORTS_SSE4_1 __builtin_cpu_supports("sse4.1")
#else
#define CPU_SUPPORTS_AVX2 cpu_supports(CPU_CAP_AVX2)
#define CPU_SUPPORTS_SSE4_1 cpu_supports(CPU_CAP_SSE4_1)
#endif
#endif

#if defined(__x86_64__)
// X86-64 CPUs always support SSE2
#define CPU_SUPPORTS_SSE2 1
#elif defined(__i386__)
#if defined(__GNUC__) && !(defined(__APPLE__) && (__clang_major__ <= 8))
#define CPU_SUPPORTS_SSE2 __builtin_cpu_supports("sse2")
#else
#define CPU_SUPPORTS_SSE2 cpu_supports(CPU_CAP_SSE2)
#endif
#else
#define CPU_SUPPORTS_SSE2 0
#endif

#if defined(__aarch64__)
#define CPU_SUPPORTS_NEON 1
#elif defined(__arm__)
#define CPU_SUPPRTS_NEON cpu_supports(CPU_CAP_NEON)
#else
#define CPU_SUPPORTS_NEON 0
#endif

#define apply_region(name, type, xor, attributes)                                                  \
  static inline void attributes name(type* restrict dst, type const* restrict src,                 \
                                     unsigned int count) {                                         \
    for (unsigned int i = count; i; --i, ++dst, ++src) {                                           \
      *dst = (xor)(*dst, *src);                                                                    \
    }                                                                                              \
  }

#define apply_mask_region(name, type, xor, and, attributes)                                        \
  static inline void attributes name(type* restrict dst, type const* restrict src,                 \
                                     type const mask, unsigned int count) {                        \
    for (unsigned int i = count; i; --i, ++dst, ++src) {                                           \
      *dst = (xor)(*dst, (and)(mask, *src));                                                       \
    }                                                                                              \
  }

#define apply_array(name, type, xor, count, attributes)                                            \
  static inline void attributes name(type dst[count], type const lhs[count],                       \
                                     type const rhs[count]) {                                      \
    for (unsigned int i = 0; i < count; ++i) {                                                     \
      dst[i] = (xor)(lhs[i], rhs[i]);                                                              \
    }                                                                                              \
  }

/**
 * \brief Perform a left shift on a 256 bit value.
 */
static inline __m256i FN_ATTRIBUTES_AVX2 mm256_shift_left(__m256i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m256i carry  = _mm256_srli_epi64(data, 64 - count);
  __m256i rotate = _mm256_permute4x64_epi64(carry, _MM_SHUFFLE(2, 1, 0, 3));
  carry          = _mm256_blend_epi32(_mm256_setzero_si256(), rotate, _MM_SHUFFLE(3, 3, 3, 0));
  data           = _mm256_slli_epi64(data, count);
  return _mm256_or_si256(data, carry);
}

/**
 * \brief Perform a right shift on a 256 bit value.
 */
static inline __m256i FN_ATTRIBUTES_AVX2 mm256_shift_right(__m256i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m256i carry  = _mm256_slli_epi64(data, 64 - count);
  __m256i rotate = _mm256_permute4x64_epi64(carry, _MM_SHUFFLE(0, 3, 2, 1));
  carry          = _mm256_blend_epi32(_mm256_setzero_si256(), rotate, _MM_SHUFFLE(0, 3, 3, 3));
  data           = _mm256_srli_epi64(data, count);
  return _mm256_or_si256(data, carry);
}


apply_region(mm256_xor_region, __m256i, _mm256_xor_si256, FN_ATTRIBUTES_AVX2_NP);
apply_mask_region(mm256_xor_mask_region, __m256i, _mm256_xor_si256, _mm256_and_si256,
                  FN_ATTRIBUTES_AVX2_NP);

/**
 * \brief Perform a left shift on a 128 bit value.
 */
static inline __m128i FN_ATTRIBUTES_SSE2 mm128_shift_left(__m128i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m128i carry = _mm_bslli_si128(data, 8);
  /* if (count >= 64) {
    return _mm_slli_epi64(carry, count - 64);
  } */
  carry = _mm_srli_epi64(carry, 64 - count);
  data  = _mm_slli_epi64(data, count);
  return _mm_or_si128(data, carry);
}

/**
 * \brief Perform a right shift on a 128 bit value.
 */
static inline __m128i FN_ATTRIBUTES_SSE2 mm128_shift_right(__m128i data, unsigned int count) {
  if (!count) {
    return data;
  }

  __m128i carry = _mm_bsrli_si128(data, 8);
  /* if (count >= 64) {
    return _mm_srli_epi64(carry, count - 64);
  } */
  carry = _mm_slli_epi64(carry, 64 - count);
  data  = _mm_srli_epi64(data, count);
  return _mm_or_si128(data, carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm256_shift_right_sse(__m128i res[2],
                                                               __m128i const data[2],
                                                               unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    return;
  }

  __m128i total_carry = _mm_bslli_si128(data[1], 8);
  total_carry         = _mm_slli_epi64(total_carry, 64 - count);
  for (int i = 0; i < 2; ++i) {
    __m128i carry = _mm_bsrli_si128(data[i], 8);
    carry         = _mm_slli_epi64(carry, 64 - count);
    res[i]        = _mm_srli_epi64(data[i], count);
    res[i]        = _mm_or_si128(res[i], carry);
  }
  res[0] = _mm_or_si128(res[0], total_carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm256_shift_left_sse(__m128i res[2], __m128i const data[2],
                                                              unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    return;
  }

  __m128i total_carry = _mm_bsrli_si128(data[0], 8);
  total_carry         = _mm_srli_epi64(total_carry, 64 - count);

  for (int i = 0; i < 2; ++i) {
    __m128i carry = _mm_bslli_si128(data[i], 8);

    carry  = _mm_srli_epi64(carry, 64 - count);
    res[i] = _mm_slli_epi64(data[i], count);
    res[i] = _mm_or_si128(res[i], carry);
  }
  res[1] = _mm_or_si128(res[1], total_carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm384_shift_right_sse(__m128i res[3],
                                                               __m128i const data[3],
                                                               unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    return;
  }
  __m128i total_carry = _mm_bslli_si128(data[2], 8);
  total_carry         = _mm_slli_epi64(total_carry, 64 - count);

  mm256_shift_right_sse(&(res[0]), &(data[0]), count);
  res[2] = mm128_shift_right(data[2], count);

  res[1] = _mm_or_si128(res[1], total_carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm384_shift_left_sse(__m128i res[3], __m128i const data[3],
                                                              unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    return;
  }

  __m128i total_carry = _mm_bsrli_si128(data[1], 8);
  total_carry         = _mm_srli_epi64(total_carry, 64 - count);

  mm256_shift_left_sse(&(res[0]), &(data[0]), count);
  res[2] = mm128_shift_left(data[2], count);

  res[2] = _mm_or_si128(res[2], total_carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm512_shift_right_sse(__m128i res[4],
                                                               __m128i const data[4],
                                                               unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    res[3] = data[3];
    return;
  }
  __m128i total_carry = _mm_bslli_si128(data[2], 8);
  total_carry         = _mm_slli_epi64(total_carry, 64 - count);

  mm256_shift_right_sse(&(res[0]), &(data[0]), count);
  mm256_shift_right_sse(&(res[2]), &(data[2]), count);
  res[1] = _mm_or_si128(res[1], total_carry);
}

static inline void FN_ATTRIBUTES_SSE2_NP mm512_shift_left_sse(__m128i res[4], __m128i const data[4],
                                                              unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    res[2] = data[2];
    res[3] = data[3];
    return;
  }

  __m128i total_carry = _mm_bsrli_si128(data[1], 8);
  total_carry         = _mm_srli_epi64(total_carry, 64 - count);

  mm256_shift_left_sse(&(res[0]), &(data[0]), count);
  mm256_shift_left_sse(&(res[2]), &(data[2]), count);
  res[2] = _mm_or_si128(res[2], total_carry);
}

apply_region(mm128_xor_region, __m128i, _mm_xor_si128, FN_ATTRIBUTES_SSE2_NP);
apply_mask_region(mm128_xor_mask_region, __m128i, _mm_xor_si128, _mm_and_si128,
                  FN_ATTRIBUTES_SSE2_NP);
apply_array(mm256_xor_sse, __m128i, _mm_xor_si128, 2, FN_ATTRIBUTES_SSE2_NP);
apply_array(mm256_and_sse, __m128i, _mm_and_si128, 2, FN_ATTRIBUTES_SSE2_NP);


#undef apply_region
#undef apply_mask_region
#undef apply_array

#endif
