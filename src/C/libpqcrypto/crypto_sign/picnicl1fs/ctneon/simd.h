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
 * \brief Perform a right shift on a 128 bit value.
 */
static inline uint32x4_t mm128_shift_right(uint32x4_t data, const unsigned int count) {
  if (!count) {
    return data;
  }

  uint32x4_t carry = vmovq_n_u32(0);
  carry            = vextq_u32(data, carry, 1);
  carry            = vshlq_n_u32(carry, 32 - count);
  data             = vshrq_n_u32(data, count);
  data             = vorrq_u32(data, carry);
  return data;
}

static inline uint32x4_t mm128_shift_left(uint32x4_t data, unsigned int count) {
  if (!count) {
    return data;
  }

  uint32x4_t carry = vmovq_n_u32(0);
  carry            = vextq_u32(carry, data, 3);
  carry            = vshrq_n_u32(carry, 32 - count);
  data             = vshlq_n_u32(data, count);
  data             = vorrq_u32(data, carry);
  return data;
}

static inline void mm256_shift_right(uint32x4_t res[2], uint32x4_t const data[2],
                                     const unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    return;
  }

  uint32x4_t total_carry = vmovq_n_u32(0);
  total_carry            = vextq_u32(total_carry, data[1], 1);

  total_carry = vshlq_n_u32(total_carry, 32 - count);

  for (int i = 0; i < 2; i++) {
    uint32x4_t carry = vmovq_n_u32(0);
    carry            = vextq_u32((uint32x4_t)data[i], carry, 1);
    carry            = vshlq_n_u32(carry, 32 - count);
    res[i]           = vshrq_n_u32(data[i], count);
    res[i]           = vorrq_u32(res[i], carry);
  }

  res[0] = vorrq_u32(res[0], total_carry);
}

static inline void mm256_shift_left(uint32x4_t res[2], uint32x4_t const data[2],
                                    unsigned int count) {
  if (!count) {
    res[0] = data[0];
    res[1] = data[1];
    return;
  }

  uint32x4_t total_carry = vmovq_n_u32(0);
  total_carry            = vextq_u32((uint32x4_t)data[0], total_carry, 3);
  total_carry            = vshrq_n_u32(total_carry, 32 - count);

  for (int i = 0; i < 2; i++) {
    uint32x4_t carry = vmovq_n_u32(0);
    carry            = vextq_u32(carry, data[i], 3);
    carry            = vshrq_n_u32(carry, 32 - count);
    res[i]           = vshlq_n_u32(data[i], count);
    res[i]           = vorrq_u32(res[i], carry);
  }
  res[1] = vorrq_u32(res[1], total_carry);
}


apply_region(mm128_xor_region, uint32x4_t, veorq_u32, );
apply_mask_region(mm128_xor_mask_region, uint32x4_t, veorq_u32, vandq_u32, );
apply_array(mm256_xor, uint32x4_t, veorq_u32, 2, );
apply_array(mm256_and, uint32x4_t, vandq_u32, 2, );

#undef apply_region
#undef apply_mask_region
#undef apply_array

#endif
