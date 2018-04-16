/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */


#include "mpc.h"

#include "simd.h"

#include <string.h>

void mpc_clear(mzd_local_t* const* res, unsigned sc) {
  for (unsigned int i = 0; i < sc; i++) {
    mzd_local_clear(res[i]);
  }
}

void mpc_shift_right(mzd_local_t* const* res, mzd_local_t* const* val, unsigned count,
                     unsigned sc) {
  MPC_LOOP_CONST(mzd_shift_right, res, val, count, sc);
}

void mpc_shift_left(mzd_local_t* const* res, mzd_local_t* const* val, unsigned count, unsigned sc) {
  MPC_LOOP_CONST(mzd_shift_left, res, val, count, sc);
}

void mpc_and_const(mzd_local_t* const* result, mzd_local_t* const* first, mzd_local_t const* second,
                   unsigned sc) {
  MPC_LOOP_CONST(mzd_xor, result, first, second, sc);
}

void mpc_xor(mzd_local_t* const* result, mzd_local_t* const* first, mzd_local_t* const* second,
             unsigned sc) {
  MPC_LOOP_SHARED(mzd_xor, result, first, second, sc);
}

void mpc_and_uint64(uint64_t* res, uint64_t const* first, uint64_t const* second, uint64_t const* r,
                    view_t* view, unsigned viewshift) {
  for (unsigned m = 0; m < SC_PROOF; ++m) {
    const unsigned j = (m + 1) % SC_PROOF;
    uint64_t tmp1    = second[m] ^ second[j];
    uint64_t tmp2    = first[j] & second[m];
    tmp1             = tmp1 & first[m];
    tmp1             = tmp1 ^ tmp2;
    tmp2             = r[m] ^ r[j];
    res[m] = tmp1 = tmp1 ^ tmp2;
    tmp1          = tmp1 >> viewshift;
    view->t[m]    = view->t[m] ^ tmp1;
  }
}

#define mpc_and_def(type, and, xor, shift_right)                                                   \
  for (unsigned m = 0; m < SC_PROOF; ++m) {                                                        \
    const unsigned j = (m + 1) % SC_PROOF;                                                         \
    type* sm         = __builtin_assume_aligned(FIRST_ROW(view->s[m]), alignof(type));             \
    type tmp1        = (xor)(second[m], second[j]);                                                \
    type tmp2        = (and)(first[j], second[m]);                                                 \
    tmp1             = (and)(tmp1, first[m]);                                                      \
    tmp1             = (xor)(tmp1, tmp2);                                                          \
    tmp2             = (xor)(r[m], r[j]);                                                          \
    res[m] = tmp1 = (xor)(tmp1, tmp2);                                                             \
    tmp1          = (shift_right)(tmp1, viewshift);                                                \
    *sm           = (xor)(tmp1, *sm);                                                              \
  }

#define mpc_and_def_multiple(type, and, xor, shift_right, size)                                    \
  for (unsigned m = 0; m < SC_PROOF; ++m) {                                                        \
    const unsigned j = (m + 1) % SC_PROOF;                                                         \
    type* sm         = __builtin_assume_aligned(FIRST_ROW(view->s[m]), alignof(type));             \
    type tmp1[size], tmp2[size];                                                                   \
    (xor)(tmp1, second[m], second[j]);                                                             \
    (and)(tmp2, first[j], second[m]);                                                              \
    (and)(tmp1, tmp1, first[m]);                                                                   \
    (xor)(tmp1, tmp1, tmp2);                                                                       \
    (xor)(tmp2, r[m], r[j]);                                                                       \
    (xor)(tmp1, tmp1, tmp2);                                                                       \
    memcpy(res[m], tmp1, size * sizeof(type));                                                     \
    (shift_right)(tmp1, tmp1, viewshift);                                                          \
    (xor)(sm, tmp1, sm);                                                                           \
  }


void mpc_and_neon(uint32x4_t* res, uint32x4_t const* first, uint32x4_t const* second,
                  uint32x4_t const* r, view_t* view, unsigned viewshift) {
  mpc_and_def(uint32x4_t, vandq_u32, veorq_u32, mm128_shift_right);
}

void mpc_and_256_neon(uint32x4_t res[SC_PROOF][2], uint32x4_t const first[SC_PROOF][2],
                      uint32x4_t const second[SC_PROOF][2], uint32x4_t const r[SC_PROOF][2],
                      view_t* view, unsigned viewshift) {
  mpc_and_def_multiple(uint32x4_t, mm256_and, mm256_xor, mm256_shift_right, 2);
}


void mpc_and(mzd_local_t* const* res, mzd_local_t* const* first, mzd_local_t* const* second,
             mzd_local_t* const* r, view_t* view, unsigned viewshift, mzd_local_t* const* buffer) {
  mzd_local_t* b = buffer[0];

  for (unsigned m = 0; m < SC_PROOF; ++m) {
    const unsigned j = (m + 1) % SC_PROOF;

    // f[m] & s[m]
    mzd_and(res[m], first[m], second[m]);

    // f[m + 1] & s[m]
    mzd_and(b, first[j], second[m]);
    mzd_xor(res[m], res[m], b);

    // f[m] & s[m + 1]
    mzd_and(b, first[m], second[j]);
    mzd_xor(res[m], res[m], b);

    // ... ^ r[m] ^ r[m + 1]
    mzd_xor(res[m], res[m], r[m]);
    mzd_xor(res[m], res[m], r[j]);
  }

  mpc_shift_right(buffer, res, viewshift, SC_PROOF);
  mpc_xor(view->s, view->s, buffer, SC_PROOF);
}

void mpc_and_verify_uint64(uint64_t* res, uint64_t const* first, uint64_t const* second,
                           uint64_t const* r, view_t* view, uint64_t const mask,
                           unsigned viewshift) {
  for (unsigned m = 0; m < (SC_VERIFY - 1); ++m) {
    const unsigned j = (m + 1);
    uint64_t tmp1    = second[m] ^ second[j];
    uint64_t tmp2    = first[j] & second[m];
    tmp1             = tmp1 & first[m];
    tmp1             = tmp1 ^ tmp2;
    tmp2             = r[m] ^ r[j];
    res[m] = tmp1 = tmp1 ^ tmp2;
    tmp1          = tmp1 >> viewshift;
    view->t[m]    = view->t[m] ^ tmp1;
  }
  uint64_t s1        = (view->t[SC_VERIFY - 1]);
  uint64_t rsc       = s1 << viewshift;
  res[SC_VERIFY - 1] = rsc & mask;
}

#define mpc_and_verify_def(type, and, xor, shift_right, shift_left)                                \
  for (unsigned m = 0; m < (SC_VERIFY - 1); ++m) {                                                 \
    const unsigned j = (m + 1);                                                                    \
    type* sm         = __builtin_assume_aligned(FIRST_ROW(view->s[m]), alignof(type));             \
    type tmp1        = (xor)(second[m], second[j]);                                                \
    type tmp2        = (and)(first[j], second[m]);                                                 \
    tmp1             = (and)(tmp1, first[m]);                                                      \
    tmp1             = (xor)(tmp1, tmp2);                                                          \
    tmp2             = (xor)(r[m], r[j]);                                                          \
    res[m] = tmp1 = (xor)(tmp1, tmp2);                                                             \
    tmp1          = (shift_right)(tmp1, viewshift);                                                \
    *sm           = (xor)(tmp1, *sm);                                                              \
  }                                                                                                \
  type const* s1 =                                                                                 \
      __builtin_assume_aligned(CONST_FIRST_ROW(view->s[SC_VERIFY - 1]), alignof(type));            \
  type rsc           = (shift_left)(*s1, viewshift);                                               \
  res[SC_VERIFY - 1] = (and)(rsc, mask);

#define mpc_and_verify_def_multiple(type, and, xor, shift_right, shift_left, size)                 \
  for (unsigned m = 0; m < (SC_VERIFY - 1); ++m) {                                                 \
    const unsigned j = (m + 1);                                                                    \
    type* sm         = __builtin_assume_aligned(FIRST_ROW(view->s[m]), alignof(type));             \
    type tmp1[size], tmp2[size];                                                                   \
    (xor)(tmp1, second[m], second[j]);                                                             \
    (and)(tmp2, first[j], second[m]);                                                              \
    (and)(tmp1, tmp1, first[m]);                                                                   \
    (xor)(tmp1, tmp1, tmp2);                                                                       \
    (xor)(tmp2, r[m], r[j]);                                                                       \
    (xor)(tmp1, tmp1, tmp2);                                                                       \
    memcpy(res[m], tmp1, size * sizeof(type));                                                     \
    (shift_right)(tmp1, tmp1, viewshift);                                                          \
    (xor)(sm, tmp1, sm);                                                                           \
    uint64_t* tmp = (uint64_t*)&(view->t[m]);                                                      \
    *tmp ^= ((uint64_t*)&tmp1)[sizeof(type) / sizeof(uint64_t) - 1];                               \
  }                                                                                                \
  type const* s1 =                                                                                 \
      __builtin_assume_aligned(CONST_FIRST_ROW(view->s[SC_VERIFY - 1]), alignof(type));            \
  type rsc[size];                                                                                  \
  (shift_left)(rsc, s1, viewshift);                                                                \
  (and)(res[SC_VERIFY - 1], rsc, mask);


void mpc_and_verify(mzd_local_t* const* res, mzd_local_t* const* first, mzd_local_t* const* second,
                    mzd_local_t* const* r, view_t* view, mzd_local_t const* mask,
                    unsigned viewshift, mzd_local_t* const* buffer) {
  mzd_local_t* b = buffer[0];

  for (unsigned m = 0; m < (SC_VERIFY - 1); ++m) {
    const unsigned j = m + 1;

    mzd_and(res[m], first[m], second[m]);

    mzd_and(b, first[j], second[m]);
    mzd_xor(res[m], res[m], b);

    mzd_and(b, first[m], second[j]);
    mzd_xor(res[m], res[m], b);

    mzd_xor(res[m], res[m], r[m]);
    mzd_xor(res[m], res[m], r[j]);
  }

  for (unsigned m = 0; m < (SC_VERIFY - 1); ++m) {
    mzd_shift_right(b, res[m], viewshift);
    mzd_xor(view->s[m], view->s[m], b);
  }

  mzd_shift_left(res[SC_VERIFY - 1], view->s[SC_VERIFY - 1], viewshift);
  mzd_and(res[SC_VERIFY - 1], res[SC_VERIFY - 1], mask);
}

void mpc_copy(mzd_local_t** out, mzd_local_t* const* in, unsigned sc) {
  for (unsigned i = 0; i < sc; ++i) {
    mzd_local_copy(out[i], in[i]);
  }
}
