/*
 * This is a work of the U.S. Government and is not subject to copyright
 * protection in the United States. Foreign copyrights may apply.
 *
 * Written in 2015 by Jason Smith <jksmit3@tycho.ncsc.mil> and
 *                    Bryan Weeks <beweeks@tycho.ncsc.mil>
 */

/* Macros for use in GCC basic asm statements for the AVR */

#include "stringify.h"

/* x += y */
/* Results in S^8(S^{-8}(x) + y) */
#define ADD_(x3, x2, x1, x0, y3, y2, y1, y0)            \
  add x1, y0                                       \n\t \
  adc x2, y1                                       \n\t \
  adc x3, y2                                       \n\t \
  adc x0, y3                                       \n\t

/* x -= y */
#define SUB_(x3, x2, x1, x0, y3, y2, y1, y0)            \
  sub x0, y0                                       \n\t \
  sbc x1, y1                                       \n\t \
  sbc x2, y2                                       \n\t \
  sbc x3, y3                                       \n\t

/* x ^= y */
/* Needs to be done out of order to correct the S^8 above */
#define XOR_SHIFT_(x3, x2, x1, x0, y3, y2, y1, y0)      \
  eor x0, y1                                       \n\t \
  eor x1, y2                                       \n\t \
  eor x2, y3                                       \n\t \
  eor x3, y0                                       \n\t

/* x ^= ROL8(y) */
#define XOR_SHIFT_ROL8_(x3, x2, x1, x0, y3, y2, y1, y0) \
  eor x0, y3                                       \n\t \
  eor x1, y0                                       \n\t \
  eor x2, y1                                       \n\t \
  eor x3, y2                                       \n\t

/* x ^= y */
#define XOR_(x3, x2, x1, x0, y3, y2, y1, y0)            \
  eor x0, y0                                       \n\t \
  eor x1, y1                                       \n\t \
  eor x2, y2                                       \n\t \
  eor x3, y3                                       \n\t \

#define LOAD_FLASH_KEY_(x3, x2, x1, x0)                 \
  lpm x0, z+                                       \n\t \
  lpm x1, z+                                       \n\t \
  lpm x2, z+                                       \n\t \
  lpm x3, z+                                       \n\t

#define LOAD_RAM_KEY_(x3, x2, x1, x0)                   \
  ld x0, z+                                        \n\t \
  ld x1, z+                                        \n\t \
  ld x2, z+                                        \n\t \
  ld x3, z+                                        \n\t

#define LOAD_FLASH_KEY_DEC_(x3, x2, x1, x0)             \
  lpm  x0,  z+                                     \n\t \
  lpm  x1,  z+                                     \n\t \
  lpm  x2,  z+                                     \n\t \
  lpm  x3,  z+                                     \n\t \
  sbiw r30, 8                                      \n\t

#define LOAD_RAM_KEY_DEC_(x3, x2, x1, x0)               \
  ld x3, -z                                        \n\t \
  ld x2, -z                                        \n\t \
  ld x1, -z                                        \n\t \
  ld x0, -z                                        \n\t

/* Left circular shift in place */
#define LCS1_(x3, x2, x1, x0)                           \
  lsl x0                                           \n\t \
  rol x1                                           \n\t \
  rol x2                                           \n\t \
  rol x3                                           \n\t \
  adc x0, r1                                       \n\t

/* Left circular shift y by three bits with results ending in x */
#define LCS3_MULT_(x3, x2, x1, x0, y3, y2, y1, y0, eight_reg) \
  mul  y0, eight_reg                                     \n\t \
  movw x0, r0                                            \n\t \
  mul  y2, eight_reg                                     \n\t \
  movw x2, r0                                            \n\t \
  mul  y1, eight_reg                                     \n\t \
  eor  x1, r0                                            \n\t \
  eor  x2, r1                                            \n\t \
  mul  y3, eight_reg                                     \n\t \
  eor  x3, r0                                            \n\t \
  eor  x0, r1                                            \n\t

/*
 * Right circular shift in place
 *
 * Store the least significant bit in the T flag and copy it to the most
 * significant bit at the end
 */

#define RCS1_(x3, x2, x1, x0)                                 \
  bst x0, 0                                              \n\t \
  ror x3                                                 \n\t \
  ror x2                                                 \n\t \
  ror x1                                                 \n\t \
  ror x0                                                 \n\t \
  bld x3, 7                                              \n\t

/* x = y */
#define MOV_(x3, x2, x1, x0, y3, y2, y1, y0)                  \
  movw x0, y0                                            \n\t \
  movw x2, y2                                            \n\t

/* x = ROL8(y) */
#define MOV_ROL8_(x3, x2, x1, x0, y3, y2, y1, y0)             \
  mov x0, y3                                             \n\t \
  mov x1, y0                                             \n\t \
  mov x2, y1                                             \n\t \
  mov x3, y2                                             \n\t

/*
 * A SPECK round function optimized for the key schedule No unrolling is
 * done, and we take advantage of the fact the key is only a single
 * byte.
 */
#define SPECK_KS_ROUND_(x3, x2, x1, x0, y3, y2, y1, y0, tmp, i) \
  /* Rotate x by 8 */                                      \n\t \
  mov tmp, x0                                              \n\t \
  mov x0,  x1                                              \n\t \
  mov x1,  x2                                              \n\t \
  mov x2,  x3                                              \n\t \
  mov x3,  tmp                                             \n\t \
  /* x += y */                                             \n\t \
  add x0, y0                                               \n\t \
  adc x1, y1                                               \n\t \
  adc x2, y2                                               \n\t \
  adc x3, y3                                               \n\t \
  /* x ^= k[i] */                                          \n\t \
  eor x0, i                                                \n\t \
  /* Rotate y */                                           \n\t \
  LCS3_(y3, y2, y1, y0)                                    \n\t \
  /* y ^= x */                                             \n\t \
  XOR_(y3, y2, y1, y0, x3, x2, x1, x0)


#define LCS3_(x3, x2, x1, x0)                                   \
  LCS1_(x3, x2, x1, x0)                                         \
  LCS1_(x3, x2, x1, x0)                                         \
  LCS1_(x3, x2, x1, x0)

#define RCS3_(x3, x2, x1, x0)                                   \
  RCS1_(x3, x2, x1, x0)                                         \
  RCS1_(x3, x2, x1, x0)                                         \
  RCS1_(x3, x2, x1, x0)

/* Make stringified versions of these macros useful externally */
#define LCS3(x3, x2, x1, x0)                                   \
  STR(LCS3_(x3, x2, x1, x0))

#define RCS3(x3, x2, x1, x0)                                   \
  STR(RCS3_(x3, x2, x1, x0))

#define LCS3_MULT(x3, x2, x1, x0, y3, y2, y1, y0, eight_reg)   \
  STR(LCS3_MULT_(x3, x2, x1, x0, y3, y2, y1, y0, eight_reg))

#define ADD(x3, x2, x1, x0, y3, y2, y1, y0)                    \
  STR(ADD_(x3, x2, x1, x0, y3, y2, y1, y0))

#define SUB(x3, x2, x1, x0, y3, y2, y1, y0)                    \
  STR(SUB_(x3, x2, x1, x0, y3, y2, y1, y0))

#define XOR_SHIFT(x3, x2, x1, x0, y3, y2, y1, y0)              \
  STR(XOR_SHIFT_(x3, x2, x1, x0, y3, y2, y1, y0))

#define XOR_SHIFT_ROL8(x3, x2, x1, x0, y3, y2, y1, y0)         \
  STR(XOR_SHIFT_ROL8_(x3, x2, x1, x0, y3, y2, y1, y0))

#define XOR(x3, x2, x1, x0, y3, y2, y1, y0)                    \
  STR(XOR_(x3, x2, x1, x0, y3, y2, y1, y0))

#define MOV(x3, x2, x1, x0, y3, y2, y1, y0)                    \
  STR(MOV_(x3, x2, x1, x0, y3, y2, y1, y0))

#define MOV_ROL8(x3, x2, x1, x0, y3, y2, y1, y0)               \
  STR(MOV_ROL8_(x3, x2, x1, x0, y3, y2, y1, y0))

#define SPECK_KS_ROUND(x3, x2, x1, x0, y3, y2, y1, y0, tmp, i) \
  STR(SPECK_KS_ROUND_(x3, x2, x1, x0, y3, y2, y1, y0, tmp, i))

#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define LOAD_KEY(x3, x2, x1, x0)     \
  STR(LOAD_FLASH_KEY_(x3, x2, x1, x0))

#define LOAD_KEY_DEC(x3, x2, x1, x0) \
  STR(LOAD_FLASH_KEY_DEC_(x3, x2, x1, x0))

#else

#define LOAD_KEY(x3, x2, x1, x0)     \
  STR(LOAD_RAM_KEY_(x3, x2, x1, x0))
#define LOAD_KEY_DEC(x3, x2, x1, x0) \
  STR(LOAD_RAM_KEY_DEC_(x3, x2, x1, x0))

#endif

/* Basic round from Table 3 */
#define SPECK_ENC_ROUND(x3, x2, x1, x0, y3, y2, y1, y0, k3, k2, k1, k0) \
  LOAD_KEY(k3, k2, k1, k0)                                              \
  ADD(x3, x2, x1, x0, y3, y2, y1, y0)                                   \
  XOR_SHIFT(k3, k2, k1, k0, x3, x2, x1, x0)                             \
  LCS3(y3, y2, y1, y0)                                                  \
  XOR(y3, y2, y1, y0, k3, k2, k1, k0)                                   \
  MOV(x3, x2, x1, x0, k3, k2, k1, k0)

#define SPECK_DEC_ROUND(x3, x2, x1, x0, y3, y2, y1, y0, k3, k2, k1, k0) \
  XOR(y3, y2, y1, y0, x3, x2, x1, x0)                                   \
  RCS3(y3, y2, y1, y0)                                                  \
  LOAD_KEY_DEC(k3, k2, k1, k0)                                          \
  XOR(k3, k2, k1, k0, x3, x2, x1, x0)                                   \
  SUB(k3, k2, k1, k0, y3, y2, y1, y0)                                   \
  MOV_ROL8(x3, x2, x1, x0, k3, k2, k1, k0)

#define SPECK_DEC_ROUND2(x3, x2, x1, x0, y3, y2, y1, y0, k3, k2, k1, k0) \
  XOR(y3, y2, y1, y0, x3, x2, x1, x0)                                    \
  RCS3(y3, y2, y1, y0)                                                   \
  LOAD_KEY_DEC(k0, k3, k2, k1)                                           \
  XOR_SHIFT_ROL8(k3, k2, k1, k0, x3, x2, x1, x0)                         \
  SUB(k0, k3, k2, k1, y3, y2, y1, y0)                                    \
  /* Round 2 */                                                          \
  XOR(y3, y2, y1, y0, k3, k2, k1, k0)                                    \
  RCS3(y3, y2, y1, y0)                                                   \
  LOAD_KEY_DEC(x0, x3, x2, x1)                                           \
  XOR_SHIFT_ROL8(x3, x2, x1, x0, k3, k2, k1, k0)                         \
  SUB(x0, x3, x2, x1, y3, y2, y1, y0)

#define SPECK_DEC_ROUND3(x3, x2, x1, x0, y3, y2, y1, y0, k3, k2, k1, k0) \
  SPECK_DEC_ROUND2(x3, x2, x1, x0, y3, y2, y1, y0, k3, k2, k1, k0)       \
  SPECK_DEC_ROUND(x3, x2, x1, x0, y3, y2, y1, y0, k3, k2, k1, k0)

/* Unroll two rounds as documented in Table 4 */
#define SPECK_ENC_ROUND2(x3, x2, x1, x0, y3, y2, y1, y0, k3, k2, k1, k0) \
   LOAD_KEY(k3, k2, k1, k0)                                              \
   ADD(x3, x2, x1, x0, y3, y2, y1, y0)                                   \
   XOR_SHIFT(k3, k2, k1, k0, x3, x2, x1, x0)                             \
   LCS3(y3, y2, y1, y0)                                                  \
   XOR(y3, y2, y1, y0, k3, k2, k1, k0)                                   \
   LOAD_KEY(x3, x2, x1, x0)                                              \
   ADD(k3, k2, k1, k0, y3, y2, y1, y0)                                   \
   XOR_SHIFT(x3, x2, x1, x0, k3, k2, k1, k0)                             \
   LCS3(y3, y2, y1, y0)                                                  \
   XOR(y3, y2, y1, y0, x3, x2, x1, x0)

/* Single round as in Table 5 */
#define SPECK_ENC_ROUND_MULT(x3, x2, x1, x0, y3, y2, y1, y0, k3, k2, k1, k0, eight_reg) \
  LOAD_KEY(k3, k2, k1, k0)                                                              \
  ADD(x3, x2, x1, x0, y3, y2, y1, y0)                                                   \
  XOR_SHIFT(k3, k2, k1, k0, x3, x2, x1, x0)                                             \
  LCS3_MULT(x3, x2, x1, x0, y3, y2, y1, y0, eight_reg)                                  \
  XOR(x3, x2, x1, x0, k3, k2, k1, k0)

/* Unroll three rounds as documented in Table 6 */
#define SPECK_ENC_ROUND3(x3, x2, x1, x0, y3, y2, y1, y0, k3, k2, k1, k0, eight_reg) \
  LOAD_KEY(k3, k2, k1, k0)                                                          \
  ADD(x3, x2, x1, x0, y3, y2, y1, y0)                                               \
  XOR_SHIFT(k3, k2, k1, k0, x3, x2, x1, x0)                                         \
  LCS3_MULT(x3, x2, x1, x0, y3, y2, y1, y0, eight_reg)                              \
  XOR(x3, x2, x1, x0, k3, k2, k1, k0)                                               \
  LOAD_KEY(y3, y2, y1, y0)                                                          \
  ADD(k3, k2, k1, k0, x3, x2, x1, x0)                                               \
  XOR_SHIFT(y3, y2, y1, y0, k3, k2, k1, k0)                                         \
  LCS3_MULT(k3, k2, k1, k0, x3, x2, x1, x0, eight_reg)                              \
  XOR(k3, k2, k1, k0, y3, y2, y1, y0)                                               \
  LOAD_KEY(x3, x2, x1, x0)                                                          \
  ADD(y3, y2, y1, y0, k3, k2, k1, k0)                                               \
  XOR_SHIFT(x3, x2, x1, x0, y3, y2, y1, y0)                                         \
  LCS3_MULT(y3, y2, y1, y0, k3, k2, k1, k0, eight_reg)                              \
  XOR(y3, y2, y1, y0, x3, x2, x1, x0)
