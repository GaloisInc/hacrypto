/*
 * This is a work of the U.S. Government and is not subject to copyright
 * protection in the United States. Foreign copyrights may apply.
 *
 * Written in 2015 by Jason Smith <jksmit3@tycho.ncsc.mil> and
 *                    Bryan Weeks <beweeks@tycho.ncsc.mil>
 */

/* Macros for use in GCC basic asm statements for the MSP430 */

#include "stringify.h"

/* Left circular shift in place */
#define LCS1_(x1, x0)             \
  rla x0                    \n\t  \
  rlc x1                    \n\t  \
  adc x0                    \n\t

/* Rotate a 32-bit word left by three bits */
#define LCS3_(x1, x0)             \
  LCS1_(x1, x0)                   \
  LCS1_(x1, x0)                   \
  LCS1_(x1, x0)


/*
 * Rotate a 32-bit word left by eight bits
 *
 * Start with the following bytes:
 *
 * x_3 x_2 x_1 x_0
 *
 * Swap both words to get the upper bytes in the right position.  Then
 * setup the tmp register to leave the upper byte alone and swap the
 * lower byte.
 *
 * swpb x 2 -> x_2 x_3 x_0 x_1
 * tmp      -> 0 x_1
 * tmp      -> 0 x_1^x_3
 * xor  x 2 -> x_2 x_1 x_0 x_3
 *
 */

#define LCS8_(x1, x0, tmp)        \
    swpb  x0                \n\t  \
    swpb  x1                \n\t  \
    mov.b x0, tmp           \n\t  \
    xor.b x1, tmp           \n\t  \
    xor   tmp, x1           \n\t  \
    xor   tmp, x0           \n\t

/* Right circular shift in place */

/*
 * The easiest way to get the least significant bit into the carry would
 * be the following:
 *
 * bit #1, x0
 *
 * This should use the constant generator and therefore take one cycle
 * and one word of code. It appears the mspdebug simulator before
 * version 0.23 doesn't count this correctly and counts three
 * cycles. The following alternative uses two words of code and a
 * temporary register, but only two cycles:
 *
 * mov x0, tmp
 * rrc tmp
 *
 */

/* Avoid problems with pound signs in macros */
#define ONE #1

#define RCS1_(x1, x0)       \
  bit ONE, x0          \n\t \
  rrc x1               \n\t \
  rrc x0               \n\t

/* Rotate a 32-bit word right by three bits */
#define RCS3_(x1, x0)   \
  RCS1_(x1, x0)         \
  RCS1_(x1, x0)         \
  RCS1_(x1, x0)

/* Rotate a 32-bit word right by eight bits */
#define RCS8_(x1, x0, tmp)       \
  mov.b x0, tmp             \n\t \
  xor.b x1, tmp             \n\t \
  swpb tmp                  \n\t \
  swpb x0                   \n\t \
  swpb x1                   \n\t \
  xor  tmp, x0              \n\t \
  xor  tmp, x1              \n\t


#define SIMON_ENC_ROUND_(x1, x0, y1, y0, k, tmp4, tmp3, tmp2, tmp1, tmp0) \
  /* Copy x to save for y and create rotated version  */                  \
  mov x1, tmp3                 \n\t                                       \
  mov x0, tmp2                 \n\t                                       \
  mov x1, tmp1                 \n\t                                       \
  mov x0, tmp0                 \n\t                                       \
  /* x = S8(x) */                                                         \
  LCS8_(x1, x0, tmp4)                                                     \
  /* tmp0 = S1(tmp0) */                                                   \
  LCS1_(tmp1, tmp0)                                                       \
  /* x &= tmp0 */                                                         \
  and tmp1, x1                 \n\t                                       \
  and tmp0, x0                 \n\t                                       \
  /* Make S2(x) */                                                        \
  LCS1_(tmp1, tmp0)                                                       \
  /* x ^= S2(x) */                                                        \
  xor tmp1, x1                 \n\t                                       \
  xor tmp0, x0                 \n\t                                       \
  /* x ^= k */                                                            \
  xor @k+, x0                  \n\t                                       \
  xor @k+, x1                  \n\t                                       \
  /* x ^= y */                                                            \
  xor y1, x1                   \n\t                                       \
  xor y0, x0                   \n\t                                       \
  /* y = tmp (saved x) */                                                 \
  mov tmp3, y1                 \n\t                                       \
  mov tmp2, y0                 \n\t

/*
 * Compute y = y ^ k ^ f(x) leaving x unmodified
 *
 * Two rounds of SIMON can then be performed by doing this twice,
 * swapping x and y the second time.
 */

#define SIMON_ENC_ROUND2_BASE_(x1, x0, y1, y0, k, tmp4, tmp3, tmp2, tmp1, tmp0) \
  /* tmp1 = tmp0 = x */                                                         \
  mov x1, tmp3                 \n\t                                             \
  mov x0, tmp2                 \n\t                                             \
  mov x1, tmp1                 \n\t                                             \
  mov x0, tmp0                 \n\t                                             \
  /* tmp1 = S8(x) */                                                            \
  LCS8_(tmp3, tmp2, tmp4)                                                       \
  /* tmp0 = S1(tmp0) */                                                         \
  LCS1_(tmp1, tmp0)                                                             \
  /* tmp1 &= tmp0 */                                                            \
  and tmp1, tmp3               \n\t                                             \
  and tmp0, tmp2               \n\t                                             \
  /* Make S2(x) */                                                              \
  LCS1_(tmp1, tmp0)                                                             \
  /* tmp1 ^= S2(x) */                                                           \
  xor tmp1, tmp3               \n\t                                             \
  xor tmp0, tmp2               \n\t                                             \
  /* tmp1 ^= k */                                                               \
  xor @k+, tmp2                \n\t                                             \
  xor @k+, tmp3                \n\t                                             \
  /* y ^= tmp1 */                                                               \
  xor tmp3, y1                 \n\t                                             \
  xor tmp2, y0                 \n\t

#define RCS1(x1, x0) STR(RCS1_(x1, x0))
#define RCS3(x1, x0) STR(RCS3_(x1, x0))

#define SIMON_ENC_ROUND2_(x1, x0, y1, y0, k, tmp4, tmp3, tmp2, tmp1, tmp0) \
  SIMON_ENC_ROUND2_BASE_(x1, x0, y1, y0, k, tmp4, tmp3, tmp2, tmp1, tmp0)  \
  SIMON_ENC_ROUND2_BASE_(y1, y0, x1, x0, k, tmp4, tmp3, tmp2, tmp1, tmp0)

#define SIMON_ENC_ROUND(x1, x0, y1, y0, k, tmp, tmp3, tmp2, tmp1, tmp0) \
  STR(SIMON_ENC_ROUND_(x1, x0, y1, y0, k, tmp, tmp3, tmp2, tmp1, tmp0))

#define SIMON_ENC_ROUND2_BASE(x1, x0, y1, y0, k, tmp, tmp3, tmp2, tmp1, tmp0) \
  STR(SIMON_ENC_ROUND2_BASE_(x1, x0, y1, y0, k, tmp, tmp3, tmp2, tmp1, tmp0))

#define SIMON_ENC_ROUND2(x1, x0, y1, y0, k, tmp, tmp3, tmp2, tmp1, tmp0) \
  STR(SIMON_ENC_ROUND2_(x1, x0, y1, y0, k, tmp, tmp3, tmp2, tmp1, tmp0))

