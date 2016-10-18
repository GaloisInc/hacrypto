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
#define ONE   #1
#define EIGHT #8

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

#define SPECK_ENC_ROUND_(x1, x0, y1, y0, k, tmp)  \
  RCS8_(x1, x0, tmp)                              \
  /* x += y */                                    \
  add  y0, x0              \n\t                   \
  addc y1, x1              \n\t                   \
  /* x ^= key */                                  \
  xor @k+, x0              \n\t                   \
  xor @k+, x1              \n\t                   \
                                                  \
  LCS3_(y1, y0)                                   \
                                                  \
  /* y ^= x */                                    \
  xor x0, y0               \n\t                   \
  xor x1, y1               \n\t


#define SPECK_ENC_KS_ROUND_(x1, x0, y1, y0, k, tmp)  \
  RCS8_(x1, x0, tmp)                                 \
  /* x += y */                                       \
  add  y0, x0              \n\t                      \
  addc y1, x1              \n\t                      \
  /* x ^= key */                                     \
  xor k, x0                \n\t                      \
                                                     \
  LCS3_(y1, y0)                                      \
                                                     \
  /* y ^= x */                                       \
  xor x0, y0               \n\t                      \
  xor x1, y1               \n\t


#define SPECK_DEC_ROUND_(x1, x0, y1, y0, k, tmp)             \
  /* y ^= x */                                               \
  xor x0, y0              \n\t                               \
  xor x1, y1              \n\t                               \
                                                             \
  /* y = RCS3(y) */                                          \
  RCS3_(y1, y0)                                              \
                                                             \
  /* x ^= k */                                               \
  xor @k+, x0             \n\t                               \
  xor @k+, x1             \n\t                               \
                                                             \
  /* Jump back to the beginning of the previous key word */  \
  sub EIGHT, k            \n\t                               \
                                                             \
  /* x -= y */                                               \
  sub  y0, x0             \n\t                               \
  subc y1, x1             \n\t                               \
                                                             \
  /* x = LCS8(x) */                                          \
  LCS8_(x1, x0, tmp)


#define LCS1(x1, x0)      STR(LCS1_(x1, x0))
#define LCS3(x1, x0)      STR(LCS3_(x1, x0))
#define LCS8(x1, x0, tmp) STR(LCS8_(x1, x0, tmp))
#define RCS1(x1, x0)      STR(RCS1_(x1, x0))
#define RCS3(x1, x0)      STR(RCS3_(x1, x0))
#define RCS8(x1, x0, tmp) STR(RCS8_(x1, x0, tmp))

#define SPECK_ENC_ROUND(x1, x0, y1, y0, k, tmp) \
  STR(SPECK_ENC_ROUND_(x1, x0, y1, y0, k, tmp))

#define SPECK_ENC_KS_ROUND(x1, x0, y1, y0, k, tmp) \
  STR(SPECK_ENC_KS_ROUND_(x1, x0, y1, y0, k, tmp))

#define SPECK_ENC_ROUND2(x1, x0, y1, y0, k, tmp) \
  SPECK_ENC_ROUND(x1, x0, y1, y0, k, tmp)        \
  SPECK_ENC_ROUND(x1, x0, y1, y0, k, tmp)

#define SPECK_ENC_ROUND3(x1, x0, y1, y0, k, tmp) \
  SPECK_ENC_ROUND2(x1, x0, y1, y0, k, tmp)       \
  SPECK_ENC_ROUND(x1, x0, y1, y0, k, tmp)

#define SPECK_DEC_ROUND(x1, x0, y1, y0, k, tmp) \
  STR(SPECK_DEC_ROUND_(x1, x0, y1, y0, k, tmp))

#define SPECK_DEC_ROUND2(x1, x0, y1, y0, k, tmp) \
  SPECK_DEC_ROUND(x1, x0, y1, y0, k, tmp)        \
  SPECK_DEC_ROUND(x1, x0, y1, y0, k, tmp)

#define SPECK_DEC_ROUND3(x1, x0, y1, y0, k, tmp) \
  SPECK_DEC_ROUND2(x1, x0, y1, y0, k, tmp)       \
  SPECK_DEC_ROUND(x1, x0, y1, y0, k, tmp)
