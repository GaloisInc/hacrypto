/* test_gfshare_isfield copyright 2006 Simon McVittie <smcv pseudorandom co uk>
 * Released under the same terms and lack-of-warranty as libgfshare itself.
 *
 * Demonstrate that the field used in libgfshare is in fact a field, by
 * exhaustive calculation. A proper proof would be much more elegant, but
 * I need to read up on Galois fields in order to produce one.
 */

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "libgfshare_tables.h"

typedef unsigned char byte;

/** Assert that predicate is true. If not, display it along with the values
 * of integer variables a, b and c, which must be in scope wherever this
 * macro is used, and abort.
 */
#define myassert(predicate) \
    do { \
        if (!(predicate)) { \
            fprintf(stderr, "Assertion failed: %s (with a=%d b=%d c=%d)\n", \
                    #predicate, a, b, c); \
            abort();\
        } \
    } while (0)

/* ----------------------------------------------------------------- */
/* Naive implementations of the field operations.
 * Note that by construction, these use no more than the following lookup
 * table elements:
 * - logs[1] up to logs[255]
 * - exps[0] up to exps[254] (but not exps[255]!)
 */

/** The field addition operation a(+)b. */
static inline byte plus(byte a, byte b)
{
    return (a^b) & 255;
}

/** The field multiplication operation a(x)b. */
static inline byte times(byte a, byte b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    return exps[(logs[a]+logs[b]) % 255];
}

/** The additive inverse (-)b. */
static inline byte addinv(byte b)
{
    return b;
}

/** The multiplicative inverse b^{-1}. */
static inline byte multiinv(byte b)
{
    assert(b != 0);     /* 0 has no multiplicative inverse */
    return exps[255 - logs[b]];
}

static void verify_naive(void)
{
    register int a, b = -1, c = -1;

    for (a = 0; a < 256; a++) {
        /* Identities */
        myassert(plus(a, 0) == a);
        myassert(times(a, 1) == a);
        /* Inverses */
        myassert(plus(addinv(a), a) == 0);
        if (a != 0) {
            myassert(times(multiinv(a), a) == 1);
        }
        for (b = 0; b < 256; b++) {
            /* Commutativity */
            myassert(plus(a, b) == plus(b, a));
            myassert(times(a, b) == times(b, a));
            for (c = 0; c < 256; c++) {
                /* Associativity */
                myassert(plus(plus(a, b), c) == plus(a, plus(b, c)));
                myassert(times(times(a, b), c) == times(a, times(b, c)));
                /* Distributivity */
                myassert(times(a, plus(b, c)) == plus(times(a, b), times(a, c)));
            }
        }
    }
}

/* ----------------------------------------------------------------- */
/* Optimized versions:
 *
 * libgfshare in fact takes some short-cuts in its implementation.
 *
 * Firstly, the exps table is twice as long as would be required by the
 * naive implementation above, with exps[255] == exps[0], ...,
 * exps[509] == exps[254]. This means that the instance of
 * exps[(logs[a] + logs[b]) & 255] seen in the field multiplication operation
 * can be replaced by exps[logs[a] + logs[b]] if logs[a], logs[b] are known to
 * be no greater than 254.
 *
 * By construction, all elements of the logs table are no greater than 254,
 * so this can be used to simplify the multiplication operation.
 *
 * Secondly, libgfshare exploits the fact that exp and log are inverses
 * to reduce the number of exp operations needed: instead of implementing
 * a(x)b(x)...(x)z naively as
 *      exps[(logs[a]+logs[exps[(logs[b] + logs[exps[...]]) % 255]]) % 255]
 * it uses
 *      exps[(logs[a] + (logs[b] + ...) % 255) % 255]
 */

static void verify_opt(void)
{
    register int a;
    int b = -1, c = -1;

    for (a = 0; a < 256; a++) {
        if (a != 255) {
            myassert(exps[a] == exps[a + 255]);
            myassert(logs[exps[a]] == a);
        }
        if (a != 0) {
            myassert(logs[a] <= 254);
            myassert(exps[logs[a]] == a);
        }
    }
}

/* ----------------------------------------------------------------- */
int main(void)
{
    verify_naive();
    verify_opt();
    return 0;
}
