#include "reedsolomon.h"
#include "gf256x.h"
#include <stdio.h>
#include <stdlib.h>

/* reversed order! I.e. the least significant coefficient comes last. */
unsigned char generator_data[RS_DELTA] = 
{
    0x58,  0xd8,  0xc3,  0x17,  0x6f,  0x52,  0x4f,  0x51,  0x3e,  0x78,  0xf9,  0xfa,  0x0b,  0x86,  0xd1,  0x74,  0x45,  0xaa,  0xd0,  0x2d,  0xf9,  0xdf,  0x04,  0x13,  0x78,  0x51,  0xb6,  0xd9,  0x2c,  0x41,  0x5d,  0x22,  0x76,  0xe3,  0x70,  0x1c,  0x41,  0x30,  0xf4,  0xa5,  0xf2,  0xd8,  0x79,  0x32,  0xab,  0x20,  0xd9,  0xa6,  0x85,  0x86,  0x04,  0x78,  0x36,  0x2a,  0x0d,  0x18,  0x5f,  0xe4,  0xad,  0xf7,  0x50,  0x2a,  0x59,  0x44,  0x51,  0xb5,  0x70,  0x33,  0x76,  0x6c,  0xf3,  0xdf,  0x12,  0x26,  0xe6,  0x01,  0x1c,  0x6d,  0x83,  0x0e,  0xea,  0x97,  0x15,  0x6c,  0x07,  0xb0,  0xec,  0x93,  0xaf,  0xb7,  0x42,  0x23,  0xb2,  0xf3,  0x24,  0x73,  0xff,  0x33,  0x24,  0x06,  0x78,  0xa3,  0x3b,  0x09,  0xd6,  0x66,  0x6d,  0xfd,  0x98,  0x89,  0x01,  0x90,  0x7c,  0xf1,  0x8f,  0x47,  0x5b,  0xe3,  0x1c,  0xae,  0x0d,  0x9d,  0x4e,  0x14,  0xc0,  0x40,  0x82,  0x2d,  0x27,  0x2e,  0xe5,  0xab,  0xc1,  0xfc,  0x2b,  0xa5,  0x58,  0xb4,  0xb3,  0xb7,  0x58,  0x63,  0xdb,  0x34,  0xd2,  0x21,  0xa0,  0x92,  0x16,  0xff,  0x6f,  0x9f,  0x07,  0xed,  0x91,  0xc2,  0x44,  0x59,  0xe7,  0xc9,  0xe0,  0x7f,  0x05,  0x1b,  0x70,  0x47,  0xa5,  0xcc,  0xec,  0x7a,  0x77,  0x31,  0xd4,  0xd8,  0x97,  0x95,  0x35,  0xf9,  0x39,  0x88,  0x55,  0x0e,  0x13,  0x80,  0x87,  0xb1,  0xb3,  0xbd,  0xa4,  0x62,  0xdc,  0x63,  0xf1,  0xe6,  0xbc,  0xaa,  0x94,  0x61,  0x79,  0x1f,  0xfd,  0x86,  0x2b,  0xc7,  0x51,  0x89,  0x52,  0x36,  0x2f,  0xd8,  0xac,  0xa9,  0x7b,  0xf6,  0x99,  0xa9,  0x20,  0x56,  0x80,  0x53,  0x05,  0xfc,  0xfb,  0x01
};
int generator_degree = RS_DELTA-1;

/**
 * rs_encode
 * Encode a string of bytes of length RS_K using the Reed Solomon
 * code. The response length will be RS_N.
 */
int rs_encode( unsigned char * dest, unsigned char * source )
{
    gf256x message;
    gf256x codeword;
    gf256x generator;
    int i;

    message.degree = RS_K - 1;
    message.data = source;

    codeword.degree = RS_N - 1;
    codeword.data = dest;

    generator.degree = generator_degree;
    generator.data = generator_data;

    codeword = gf256x_init(0);
    gf256x_multiply(&codeword, message, generator);
    for( i = 0 ; i < RS_N ; ++i )
    {
        dest[i] = codeword.data[i];
    }
    gf256x_destroy(codeword);

    return 0;
}

/**
 * rs_decode
 * Decode a possibly noisy received word.
 * @returns:
 *  * the number of corrected symbols on success; -1 on failure
 */
int rs_decode( unsigned char * dest, unsigned char * source )
{
    int i;
    int all_zero;
    int num_errors;
    int success;
    unsigned char syndrome[RS_DELTA-1];
    unsigned char errors[RS_N];
    unsigned char codeword[RS_N];
    gf256x g, s;
    gf256x sigma, omega;
    gf256x sigma_deriv;

    /* get syndrome */
    all_zero = rs_syndrome(syndrome, source);

    /* test for zero (no errors) */
    if( all_zero == 1 )
    {
        return rs_decode_error_free(dest, source);
    }

    /* convert syndrome to polynomial */
    s = gf256x_init(RS_DELTA-2);
    for( i = 0 ; i <= RS_DELTA-2 ; ++i )
    {
        s.data[i] = syndrome[i];
    }

    /* find error locator polynomial */
    g = gf256x_init(0);
    gf256x_one(&g);
    gf256x_multiply_constant_shift(&g, g, 1, RS_DELTA-1);
    sigma = gf256x_init(0);
    omega = gf256x_init(0);
    rs_interrupted_euclidean(&sigma, &omega, s, g);

    /* compute formal derivative of sigma */
    sigma_deriv = gf256x_init(0);
    rs_formal_derivative(&sigma_deriv, sigma);

    /* find and decode errors already */
    num_errors = rs_errors(errors, sigma, sigma_deriv, omega);

    /* maybe quit if num_errors == 0? */

    /* use errors to correct */
    for( i = 0 ; i < RS_N ; ++i )
    {
        codeword[i] = source[i] ^ errors[i];
    }

    /* decode error-free */
    success = rs_decode_error_free(dest, codeword);

    /* clean up */
    gf256x_destroy(s);
    gf256x_destroy(g);
    gf256x_destroy(sigma);
    gf256x_destroy(omega);
    gf256x_destroy(sigma_deriv);

    if( success == 1 )
    {
        return num_errors;
    }
    else
    {
        return -1;
    }
}

/**
 * rs_syndrome
 * Compute the syndrome from the received word.
 * @returns:
 *  * 1 if the syndrome is zero everywhere (indicating the received
 *    word is a codeword), or 0 otherwise (indicating the presence
 *    of noisy).
 */
int rs_syndrome( unsigned char * syndrome, unsigned char * word )
{
    int is_all_zero;
    int i, j;
    unsigned char z, zi, zij, ev;

    /* first, set all elements to zero */
    for( i = 0 ; i < RS_DELTA-1 ; ++i )
    {
        syndrome[i] = 0;
    }
    is_all_zero = 1;

    /* evaluate received polynomial in ith support element, where i
     * goes from 1 to (and excluding) delta */
    z = 2;
    for( i = 1 ; i < RS_DELTA ; ++i )
    {
        ev = 0;
        zi = gf256_exp(z, i);
        for( j = 0 ; j < RS_N ; ++j )
        {
            zij = gf256_exp(zi, j);
            ev ^= gf256_multiply(word[j], zij);
        }
        syndrome[i-1] = ev;

        is_all_zero = is_all_zero & (ev == 0);
    }

    return is_all_zero;
}

/**
 * rs_decode_error_free
 * Decode a noise-free codeword.
 * @returns:
 *  * 1 if decoding succeeded; 0 otherwise (indicating the given word
 *    was clean not a codeword)
 */
int rs_decode_error_free( unsigned char * dest, unsigned char * source )
{
    gf256x s, d;
    int i;
    int ret;

    s = gf256x_init(RS_N-1);
    d = gf256x_init(RS_K);

    for( i = 0 ; i < RS_N ; ++i )
    {
        s.data[i] = source[i];
    }

    ret = (0 != rs_decode_polynomial(&d, s));

    for( i = 0 ; i < 1+d.degree ; ++i )
    {
        dest[i] = d.data[i];
    }
    for( ; i < RS_K ; ++i )
    {
        dest[i] = 0;
    }

    gf256x_destroy(s);
    gf256x_destroy(d);

    return ret;
}

/**
 * rs_interrupted_euclidean
 * Use the interrupted extended Euclidean algorithm to compute sort-
 * of Bezout coefficients a and b such that ax = b = mod y.
 */
int rs_interrupted_euclidean( gf256x * a, gf256x * b, gf256x x, gf256x y )
{
    gf256x t1, t2;
    gf256x r1, r2;
    gf256x s1, s2;
    gf256x quotient, remainder, temp, prod;
    
    t1 = gf256x_init(0);
    t2 = gf256x_init(0);
    s1 = gf256x_init(0);
    s2 = gf256x_init(0);
    r1 = gf256x_init(0);
    r2 = gf256x_init(0);
    quotient = gf256x_init(0);
    remainder = gf256x_init(0);
    temp = gf256x_init(0);
    prod = gf256x_init(0);

    gf256x_one(&t1);
    gf256x_zero(&t2);
    gf256x_copy(&r1, y);
    gf256x_copy(&r2, x);
    gf256x_zero(&s1);
    gf256x_one(&s2);

    while( r2.degree >= t2.degree )
    {
        gf256x_divide(&quotient, &remainder, r1, r2);

        gf256x_copy(&temp, t1);
        gf256x_copy(&t1, t2);
        gf256x_multiply(&prod, quotient, t1);
        gf256x_add(&t2, temp, prod);

        gf256x_copy(&temp, s1);
        gf256x_copy(&s1, s2);
        gf256x_multiply(&prod, quotient, s1);
        gf256x_add(&s2, temp, prod);

        gf256x_copy(&temp, r1);
        gf256x_copy(&r1, r2);
        gf256x_multiply(&prod, quotient, r1);
        gf256x_add(&r2, temp, prod);
    }

    gf256x_copy(a, s1);
    gf256x_copy(b, r1);

    gf256x_destroy(t1);
    gf256x_destroy(t2);
    gf256x_destroy(s1);
    gf256x_destroy(s2);
    gf256x_destroy(r1);
    gf256x_destroy(r2);
    gf256x_destroy(quotient);
    gf256x_destroy(remainder);
    gf256x_destroy(temp);
    gf256x_destroy(prod);

    return 0;
}

/**
 * rs_formal_derivative
 * Compute the formal derivative of the given polynomial.
 */
int rs_formal_derivative( gf256x * Df, gf256x f )
{
    int i;

    if( Df->degree != f.degree - 1 )
    {
        gf256x_destroy(*Df);
        *Df = gf256x_init(f.degree - 1);
    }

    for( i = 1 ; i <= f.degree ; ++i )
    {
        if( (i & 1) == 1 )
        {
            Df->data[i-1] = f.data[i];
        }
        else
        {
            Df->data[i-1] = 0;
        }
    }

    return 0;
}

/**
 * rs_errors
 * Find the errors using Chien search and correct them.
 * @returns:
 *  * the number of found (and corrected) errors
 */
int rs_errors( unsigned char * errors, gf256x sigma, gf256x sigma_deriv, gf256x omega )
{
    int i;
    int num_errors;
    unsigned char sdzmi;
    unsigned char zmi;

    num_errors = 0;
    for( i = 0 ; i < RS_N ; ++i )
    {
        if( gf256x_eval(sigma, gf256_exp(2, -i)) == 0 )
        {
            num_errors = num_errors + 1;
            zmi = gf256_exp(2, -i);
            sdzmi = gf256_inverse(gf256x_eval(sigma_deriv, zmi));
            errors[i] = gf256_multiply(gf256x_eval(omega, zmi), sdzmi);
        }
        else
        {
            errors[i] = 0;
        }
    }

    return num_errors;
}

/**
 * rs_decode_polynomial
 * Decode a codeword-polynomial (with no noise) into a message-
 * polynomial.
 * @returns:
 *  * 0 if division was clean; 1 if there was a nonzero remainder.
 */
int rs_decode_polynomial( gf256x * dest, gf256x codeword )
{
    gf256x rem;
    gf256x generator;
    int ret;

    rem = gf256x_init(0);
    generator.data = generator_data;
    generator.degree = generator_degree;

    gf256x_divide(dest, &rem, codeword, generator);
    ret = !gf256x_is_zero(rem);
    gf256x_destroy(rem);

    return ret;
}

