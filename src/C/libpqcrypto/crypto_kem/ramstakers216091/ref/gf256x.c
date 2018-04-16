#include "gf256x.h"
#include <stdlib.h>
#include <stdio.h>

const unsigned char gf256_dlogs[256] = { 
0xff ,  0x0 ,  0x1 ,  0x19 ,  0x2 ,  0x32 ,  0x1a ,  0xc6 ,  
0x3 ,  0xdf ,  0x33 ,  0xee ,  0x1b ,  0x68 ,  0xc7 ,  0x4b ,  
0x4 ,  0x64 ,  0xe0 ,  0xe ,  0x34 ,  0x8d ,  0xef ,  0x81 ,  
0x1c ,  0xc1 ,  0x69 ,  0xf8 ,  0xc8 ,  0x8 ,  0x4c ,  0x71 ,  
0x5 ,  0x8a ,  0x65 ,  0x2f ,  0xe1 ,  0x24 ,  0xf ,  0x21 ,  
0x35 ,  0x93 ,  0x8e ,  0xda ,  0xf0 ,  0x12 ,  0x82 ,  0x45 ,  
0x1d ,  0xb5 ,  0xc2 ,  0x7d ,  0x6a ,  0x27 ,  0xf9 ,  0xb9 ,  
0xc9 ,  0x9a ,  0x9 ,  0x78 ,  0x4d ,  0xe4 ,  0x72 ,  0xa6 ,  
0x6 ,  0xbf ,  0x8b ,  0x62 ,  0x66 ,  0xdd ,  0x30 ,  0xfd ,  
0xe2 ,  0x98 ,  0x25 ,  0xb3 ,  0x10 ,  0x91 ,  0x22 ,  0x88 ,  
0x36 ,  0xd0 ,  0x94 ,  0xce ,  0x8f ,  0x96 ,  0xdb ,  0xbd ,  
0xf1 ,  0xd2 ,  0x13 ,  0x5c ,  0x83 ,  0x38 ,  0x46 ,  0x40 ,  
0x1e ,  0x42 ,  0xb6 ,  0xa3 ,  0xc3 ,  0x48 ,  0x7e ,  0x6e ,  
0x6b ,  0x3a ,  0x28 ,  0x54 ,  0xfa ,  0x85 ,  0xba ,  0x3d ,  
0xca ,  0x5e ,  0x9b ,  0x9f ,  0xa ,  0x15 ,  0x79 ,  0x2b ,  
0x4e ,  0xd4 ,  0xe5 ,  0xac ,  0x73 ,  0xf3 ,  0xa7 ,  0x57 ,  
0x7 ,  0x70 ,  0xc0 ,  0xf7 ,  0x8c ,  0x80 ,  0x63 ,  0xd ,  
0x67 ,  0x4a ,  0xde ,  0xed ,  0x31 ,  0xc5 ,  0xfe ,  0x18 ,  
0xe3 ,  0xa5 ,  0x99 ,  0x77 ,  0x26 ,  0xb8 ,  0xb4 ,  0x7c ,  
0x11 ,  0x44 ,  0x92 ,  0xd9 ,  0x23 ,  0x20 ,  0x89 ,  0x2e ,  
0x37 ,  0x3f ,  0xd1 ,  0x5b ,  0x95 ,  0xbc ,  0xcf ,  0xcd ,  
0x90 ,  0x87 ,  0x97 ,  0xb2 ,  0xdc ,  0xfc ,  0xbe ,  0x61 ,  
0xf2 ,  0x56 ,  0xd3 ,  0xab ,  0x14 ,  0x2a ,  0x5d ,  0x9e ,  
0x84 ,  0x3c ,  0x39 ,  0x53 ,  0x47 ,  0x6d ,  0x41 ,  0xa2 ,  
0x1f ,  0x2d ,  0x43 ,  0xd8 ,  0xb7 ,  0x7b ,  0xa4 ,  0x76 ,  
0xc4 ,  0x17 ,  0x49 ,  0xec ,  0x7f ,  0xc ,  0x6f ,  0xf6 ,  
0x6c ,  0xa1 ,  0x3b ,  0x52 ,  0x29 ,  0x9d ,  0x55 ,  0xaa ,  
0xfb ,  0x60 ,  0x86 ,  0xb1 ,  0xbb ,  0xcc ,  0x3e ,  0x5a ,  
0xcb ,  0x59 ,  0x5f ,  0xb0 ,  0x9c ,  0xa9 ,  0xa0 ,  0x51 ,  
0xb ,  0xf5 ,  0x16 ,  0xeb ,  0x7a ,  0x75 ,  0x2c ,  0xd7 ,  
0x4f ,  0xae ,  0xd5 ,  0xe9 ,  0xe6 ,  0xe7 ,  0xad ,  0xe8 ,  
0x74 ,  0xd6 ,  0xf4 ,  0xea ,  0xa8 ,  0x50 ,  0x58 ,  0xaf 
};
const unsigned char gf256_antilogs[256] = { 
0x1 ,  0x2 ,  0x4 ,  0x8 ,  0x10 ,  0x20 ,  0x40 ,  0x80 ,  
0x1d ,  0x3a ,  0x74 ,  0xe8 ,  0xcd ,  0x87 ,  0x13 ,  0x26 ,  
0x4c ,  0x98 ,  0x2d ,  0x5a ,  0xb4 ,  0x75 ,  0xea ,  0xc9 ,  
0x8f ,  0x3 ,  0x6 ,  0xc ,  0x18 ,  0x30 ,  0x60 ,  0xc0 ,  
0x9d ,  0x27 ,  0x4e ,  0x9c ,  0x25 ,  0x4a ,  0x94 ,  0x35 ,  
0x6a ,  0xd4 ,  0xb5 ,  0x77 ,  0xee ,  0xc1 ,  0x9f ,  0x23 ,  
0x46 ,  0x8c ,  0x5 ,  0xa ,  0x14 ,  0x28 ,  0x50 ,  0xa0 ,  
0x5d ,  0xba ,  0x69 ,  0xd2 ,  0xb9 ,  0x6f ,  0xde ,  0xa1 ,  
0x5f ,  0xbe ,  0x61 ,  0xc2 ,  0x99 ,  0x2f ,  0x5e ,  0xbc ,  
0x65 ,  0xca ,  0x89 ,  0xf ,  0x1e ,  0x3c ,  0x78 ,  0xf0 ,  
0xfd ,  0xe7 ,  0xd3 ,  0xbb ,  0x6b ,  0xd6 ,  0xb1 ,  0x7f ,  
0xfe ,  0xe1 ,  0xdf ,  0xa3 ,  0x5b ,  0xb6 ,  0x71 ,  0xe2 ,  
0xd9 ,  0xaf ,  0x43 ,  0x86 ,  0x11 ,  0x22 ,  0x44 ,  0x88 ,  
0xd ,  0x1a ,  0x34 ,  0x68 ,  0xd0 ,  0xbd ,  0x67 ,  0xce ,  
0x81 ,  0x1f ,  0x3e ,  0x7c ,  0xf8 ,  0xed ,  0xc7 ,  0x93 ,  
0x3b ,  0x76 ,  0xec ,  0xc5 ,  0x97 ,  0x33 ,  0x66 ,  0xcc ,  
0x85 ,  0x17 ,  0x2e ,  0x5c ,  0xb8 ,  0x6d ,  0xda ,  0xa9 ,  
0x4f ,  0x9e ,  0x21 ,  0x42 ,  0x84 ,  0x15 ,  0x2a ,  0x54 ,  
0xa8 ,  0x4d ,  0x9a ,  0x29 ,  0x52 ,  0xa4 ,  0x55 ,  0xaa ,  
0x49 ,  0x92 ,  0x39 ,  0x72 ,  0xe4 ,  0xd5 ,  0xb7 ,  0x73 ,  
0xe6 ,  0xd1 ,  0xbf ,  0x63 ,  0xc6 ,  0x91 ,  0x3f ,  0x7e ,  
0xfc ,  0xe5 ,  0xd7 ,  0xb3 ,  0x7b ,  0xf6 ,  0xf1 ,  0xff ,  
0xe3 ,  0xdb ,  0xab ,  0x4b ,  0x96 ,  0x31 ,  0x62 ,  0xc4 ,  
0x95 ,  0x37 ,  0x6e ,  0xdc ,  0xa5 ,  0x57 ,  0xae ,  0x41 ,  
0x82 ,  0x19 ,  0x32 ,  0x64 ,  0xc8 ,  0x8d ,  0x7 ,  0xe ,  
0x1c ,  0x38 ,  0x70 ,  0xe0 ,  0xdd ,  0xa7 ,  0x53 ,  0xa6 ,  
0x51 ,  0xa2 ,  0x59 ,  0xb2 ,  0x79 ,  0xf2 ,  0xf9 ,  0xef ,  
0xc3 ,  0x9b ,  0x2b ,  0x56 ,  0xac ,  0x45 ,  0x8a ,  0x9 ,  
0x12 ,  0x24 ,  0x48 ,  0x90 ,  0x3d ,  0x7a ,  0xf4 ,  0xf5 ,  
0xf7 ,  0xf3 ,  0xfb ,  0xeb ,  0xcb ,  0x8b ,  0xb ,  0x16 ,  
0x2c ,  0x58 ,  0xb0 ,  0x7d ,  0xfa ,  0xe9 ,  0xcf ,  0x83 ,  
0x1b ,  0x36 ,  0x6c ,  0xd8 ,  0xad ,  0x47 ,  0x8e ,  0x1 
};

/**
 * gf256_multiply
 * Multiply two GF(256) elements using discrete log and antilog
 * tables.
 * @params:
 *  * lhs, rhs : GF(256) elements to multiply
 * @return:
 *  * product of lhs and rhs
 */
unsigned char gf256_multiply( unsigned char lhs, unsigned char rhs )
{
    int a, b;
    if( lhs == 0 || rhs == 0 )
    {
        return 0;
    }
    a = gf256_dlogs[lhs];
    b = gf256_dlogs[rhs];
    return gf256_antilogs[(a + b) % 255];
}

/**
 * gf256_inverse
 * Find the inverse of a GF(256) element.
 * @params:
 *  * elm : GF(256) element whose inverse is to be found
 * @return:
 *  * inverse of elm
 */
unsigned char gf256_inverse( unsigned char elm )
{
    int a;
    unsigned char inv;
    if( elm == 0 )
    {
        return 0;
    }
    a = gf256_dlogs[elm];
    inv = gf256_antilogs[255 - a];
    return inv;
}

/**
 * gf256_exp
 * Raise a given GF(256) element to the given power.
 */
unsigned char gf256_exp( unsigned char element, int exponent )
{
    int index;
    index = (255 + ((gf256_dlogs[element] * exponent) % 255)) % 255;
    return gf256_antilogs[index];
}

/**
 * gf256x_init
 * Initialize a GF(256)[x] object of given degree. Allocate memory
 * and set to zero.
 */
gf256x gf256x_init( int deg )
{
    gf256x elm;
    elm.data = malloc(deg+1);
    elm.degree = deg;
    return elm;
}

/**
 * gf256x_zero
 * Set the given polynomial to zero.
 */
int gf256x_zero( gf256x* p )
{
    free(p->data);
    p->degree = 0;
    p->data = malloc(1);
    p->data[0] = 0;
    return 1;
}

/**
 * gf256x_one
 * Set the given polynomial to one.
 */
int gf256x_one( gf256x* p )
{
    free(p->data);
    p->degree = 0;
    p->data = malloc(1);
    p->data[0] = 1;
    return 1;
}

/**
 * gf256x_copy
 * Copy a GF(256)[x] element from one container to another, and
 * reinitialize as necessary.
 */
int gf256x_copy( gf256x* dest, gf256x source )
{
    int i;
    if( dest->degree != source.degree )
    {
        free(dest->data);
        dest->data = malloc(source.degree+1);
        dest->degree = source.degree;
    }
    for( i = 0 ; i <= source.degree ; ++i )
    {
        dest->data[i] = source.data[i];
    }
    return 1;
}

/**
 * gf256x_destroy
 * Destroy a GF(256)[x] object. Free memory.
 */
int gf256x_destroy( gf256x p )
{
    free(p.data);

    return 1;
}

/**
 * gf256x_add
 * Add two GF(256)[x] elements together.
 */
int gf256x_add( gf256x* dest, gf256x lhs, gf256x rhs )
{
    int i;
    unsigned char * data;
    if( rhs.degree > lhs.degree )
    {
        return gf256x_add(dest, rhs, lhs);
    }

    data = malloc(lhs.degree+1);

    for( i = 0 ; i <= rhs.degree ; ++i )
    {
        data[i] = lhs.data[i] ^ rhs.data[i];
    }
    for( ; i <= lhs.degree ; ++i )
    {
        data[i] = lhs.data[i];
    }

    free(dest->data);
    dest->degree = lhs.degree;
    dest->data = data;

    while( data[dest->degree] == 0 && dest->degree > 0 )
    {
        dest->degree -= 1;
    }

    return 1;
}

/**
 * gf256x_multiply
 * Multiple two GF(256)[x] elements together.
 */
int gf256x_multiply( gf256x* dest, gf256x lhs, gf256x rhs )
{
    int i, j;
    int degree;
    unsigned char * data;

    degree = lhs.degree + rhs.degree;
    data = malloc(degree + 1);

    for( i = 0 ; i <= degree ; ++i )
    {
        data[i] = 0;
    }

    for( i = 0 ; i <= lhs.degree ; ++i )
    {
        for( j = 0 ; j <= rhs.degree ; ++j )
        {
            data[i+j] = data[i+j] ^ gf256_multiply(lhs.data[i], rhs.data[j]);
        }
    }

    free(dest->data);
    dest->data = data;
    dest->degree = degree;

    return 1;
}

/**
 * gf256x_equals
 * Decide if two elements of GF(256)[x] are equal, and return 1 if so.
 * (Return 0 otherwise.)
 */
int gf256x_equals( gf256x lhs, gf256x rhs )
{
    int i;
    int equal;
    if( lhs.degree != rhs.degree )
    {
        return 0;
    }
    equal = 1;
    for( i = 0 ; i <= lhs.degree ; ++i )
    {
        equal = equal & (lhs.data[i] == rhs.data[i]);
    }
    return equal;
}

/**
 * gf256x_is_zero
 * Determine if the given polynomial is equal to zero. Return one if
 * so, zero otherwise.
 */
int gf256x_is_zero( gf256x p )
{
    int zero;
    int i;
    zero = 1;
    for( i = 0 ; i <= p.degree ; ++i )
    {
        zero &= p.data[i] == 0;
    }
    return zero;
}

/**
 * gf256x_multiply_constant_shift
 * Multiply the polynomial with a constant and shift it (to the left,
 * i.e., towards higher degree). Satisfies:
 *  dest == constant * x^shift * poly
 */
int gf256x_multiply_constant_shift( gf256x* dest, gf256x poly, unsigned char constant, int shift )
{
    unsigned char * data;
    int i;
    int degree;

    degree = shift + poly.degree;

    data = malloc(degree+1);
    for( i = 0 ; i <= degree ; ++i )
    {
        data[i] = 0;
    }

    for( i = shift ; i <= degree ; ++i )
    {
        data[i] = gf256_multiply(poly.data[i-shift], constant);
    }

    free(dest->data);
    dest->data = data;
    dest->degree = degree;

    return 1;
}

/**
 * gf256x_divide
 * Divide one GF(256)[x] element by another and record the quotient
 * and remainder.
 */
int gf256x_divide( gf256x* quo, gf256x* rem, gf256x num, gf256x divisor )
{
    int i;
    unsigned char inv, compl;
    gf256x remainder, poly;
    unsigned char * quotient_data;

    /* make sure divisor leading coefficient is not zero */
    if( divisor.data[divisor.degree] == 0 )
    {
        poly.data = malloc(divisor.degree);
        for( i = 0 ; i < divisor.degree ; ++i )
        {
            poly.data[i] = divisor.data[i];
        }
        for( poly.degree = divisor.degree-1 ; poly.degree > 0 ; --poly.degree )
        {
            if( poly.data[poly.degree] != 0 )
            {
                break;
            }
        }
        gf256x_divide(quo, rem, num, poly);
        free(poly.data);
        return 1;
    }

    /* make sure numerator leading coefficient is not zero */
    if( num.data[num.degree] == 0 )
    {
        poly.data = malloc(num.degree);
        for( i = 0 ; i < num.degree ; ++i )
        {
            poly.data[i] = num.data[i];
        }
        for( poly.degree = num.degree-1 ; poly.degree > 0 ; --poly.degree )
        {
            if( poly.data[poly.degree] != 0 )
            {
                break;
            }
        }
        gf256x_divide(quo, rem, poly, divisor);
        free(poly.data);
        return 1;
    }

    /* make sure deg(divisor) > deg(numerator) */
    if( divisor.degree > num.degree )
    {
        gf256x_zero(quo);
        gf256x_copy(rem, num);
        return 1;
    }

    /* filtered out edge cases, proceed with division already */
    remainder = gf256x_init(0);
    poly = gf256x_init(0);
    gf256x_copy(&remainder, num);
    quotient_data = malloc(num.degree - divisor.degree + 1);
    for( i = 0 ; i <= num.degree - divisor.degree ; ++i )
    {
        quotient_data[i] = 0;
    }

    inv = gf256_inverse(divisor.data[divisor.degree]);

    for( i = remainder.degree - divisor.degree ; i >= 0 ; --i )
    {
        if( remainder.degree < divisor.degree + i )
        {
            continue;
        }


        compl = gf256_multiply(remainder.data[remainder.degree], inv);
        gf256x_multiply_constant_shift(&poly, divisor, compl, i);


        quotient_data[i] = compl;
        gf256x_add(&remainder, remainder, poly);

    }

    free(quo->data);
    quo->data = quotient_data;
    quo->degree = num.degree - divisor.degree;

    gf256x_copy(rem, remainder);
    gf256x_destroy(remainder);
    gf256x_destroy(poly);

    return 1;
}

/**
 * gf256x_xgcd
 * Compute the greatest common divisor g and Bezout coefficients a
 * and b for x and y using the extended Euclidean algorithm.
 */
int gf256x_xgcd( gf256x* a, gf256x* b, gf256x* g, gf256x x, gf256x y )
{
    gf256x s, old_s;
    gf256x t, old_t;
    gf256x r, old_r;
    gf256x quotient, remainder;
    gf256x temp;

    s = gf256x_init(0);
    old_s = gf256x_init(0);
    t = gf256x_init(0);
    old_t = gf256x_init(0);
    r = gf256x_init(0);
    old_r = gf256x_init(0);
    quotient = gf256x_init(0);
    remainder = gf256x_init(0);
    temp = gf256x_init(0);

    gf256x_zero(&s);
    gf256x_one(&old_s);
    gf256x_one(&t);
    gf256x_zero(&old_t);
    gf256x_copy(&r, y);
    gf256x_copy(&old_r, x);

    while( gf256x_is_zero(r) == 0 )
    {
        gf256x_divide(&quotient, &remainder, old_r, r);

        gf256x_copy(&old_r, r);
        gf256x_copy(&r, remainder);

        gf256x_multiply(&temp, quotient, s);
        gf256x_add(&temp, temp, old_s);
        gf256x_copy(&old_s, s);
        gf256x_copy(&s, temp);

        gf256x_multiply(&temp, quotient, t);
        gf256x_add(&temp, temp, old_t);
        gf256x_copy(&old_t, t);
        gf256x_copy(&t, temp);
    }

    gf256x_copy(a, old_s);
    gf256x_copy(b, old_t);
    gf256x_copy(g, old_r);

    gf256x_destroy(s);
    gf256x_destroy(old_s);
    gf256x_destroy(t);
    gf256x_destroy(old_t);
    gf256x_destroy(r);
    gf256x_destroy(old_r);
    gf256x_destroy(quotient);
    gf256x_destroy(remainder);
    gf256x_destroy(temp);

    return 1;
}

/**
 * gf256x_eval
 * Evaluate the given polynomial in a given point.
 */
unsigned char gf256x_eval( gf256x polynomial, unsigned char point )
{
    int i;
    unsigned char acc;
    unsigned char xi;
    acc = 0;
    xi = 1;
    for( i = 0 ; i <= polynomial.degree ; ++i )
    {
        acc = acc ^ gf256_multiply(polynomial.data[i], xi);
        xi = gf256_multiply(xi, point);
    }

//    printf("evaluating polynomial "); gf256x_print(polynomial); printf(" int point %02x; result: %02x\n", point, acc);

    return acc;
}

/**
 * gf256x_print
 * Cast the polynomial's coefficients to hex number and throw them to
 * stdout.
 */
int gf256x_print( gf256x p )
{
    int i;

    for( i = 0 ; i <= p.degree ; ++i )
    {
        printf("%02x", p.data[i]);
    }

    return 1;
}

