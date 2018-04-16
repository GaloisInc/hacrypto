#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "gf.h"

/*
 ~~~~~~~~ARITHMETIC FIELD ELEMENT CONSTRUCTION ~~~~~~~~~~~~~~~~
 We define arithmetic field in  F[2][x]/(f), where f is an m-irreducible polynomial.
 In our case, m=5 or m=6.
 For multiplication ,inversion,square,exponentiation field elements, we have adopted the "bitsliced-operation" technic.
 Addition field element, we used XOR between integers.
 */

static void gf_init_antilog_sf()
{
    /*
    SUBFIELD table.
    Build table for faster calculation.
    In memory access is faster than calculating.
    */
    int i = 1;
    int temp = 1 << (gf_extd_sf - 1);
    gf_antilog_sf = (gf_t *)malloc((gf_card_sf * sizeof(gf_t)));
    gf_antilog_sf[0] = 1;
    for (i = 1; i < gf_ord_sf; ++i)
    {
        gf_antilog_sf[i] = gf_antilog_sf[i - 1] << 1;
        if ((gf_antilog_sf[i - 1]) & temp)
        {
            // XOR with 67: X^6 + x + 1
            gf_antilog_sf[i] ^= poly_primitive_subfield;
        }
    }
    gf_antilog_sf[gf_ord_sf] = 1;
}

static void gf_init_log_sf()
{
    /*
    SUBFIELD table.
    Build table for faster calculation.
    In memory access is faster than calculating.
    */
    int i = 1;
    gf_log_sf = (gf_t *)malloc((gf_card_sf * sizeof(gf_t)));
    gf_log_sf[0] = -1;
    gf_log_sf[1] = 0;
    for (i = 1; i < gf_ord_sf; ++i)
    {
        gf_log_sf[gf_antilog_sf[i]] = i;
    }
}

static void gf_init_antilog()
{
    /*
    MAINFIELD table.
    Build table for faster calculation.
    In memory access is faster than calculating.
    */
    int i = 1;
    gf_antilog = (gf *)malloc(gf_card * sizeof(gf));
    gf p = 1;
    gf_antilog[0] = 1;
    // gf_card = 4096
    for (i = 1; i < gf_card; i++)
    {
        p = gf_mult(p, 64);
        gf_antilog[i] = p;
    }
}

static void gf_init_log()
{
    /*
    MAINFIELD table.
    Build table for faster calculation.
    In memory access is faster than calculating.
    */
    int i = 1;
    gf_log = (gf *)malloc((gf_card * sizeof(gf)));
    gf_log[0] = -1;
    gf_log[1] = 0;
    for (i = 1; i < gf_ord; ++i)
    {
        gf_log[gf_antilog[i]] = i;
    }
}

// Unused function
gf gf_diff1(gf a, gf b)
{
    uint32_t t = (uint32_t)(a ^ b);
    t = ((t - 1) >> 20) ^ 0xFFF;
    return (gf)t;
}

// Correct gf_Div
// Use in poly.c
gf gf_div(gf a, gf b)
{
    if (b == 0)
    {
        fprintf(stderr, "ERROR %d is not invertible", b);
        exit(-1);
    }
    else
    {
        gf res = gf_mult(a, gf_inv(b));
        return res;
    }
}

// Correct gf_Pow
gf gf_pow(gf in, int n)
{

    gf h, t;
    h = 1;
    t = in;
    while (n != 0)
    {
        if ((n & 1) == 1)
        {
            h = gf_mult(h, t);
        }
        n = n >> 1;
        t = gf_mult(t, t);
    }
    return h;
}

// Correct gf_mult
gf gf_mult(gf x, gf y)
{
    gf a1, b1, a2, b2, a3, b3;

    a1 = x >> 6;
    b1 = x & 63;
    a2 = y >> 6;
    b2 = y & 63;

    a3 = gf_Mult_subfield(gf_Mult_subfield(a1, a2), 36) ^ gf_Mult_subfield(a1, b2) ^ gf_Mult_subfield(b1, a2);

    b3 = gf_Mult_subfield(gf_Mult_subfield(a1, a2), 2) ^ gf_Mult_subfield(b1, b2);

    return (a3 << 6) ^ b3;
}

// Correct gf_sq
gf gf_sq(gf x)
{
    gf a1, b1, a3, b3;

    a1 = x >> 6;
    b1 = x & 63;

    a3 = gf_Mult_subfield(gf_Mult_subfield(a1, a1), 36);

    b3 = gf_Mult_subfield(gf_Mult_subfield(a1, a1), 2) ^ gf_Mult_subfield(b1, b1);

    return (a3 << 6) ^ b3;
}

// Correct gf_Inv
gf gf_inv(gf in)
{
    gf tmp_11;
    gf tmp_1111;

    gf out = in;

    out = gf_sq(out);
    tmp_11 = gf_mult(out, in);

    out = gf_sq(tmp_11);
    out = gf_sq(out);
    tmp_1111 = gf_mult(out, tmp_11);

    out = gf_sq(tmp_1111);
    out = gf_sq(out);
    out = gf_sq(out);
    out = gf_sq(out);
    out = gf_mult(out, tmp_1111);

    out = gf_sq(out);
    out = gf_sq(out);
    out = gf_mult(out, tmp_11);

    out = gf_sq(out);
    out = gf_mult(out, in);

    return gf_sq(out);
}

int init_done = 0;

int gf_init(int extdeg)
{
    if (extdeg > gf_extd_sf)
    {

        exit(0);
    }

    if (init_done != extdeg)
    {
        if (init_done)
        {
            free(gf_antilog_sf);
            free(gf_log_sf);
            free(gf_antilog);
            free(gf_log);
        }
        init_done = extdeg;
        gf_init_antilog_sf();
        gf_init_log_sf();
        gf_init_antilog();
        gf_init_log();
    }

    return 1;
}

