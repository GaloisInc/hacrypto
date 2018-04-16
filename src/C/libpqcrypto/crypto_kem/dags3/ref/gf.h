#include <stdint.h>

#ifndef GF_H
#define GF_H

typedef uint16_t gf;
typedef uint16_t gf_t;

// Extension degree 12
#define gf_extd 12
// Field size 2^12
#define gf_card (1 << gf_extd)
// Field Group order 2^12 - 1
#define gf_ord ((gf_card)-1)

// Subfield delaration

// Define subfield degree
#define m_val 2
// Subfield degree is 6
#define gf_extd_sf gf_extd / m_val
// Subfield size 2^6
#define gf_card_sf (1 << gf_extd_sf)
// Subfield Group order 2^6 -1
#define gf_ord_sf ((gf_card_sf)-1)

// Define Field value
#define u_val 64
// Define Poly primitive subfield: X^6 + x + 1
#define poly_primitive_subfield 67

//int gf_extension_degree, gf_cardinality, gf_multiplicative_order;
gf_t *gf_log_sf;
gf_t *gf_antilog_sf;

gf *gf_log;
gf *gf_antilog;

#define gf_unit() 1
#define gf_zero() 0
#define gf_add(x, y) ((x) ^ (y)) // Addition in the field

////////////////////////////////////////////////////////////////////
///////////////////////// SUBFIELD OPERATION ///////////////////////

/* we obtain a value between 0 and (q-1) included, the class of 0 is
 represented by 0 or q-1 (this is why we write _K->exp[q-1]=_K->exp[0]=1)*/

#define gf_modq_1_sf(d) ((d) % 63)

// Check y is zero, if zero, return 0, else calculate
#define gf_mul_fast_subfield(x, y) ((y) ? gf_antilog_sf[gf_modq_1_sf(gf_log_sf[x] + gf_log_sf[y])] : 0)

// Multiplication in the field : apha^i*alpha^j=alpha^(i+j)
// Check x is zero, if zero, return 0, else calculate
#define gf_Mult_subfield(x, y) ((x) ? gf_mul_fast_subfield(x, y) : 0)

// In direct way to calculate power in range 2^6.
// Only use in line
// 404:decoding.c: 				valeur_erreurs->coeff[i] = gf_Pow_subfield(2, k);
// gf_Pow_subfield is always calculate 2^k
#define gf_Pow_subfield(x, i) (gf_antilog_sf[(gf_modq_1_sf(gf_log_sf[x] * i))])

// Inverse in the subfield
#define gf_Inv_subfield(x) gf_antilog_sf[gf_ord_sf - gf_log_sf[x]]

////////////////////////////////////////////////////////////////////
///////////////////////// MAIN FIELD OPERATION /////////////////////

#define _gf_modq_1(d) ((d) % 4095)

// Check y is zero, if zero, return 0, else calculate
#define gf_mul_fast(x, y) ((y) ? gf_antilog[_gf_modq_1(gf_log[x] + gf_log[y])] : 0)

// Check x is zero, if zero, return 0, else calculate
// Multiplication in the field : apha^i*alpha^j=alpha^(i+j)
//#define gf_Mult(x, y) ((x) ? gf_mul_fast(x, y) : 0)

////////////////////////////////////////////////////////////////////
///////////////////////// INCORRECT FUNCTION ///////////////////////
// Should be REMOVED

// Incorrect gf_Pow due to incorrect antilog table
//#define gf_Pow(x, i) (gf_antilog[(_gf_modq_1(gf_log[x] * i))])

// Incorrect gf_DIV due to incorrect antilog table
//#define gf_Div(x, y) ((x) ? gf_antilog[_gf_modq_1(gf_log[x] - gf_log[y])] : 0) // Division in the field : apha^i/alpha^j=alpha^(i-j)

// Incorrect gf_Inv due to incorrect antilog table
//#define gf_Inv(x) gf_antilog[gf_ord - gf_log[x]]                               // Inverse in the field

////////////////////////////////////////////////////////////////////

// Correct gf_Mult1 =>> will rename to gf_Mult
gf gf_mult(gf in0, gf in1);

// Correct gf_Inv1 =>> will rename to gf_Inv
// Use in poly, matrix, keygen, decoding
gf gf_inv(gf in);

// Correct gf_sq1 =>> will rename to gf_sq
gf gf_sq(gf in);

// Incorrect gf_Div1
//gf gf_Div1(gf a, gf b);

// Propose gf_Div2
gf gf_div(gf a, gf b);

// In correct gf_Pow1
gf gf_Pow1(gf f, int n);

// Propose gf_Ppw
gf gf_pow(gf f, int n);

// Un-nessary use antilog and log table
int gf_init(int extdeg);

#endif
