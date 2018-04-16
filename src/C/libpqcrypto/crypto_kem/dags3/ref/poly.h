#ifndef POLY_H
#define POLY_H


typedef struct polynomial {
  int deg, size;
  gf * coeff;
} * poly_t; // Polynomyal coefficients belong to the finite field

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define poly_deg(p) ((p)->deg)
#define poly_size(p) ((p)->size)
#define poly_set_deg(p, d) ((p)->deg = (d))
#define poly_coeff(p, i) ((p)->coeff[i])
#define poly_set_coeff(p, i, a) ((p)->coeff[i] = (a))
#define poly_addto_coeff(p, i, a) ((p)->coeff[i] = (((p)->coeff[i])^(a)))
#define poly_multo_coeff(p, i, a) ((p)->coeff[i] = gf_Mult((p)->coeff[i], (a)))
#define poly_tete(p) ((p)->coeff[(p)->deg])


int poly_calcule_deg(poly_t p);
poly_t poly_alloc(int d);
poly_t poly_copy(poly_t p);
void poly_free(poly_t p);
void poly_set_to_zero(poly_t p);
void poly_set(poly_t p, poly_t q);
poly_t poly_mul(poly_t p, poly_t q);
void poly_rem(poly_t p, poly_t g);
poly_t poly_quo(poly_t p, poly_t d);
gf poly_eval(poly_t p, gf a);
//void poly_eeaux(poly_t * u, poly_t * v, poly_t p, poly_t g, int t);
//void aff_poly(poly_t poly);
poly_t poly_Div(poly_t a, poly_t b);
poly_t poly_srivastava(gf *W, int s, int t);
//poly_t * poly_syndrome_init(poly_t generator, gf *support, int n);
void poly_set_to_unit(poly_t p);
//poly_t deriv(poly_t p);
void poly_add_free(poly_t r, poly_t a, poly_t b);

//int Deg_Max(poly_t a, poly_t b);
//void poly_eeaux_new(poly_t  * u, poly_t * v,poly_t *r, poly_t p, poly_t g, int t) ;

#endif  
