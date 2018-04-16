#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gf.h"
#include "poly.h"

poly_t
poly_alloc (int d)
{
  poly_t p;
  p = (poly_t) malloc (sizeof(struct polynomial));
  p->deg = -1;
  p->size = d + 1;
  p->coeff = (gf *) calloc (p->size, sizeof(gf));
  return p;
}

poly_t
poly_copy (poly_t p)
{
  poly_t q;
  q = (poly_t) malloc (sizeof(struct polynomial));
  q->deg = p->deg;
  q->size = p->size;
  q->coeff = (gf *) calloc (q->size, sizeof(gf));
  memcpy (q->coeff, p->coeff, p->size * sizeof(gf));
  return q;
}

void
poly_free (poly_t p)
{
  free (p->coeff);
  free (p);
}

void
poly_set_to_zero (poly_t p)
{
  memset (p->coeff, 0, p->size * sizeof(gf));
  p->deg = -1;
}

poly_t
poly_set_to_null ()
{
  poly_t p;
  p = poly_alloc (0);
  p->coeff[0] = 0;
  p->deg = -1;
  return p;
}
void
poly_set_to_unit (poly_t p)
{
  memset (p->coeff, 0, p->size * sizeof(gf));
  p->coeff[0] = 1;
  p->deg = 0;
}

//Compute the maximal degree of a given polynomial
int
poly_calcule_deg (poly_t p)
{
  int d = p->size - 1;
  while ((d >= 0) && (p->coeff[d] == 0))
    --d;
  p->deg = d;
  return d;
}
//Set the polynomial p which is equal to q
void
poly_set (poly_t p, poly_t q)
{
  int d = p->size - q->size;
  if (d < 0)
    {
      memcpy (p->coeff, q->coeff, p->size * sizeof(gf));
      poly_calcule_deg (p);
    }
  else
    {
      memcpy (p->coeff, q->coeff, q->size * sizeof(gf));
      memset (p->coeff + q->size, 0, d * sizeof(gf));
      poly_calcule_deg (q);
      p->deg = q->deg;
    }
}
//Used by poly_eval
gf
poly_eval_aux (gf * coeff, gf a, int d)
{
  gf b;
  b = coeff[d--];
  for (; d >= 0; --d){
      if (b != 0){
      	b = gf_add(gf_mult(b, a), coeff[d]);
      }
      else{
      	b = coeff[d];
      }
  }
  return b;
}


//Returns the multiplication of p by q
poly_t
poly_mul (poly_t p, poly_t q)
{
  int i, j, dp, dq;
  poly_t r;

  poly_calcule_deg (p);
  poly_calcule_deg (q);
  dp = poly_deg(p);
  dq = poly_deg(q);
  r = poly_alloc (dp + dq);
  for (i = 0; i <= dp; ++i){
    for (j = 0; j <= dq; ++j){
      poly_addto_coeff(r, i + j, gf_mult(poly_coeff(p,i),poly_coeff(q,j)));
    }
  }
  poly_calcule_deg (r);

  return r;
}


//Returns the addition of p by q in r (used to avoid memory leak)
void
poly_add_free (poly_t r, poly_t a, poly_t b)
{
  int i;
  if (a->deg == -1){
      r->deg = b->deg;
      memcpy(r->coeff, b->coeff, b->deg * sizeof(gf));
  }
  else if (b->deg == -1){
      r->deg = a->deg;
    	memcpy(r->coeff, a->coeff, a->deg * sizeof(gf));
  }
  else{
      if (a->deg == b->deg){
      	r->deg = a->deg;
      	for (i = 0; i < a->deg + 1; i++){
      		r->coeff[i] = (a->coeff[i]) ^ (b->coeff[i]);
      	}
      }
      if (a->deg > b->deg){
      	r->deg = a->deg;
      	for (i = 0; i < b->deg + 1; i++)
      		r->coeff[i] = (a->coeff[i]) ^ (b->coeff[i]);
      	memcpy(r->coeff + (b->deg + 1),
      			a->coeff + (b->deg + 1),
						(a->deg - b->deg) * sizeof(gf));
      }
      if (b->deg > a->deg){

      	r->deg = b->deg;
      	for (i = 0; i < a->deg + 1; i++)
      		r->coeff[i] = (a->coeff[i]) ^ (b->coeff[i]);
      	memcpy(r->coeff + (a->deg + 1),
      			b->coeff + (a->deg + 1),
						(b->deg - a->deg) * sizeof(gf));
      }
    }
}

gf
poly_eval (poly_t p, gf a)
{
  poly_calcule_deg (p);
  return poly_eval_aux (p->coeff, a, p->deg);
}

void
poly_rem (poly_t p, poly_t g)
{
  int i, j, d;
  gf a, b;
  poly_calcule_deg (p);
  poly_calcule_deg (g);
  d = p->deg - g->deg;
  if (d >= 0){
      a = gf_inv (poly_tete(g));
      for (i = p->deg; d >= 0; --i, --d){
      	if (poly_coeff(p, i) != 0){
      		b = gf_mult(a, poly_coeff(p, i));
      		for (j = 0; j < g->deg; ++j){
      			poly_addto_coeff(p, j + d, gf_mult(b, poly_coeff(g, j))); //In F2^m, addition=soustraction
      		}
      		poly_set_coeff(p, i, 0);
      	}
      }
      poly_set_deg(p, g->deg - 1);
      while ((p->deg >= 0) && (poly_coeff(p, p->deg) == 0)){
      	poly_set_deg(p, p->deg - 1);
      }
    }
}

poly_t
poly_quo (poly_t p, poly_t d)
{
  int i, j, dd, dp;
  gf a, b;
  poly_t quo, rem;

  dd = poly_calcule_deg (d);
  dp = poly_calcule_deg (p);
  rem = poly_copy (p);
  quo = poly_alloc (dp - dd);
  quo->deg = dp - dd;
  a = gf_inv (poly_coeff(d, dd));
  for (i = dp; i >= dd; --i){
      b = gf_mult(a, poly_coeff(rem, i));
      quo->coeff[i-dd] = b;
      if (b != 0){
      	rem->coeff[i] = 0;
      	for (j = i - 1; j >= i - dd; --j){
      		poly_addto_coeff(rem, j, gf_mult(b, poly_coeff(d, dd - i + j)));
      	}
      }
    }
  poly_free (rem);
  return quo;
}

// We suppose deg(g) >= deg(p)
// Returns r1 and u1 such as r1 = u1 * p + v1 * g with deg(r1)<t and deg(u1)= deg (g) - deg (r0) <deg (g) - t
//void
//poly_eeaux (poly_t * u, poly_t * v, poly_t p, poly_t g, int t)
//{
//  int i, j, dr, du, delta;
//  gf a;
//  poly_t aux, r0, r1, u0, u1, v0, v1;
//
//  // initialisation of the local variables
//  // r0 <- g, r1 <- p, u0 <- 0, u1 <- 1
//  dr = poly_calcule_deg (g);
//  r0 = poly_alloc (dr);
//  r1 = poly_alloc (dr - 1);
//
//  u0 = poly_alloc (dr - 1);
//  u1 = poly_alloc (dr - 1);
//  v0 = poly_alloc (dr - 1);
//  v1 = poly_alloc (dr - 1);
//
//  //*************************************
//  poly_set (r0, g);
//  poly_set (r1, p);
//  //**************************************
//  poly_set_to_zero (u0);
//// poly_set_to_zero(u1);
//  poly_set_to_unit (u1);
//  //poly_set_deg(u1, 0);
//  poly_set_to_zero (v1);
//  poly_set_to_unit (v0);
//
//  du = 0;
//  dr = r1->deg;
//  delta = r0->deg - dr;
//
//  while (dr >= t)
//    {
//      for (j = delta; j >= 0; --j)
//	{
//	  a = gf_div(r0->coeff[dr + j], r1->coeff[dr]);
//	  if (a != 0)
//	    {
//	      // u0(z) <- u0(z) + a * u1(z) * z^j
//	      for (i = 0; i <= du; ++i)
//		{
//		  poly_addto_coeff(u0, i + j, gf_mult(a, u1->coeff[i]));
//		}
//	      // r0(z) <- r0(z) + a * r1(z) * z^j
//	      for (i = 0; i <= dr; ++i)
//		{
//		  poly_addto_coeff(r0, i + j, gf_mult(a, poly_coeff(r1, i)));
//		}
//	      for (i = 0; i <= dr; ++i)
//		{
//		  poly_addto_coeff(v0, i + j, gf_mult(a, poly_coeff(v1, i)));
//		}
//	    }
//	}
//      // exchange
//      aux = r0;
//      r0 = r1;
//      r1 = aux;
//      aux = u0;
//      u0 = u1;
//      u1 = aux;
//      aux = v0;
//      v0 = v1;
//      v1 = aux;
//      //aff_poly(u1);
//
//      du = du + delta;
//      delta = 1;
//      while (r1->coeff[dr - delta] == 0)
//	delta++;
//      dr -= delta;
//    }
//
//  poly_set_deg(u1, du);
//  poly_set_deg(r1, dr);
//  poly_set_deg(v1, du);
//  //return u1 and r1;
//
//  *u = u1;
//  *v = r1;
//  poly_free (r0);
//  poly_free (u0);
//  poly_free (v0);
//}

//void
//poly_eeaux_new (poly_t * u, poly_t * v, poly_t *r, poly_t p, poly_t g, int t)
//{
//  int dr, delta;
//  poly_t r0, r1, u0, u1, v0, v1, u2, v2, r2;
//
//  // initialization of the local variables
//  // r0 <- g, r1 <- p, u0 <- 0, u1 <- 1
//  dr = poly_calcule_deg (g);
//  r0 = poly_alloc (dr);
//  r1 = poly_alloc (dr - 1);
//
//  u0 = poly_alloc (dr - 1);
//  u1 = poly_alloc (dr - 1);
//  v0 = poly_alloc (dr - 1);
//  v1 = poly_alloc (dr - 1);
//  u2 = poly_alloc (dr - 1);
//  v2 = poly_alloc (dr - 1);
//  r2 = poly_alloc (dr - 1);
//
//  //*************************************
//  poly_set (r0, g);
//  poly_set (r1, p);
//  //**************************************
//  poly_set_to_zero (u1);
//// poly_set_to_zero(u1);
//  poly_set_to_unit (u0);
//  //poly_set_deg(u1, 0);
//  poly_set_to_zero (v0);
//  poly_set_to_unit (v1);
//
//  // invariants:
//  // r1 = u1 * p + v1 * g
//  // r0 = u0 * p + v0 * g
//  // and deg(u1) = deg(g) - deg(r0)
//  // It stops when deg (r1) <t (deg (r0)> = t)
//  // And therefore deg (u1) = deg (g) - deg (r0) <deg (g) - t
//
//  dr = r1->deg;
//  delta = r0->deg - dr;
//  poly_t quot;
//  quot = poly_alloc (delta);
//  quot = poly_quo (r0, r1);
//  poly_add_free (u2, u0, poly_mul (quot, u1));
//  poly_add_free (v2, v0, poly_mul (quot, v1));
//  poly_add_free (r2, r0, poly_mul (quot, r1));
//  poly_calcule_deg (r2);
//  while (r2->deg >= t)
//    {
//
//      r0 = poly_copy (r1);
//      r1 = poly_copy (r2);
//      quot = poly_quo (r0, r1);
//      u0 = poly_copy (u1);
//      u1 = poly_copy (u2);
//      v0 = poly_copy (v1);
//      v1 = poly_copy (v2);
//      poly_add_free (u2, u0, poly_mul (quot, u1));
//      poly_add_free (v2, v0, poly_mul (quot, v1));
//      poly_add_free (r2, r0, poly_mul (quot, r1));
//      poly_calcule_deg (r2);
//    }
//
//  *u = u2;
//  *r = r2;
//  *v = v2;
//  //poly_free(r0);
//  poly_free (u0);
//  poly_free (v0);
//  //poly_free(u1);
//  //poly_free(r1);
//  poly_free (u1);
//  poly_free (v1);
//  poly_free (r1);
//}
// Each F[i] is the syndrome of the error vector with  a single '1' in i-th position.
/*
poly_t *
poly_syndrome_init (poly_t generator, gf *support, int n)
{
  int i, j, t;
  gf a;
  poly_t * F;

  F = malloc (n * sizeof(poly_t));
  t = poly_deg(generator);

  //g(z)=g_t+g_(t-1).z^(t-1)+......+g_1.z+g_0
  //f(z)=f_(t-1).z^(t-1)+......+f_1.z+f_0

  for (j = 0; j < n; j++){
      F[j] = poly_alloc (t - 1);
      poly_set_coeff(F[j], t - 1, 1);
      for (i = t - 2; i >= 0; i--){
      	poly_set_coeff(F[j], i,
      			gf_add(poly_coeff(generator,i+1),
      			gf_mult(support[j],
      			poly_coeff(F[j],i+1))));
      }
      a = gf_add(poly_coeff(generator,0),
      gf_mult(support[j],poly_coeff(F[j],0)));
      for (i = 0; i < t; i++){
      	poly_set_coeff(F[j], i, gf_div(poly_coeff(F[j],i),a));
      }
      poly_calcule_deg (F[j]);
    }

  return F;
}
*/
poly_t
poly_srivastava (gf * W, int s, int t)
{
  poly_t poly_de_goppa_srivasta, poly1, temp;
  int i, j;

  poly_de_goppa_srivasta = poly_alloc (s * t);
  poly_set_to_zero (poly_de_goppa_srivasta);
  poly_de_goppa_srivasta->coeff[0] = 1;

  poly1 = poly_alloc (1);
  poly_set_to_zero (poly1);

  for (i = 0; i < s; i++){
      poly1->coeff[1] = 1;
      poly1->coeff[0] = W[i];
      for (j = 0; j < t; j++){
      	//poly_de_goppa_srivasta = poly_mul (poly_de_goppa_srivasta, poly1);
      	temp = poly_mul(poly_de_goppa_srivasta, poly1);
      	poly_free(poly_de_goppa_srivasta);
      	poly_de_goppa_srivasta = temp;
      }
  }

  poly_free(poly1);
  return poly_de_goppa_srivasta;
}
/*
void
aff_poly (poly_t poly)
{

  int i;
  for (i = 0; i < poly->size; i++)
    printf ("%d\t", poly->coeff[i]);
  printf ("\n");
}
*/
/*
poly_t
deriv (poly_t p)
{
  poly_t f;
  f = poly_alloc (p->size - 1);
  int i;
  //f=poly_copy(f);
  poly_set_to_zero (f);
  for (i = 1; i <= p->size; i++)
    {
      if (i % 2 != 0)
	{
	  f->coeff[i - 1] = p->coeff[i];
	}
    }

  return f;
}
*/
/*
void
affiche_poly (poly_t p)
{
  int i;
  for (i = 0; i < p->size; i++)
    {
      printf ("%d \t", p->coeff[i]);
    }
}
*/
/*
int
Deg_Max (poly_t a, poly_t b)
{
  int r;
  poly_calcule_deg (a);
  poly_calcule_deg (b);
  if (a->deg <= b->deg)
    {
      r = b->deg;
    }
  else
    {
      r = a->deg;
    }
  return r;
}
*/
