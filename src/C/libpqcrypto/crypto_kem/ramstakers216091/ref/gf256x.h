#ifndef GF256X_H
#define GF256X_H

extern const unsigned char gf256_dlogs[256];
extern const unsigned char gf256_antilogs[256];

unsigned char gf256_multiply( unsigned char lhs, unsigned char rhs );
unsigned char gf256_inverse( unsigned char elm );
unsigned char gf256_exp( unsigned char elm, int exponent );

typedef struct
{
    unsigned char * data;
    int degree;
} gf256x;

gf256x gf256x_init( int deg );
int gf256x_copy( gf256x* dest, gf256x source );
int gf256x_destroy( gf256x p );

unsigned char gf256x_eval( gf256x polynomial, unsigned char point );
int gf256x_add( gf256x* dest, gf256x lhs, gf256x rhs );
int gf256x_multiply( gf256x* dest, gf256x lhs, gf256x rhs );
int gf256x_multiply_constant_shift( gf256x* dest, gf256x poly, unsigned char constant, int shift );
int gf256x_divide( gf256x* quo, gf256x* rem, gf256x num, gf256x den );
int gf256x_xgcd( gf256x* a, gf256x* b, gf256x* g, gf256x x, gf256x y );

int gf256x_one( gf256x* g );
int gf256x_zero( gf256x* g );
int gf256x_is_zero( gf256x g );

int gf256x_print( gf256x p );

#endif

