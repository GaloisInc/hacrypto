#ifndef MQDSS_GF31_H
#define MQDSS_GF31_H

typedef unsigned short gf31;

/* This performs a full unique reduction mod 13 on x; x can be any unsigned
   16-bit integer (i.e. in the range [0, 65535]) */
gf31 mod31(gf31 x);

/* Given a vector of elements in the range [0, 31], this reduces the elements
   to the range [0, 30] by mapping 31 to 0 (i.e reduction mod 31) */
void vgf31_unique(gf31 *out, gf31 *in);

/* Given a vector of 16-bit integers (i.e. in [0, 65535], this reduces the
   elements to the range [0, 30] by mapping 31 to 0 (i.e reduction mod 31) */
void vgf31_shorten_unique(gf31 *out, gf31 *in);

/* Given a seed, samples len gf31 elements (in the range [0, 30]), and places
   them in a vector of 16-bit elements */
void gf31_nrand(gf31 *out, const int len, const unsigned char *seed, const int seedlen);

/* Given a seed, samples len gf31 elements, transposed into unsigned range,
   i.e. in the range [-15, 15], and places them in an array of 8-bit integers.
   This is used for the expansion of F, which wants packed elements. */
void gf31_nrand_schar(signed char *out, const int len, const unsigned char *seed, const int seedlen);

/* Unpacks an array of packed GF31 elements to one element per gf31.
   Assumes that there is sufficient empty space available at the end of the
   array to unpack. Can perform in-place. */
void gf31_nunpack(gf31 *out, const unsigned char *in, const int n);

/* Packs an array of GF31 elements from gf31's to concatenated 5-bit values.
   Assumes that there is sufficient space available to unpack.
   Can perform in-place. */
void gf31_npack(unsigned char *out, const gf31 *in, const int n);

#endif
