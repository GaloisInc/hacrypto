/*
uX.h version $Date$
D. J. Bernstein
Romain Dolbeau
Public domain.

This does a variable number of blocks, depending on the SVE vector size.
*/

#define VEC4_ROT(a,imm) sveor_u32_z(svptrue_b32(), svlsl_n_u32_z(svptrue_b32(), a, imm),svlsr_n_u32_z(svptrue_b32(), a, 32-imm))

#define VEC4_ROT16(a) svrevh_u32_z(svptrue_b32(), a)

#define VEC4_QUARTERROUND(a,b,c,d)                                \
   x_##a = svadd_u32_z(svptrue_b32(), x_##a, x_##b); t_##a = sveor_u32_z(svptrue_b32(), x_##d, x_##a); x_##d = VEC4_ROT16(t_##a); \
   x_##c = svadd_u32_z(svptrue_b32(), x_##c, x_##d); t_##c = sveor_u32_z(svptrue_b32(), x_##b, x_##c); x_##b = VEC4_ROT(t_##c, 12); \
   x_##a = svadd_u32_z(svptrue_b32(), x_##a, x_##b); t_##a = sveor_u32_z(svptrue_b32(), x_##d, x_##a); x_##d = VEC4_ROT(t_##a,  8); \
   x_##c = svadd_u32_z(svptrue_b32(), x_##c, x_##d); t_##c = sveor_u32_z(svptrue_b32(), x_##b, x_##c); x_##b = VEC4_ROT(t_##c,  7)

  if (!bytes) return;
uint64_t vc = svcntb(); /* how many bytes in a vector */
if (bytes>=16*vc) {
  u32 in12, in13;
  svuint32_t x_0 = svdup_n_u32(x[0]);
  svuint32_t x_1 = svdup_n_u32(x[1]);
  svuint32_t x_2 = svdup_n_u32(x[2]);
  svuint32_t x_3 = svdup_n_u32(x[3]);
  svuint32_t x_4 = svdup_n_u32(x[4]);
  svuint32_t x_5 = svdup_n_u32(x[5]);
  svuint32_t x_6 = svdup_n_u32(x[6]);
  svuint32_t x_7 = svdup_n_u32(x[7]);
  svuint32_t x_8 = svdup_n_u32(x[8]);
  svuint32_t x_9 = svdup_n_u32(x[9]);
  svuint32_t x_10 = svdup_n_u32(x[10]);
  svuint32_t x_11 = svdup_n_u32(x[11]);
  svuint32_t x_12;// = svdup_n_u32(x[12]); /* useless */
  svuint32_t x_13;// = svdup_n_u32(x[13]); /* useless */
  svuint32_t x_14 = svdup_n_u32(x[14]);
  svuint32_t x_15 = svdup_n_u32(x[15]);
  svuint32_t orig0 = x_0;
  svuint32_t orig1 = x_1;
  svuint32_t orig2 = x_2;
  svuint32_t orig3 = x_3;
  svuint32_t orig4 = x_4;
  svuint32_t orig5 = x_5;
  svuint32_t orig6 = x_6;
  svuint32_t orig7 = x_7;
  svuint32_t orig8 = x_8;
  svuint32_t orig9 = x_9;
  svuint32_t orig10 = x_10;
  svuint32_t orig11 = x_11;
  svuint32_t orig12;// = x_12; /* useless */
  svuint32_t orig13;// = x_13; /* useless */
  svuint32_t orig14 = x_14;
  svuint32_t orig15 = x_15;
  svuint32_t t_0;
  svuint32_t t_1;
  svuint32_t t_2;
  svuint32_t t_3;
  svuint32_t t_4;
  svuint32_t t_5;
  svuint32_t t_6;
  svuint32_t t_7;
  svuint32_t t_8;
  svuint32_t t_9;
  svuint32_t t_10;
  svuint32_t t_11;
  svuint32_t t_12;
  svuint32_t t_13;
  svuint32_t t_14;
  svuint32_t t_15;

  while (bytes >= 16*vc) {
    x_0 = orig0;
    x_1 = orig1;
    x_2 = orig2;
    x_3 = orig3;
    x_4 = orig4;
    x_5 = orig5;
    x_6 = orig6;
    x_7 = orig7;
    x_8 = orig8;
    x_9 = orig9;
    x_10 = orig10;
    x_11 = orig11;
    //x_12 = orig12; /* useless */
    //x_13 = orig13; /* useless */
    x_14 = orig14;
    x_15 = orig15;


    /* svindex() makes it easy to build the input counter */
    const svuint64_t addv13 = svindex_u64(0, 1);
    const svuint64_t addv12 = svadd_n_u64_z(svptrue_b64(), addv13, vc/8);
    svuint64_t t12, t13;
    in12 = x[12];
    in13 = x[13];
    u64 in1213 = ((u64)in12) | (((u64)in13) << 32);
    t12 = svdup_n_u64(in1213);
    t13 = svdup_n_u64(in1213);

    x_12 = svreinterpret_u32_u64(svadd_u64_z(svptrue_b64(), addv12, t12));
    x_13 = svreinterpret_u32_u64(svadd_u64_z(svptrue_b64(), addv13, t13));

    svuint32_t t = x_12;
    x_12 = svuzp1_u32(x_13, x_12);
    x_13 = svuzp2_u32(x_13, t);


    orig12 = x_12;
    orig13 = x_13;

    in1213 += vc/4;
    
    x[12] = in1213 & 0xFFFFFFFF;
    x[13] = (in1213>>32)&0xFFFFFFFF;

    for (i = 0 ; i < ROUNDS ; i+=2) {
      VEC4_QUARTERROUND( 0, 4, 8,12);
      VEC4_QUARTERROUND( 1, 5, 9,13);
      VEC4_QUARTERROUND( 2, 6,10,14);
      VEC4_QUARTERROUND( 3, 7,11,15);
      VEC4_QUARTERROUND( 0, 5,10,15);
      VEC4_QUARTERROUND( 1, 6,11,12);
      VEC4_QUARTERROUND( 2, 7, 8,13);
      VEC4_QUARTERROUND( 3, 4, 9,14);
    }

#define ONEQUAD_TRANSPOSE(a,b,c,d)                                      \
    {                                                                   \
      svuint32_t t00, t01, t10, t11;                                    \
      svuint64_t t0, t1, t2, t3;                                        \
      x_##a = svadd_u32_z(svptrue_b32(), x_##a, orig##a);                                \
      x_##b = svadd_u32_z(svptrue_b32(), x_##b, orig##b);                                \
      x_##c = svadd_u32_z(svptrue_b32(), x_##c, orig##c);                                \
      x_##d = svadd_u32_z(svptrue_b32(), x_##d, orig##d);                                \
      t00 = svtrn1_u32(x_##a,x_##b);\
      t01 = svtrn2_u32(x_##a,x_##b);\
      t10 = svtrn1_u32(x_##c,x_##d);\
      t11 = svtrn2_u32(x_##c,x_##d);\
      x_##a = svreinterpret_u32_u64(svtrn1_u64(svreinterpret_u64_u32(t00), svreinterpret_u64_u32(t10)));\
      x_##b = svreinterpret_u32_u64(svtrn1_u64(svreinterpret_u64_u32(t01), svreinterpret_u64_u32(t11)));\
      x_##c = svreinterpret_u32_u64(svtrn2_u64(svreinterpret_u64_u32(t00), svreinterpret_u64_u32(t10)));\
      x_##d = svreinterpret_u32_u64(svtrn2_u64(svreinterpret_u64_u32(t01), svreinterpret_u64_u32(t11)));\
      t0 = sveor_u64_z(svptrue_b64(), svreinterpret_u64_u32(x_##a), svld1_gather_s64offset_u64(svptrue_b64(), (uint64_t*)(m+0), gvv));             \
      svst1_scatter_s64offset_u64(svptrue_b64(), (uint64_t*)(out+0), gvv, t0);\
      t1 = sveor_u64_z(svptrue_b64(), svreinterpret_u64_u32(x_##b), svld1_gather_s64offset_u64(svptrue_b64(), (uint64_t*)(m+64), gvv));             \
      svst1_scatter_s64offset_u64(svptrue_b64(), (uint64_t*)(out+64), gvv, t1);\
      t2 = sveor_u64_z(svptrue_b64(), svreinterpret_u64_u32(x_##c), svld1_gather_s64offset_u64(svptrue_b64(), (uint64_t*)(m+128), gvv));             \
      svst1_scatter_s64offset_u64(svptrue_b64(), (uint64_t*)(out+128), gvv, t2);\
      t3 = sveor_u64_z(svptrue_b64(), svreinterpret_u64_u32(x_##d), svld1_gather_s64offset_u64(svptrue_b64(), (uint64_t*)(m+192), gvv));             \
      svst1_scatter_s64offset_u64(svptrue_b64(), (uint64_t*)(out+192), gvv, t3);\
    }
    
#define ONEQUAD(a,b,c,d) ONEQUAD_TRANSPOSE(a,b,c,d)

    svint64_t gvv, gvvl, gvvh;
    /* But beware, the range of immediates is small in svindex
     * So need to be a bit careful to construct the vector of gather/scatter indices
     */
    gvvl = svindex_s64(0, 1);
    gvvl = svlsl_n_s64_z(svptrue_b64(), gvvl, 8);
    gvvl = svzip1(gvvl, gvvl);
    gvv = svadd_s64_z(svptrue_b64(), gvvl, svdupq_n_s64(0,8));

    ONEQUAD(0,1,2,3);
    m+=16;
    out+=16;
    ONEQUAD(4,5,6,7);
    m+=16;
    out+=16;
    ONEQUAD(8,9,10,11);
    m+=16;
    out+=16;
    ONEQUAD(12,13,14,15);
    m-=48;
    out-=48;
    
#undef ONEQUAD
#undef ONEQUAD_TRANSPOSE

    bytes -= 16*vc;
    out += 16*vc;
    m += 16*vc;
  }
 }
#undef VEC4_ROT
#undef VEC4_QUARTERROUND
