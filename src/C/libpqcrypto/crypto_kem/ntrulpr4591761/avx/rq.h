#ifndef rq_h
#define rq_h

#include "modq.h"
#include "small.h"

extern void rq_encode(unsigned char *,const modq *);

extern void rq_decode(modq *,const unsigned char *);

extern void rq_roundencode(unsigned char *,const modq *);

extern void rq_decoderounded(modq *,const unsigned char *);

extern void rq_round3(modq *,const modq *);

extern void rq_mult(modq *,const modq *,const small *);

int rq_recip3(modq *,const small *);

extern void rq_fromseed(modq *,const unsigned char *);

extern void rq_top(unsigned char *,const modq *,const unsigned char *);

extern void rq_rightsubbit(unsigned char *,const unsigned char *,const modq *);

#endif
