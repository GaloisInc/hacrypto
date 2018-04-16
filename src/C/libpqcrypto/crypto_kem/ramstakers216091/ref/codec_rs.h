#ifndef CODEC_RS
#define CODEC_RS

#include "reedsolomon.h"

typedef struct
{
    int n;
    int k;
    int delta;
    int repetitions;
} codec_rs;

void codec_rs_init( codec_rs * cd, int k, int n, int inner_n, int repetitions );
void codec_rs_destroy( codec_rs cd );
void codec_rs_encode( unsigned char * dest, codec_rs cd, unsigned char * source );
int codec_rs_decode( unsigned char * dest, codec_rs cd, unsigned char * source, unsigned char * helper_data );

#endif

