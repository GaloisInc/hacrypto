#include "codec_rs.h"
#include <libkeccak.a.headers/SimpleFIPS202.h>
#include <stdio.h>
#include <stdlib.h>


/**
 * codec_rs_init
 * Create codec object for RS repetition code.
 */
void codec_rs_init( codec_rs * cd, int k, int n, int inner_n, int repetitions )
{
    cd->k = k;
    cd->repetitions = n / (RS_N*8);
    if( repetitions > 0 && repetitions < cd->repetitions )
    {
        cd->repetitions = repetitions;
    }
    cd->n = RS_N*8*repetitions;
}

/**
 * codec_rs_destroy
 * Destroy repetition RS codec object.
 */
void codec_rs_destroy( codec_rs cd )
{
}

/**
 * codec_rs_encode
 * Encode a string of k bits into a repeated codeword of length n.
 * If k or n is not divisible by 8, the most significant bits of the
 * last byte is not used.
 */
void codec_rs_encode( unsigned char * dest, codec_rs cd, unsigned char * source )
{
    int i;
    for( i = 0 ; i < cd.repetitions ; ++i )
    {
        rs_encode(dest+i*RS_N, source);
    }
}

/**
 * codec_rs_decode
 * Decode a repeated RS codeword of length n into a message of
 * length k bits. If either number is not divisible by 8, then the
 * most significant bits of the last byte are not used.
 */
int codec_rs_decode( unsigned char * dest, codec_rs cd, unsigned char * source, unsigned char * helper_data )
{
    int equals;
    int i, j;
    unsigned char hash[32];

    equals = 1;
    for( i = 0 ; i < cd.repetitions ; ++i )
    {
        /* decode */
        rs_decode(dest, source + i*RS_N);

        /* compute hash */
        SHA3_256(hash, dest, 32);

        /* compare against helper data */
        equals = 1;
        for( j = 0 ; j < 32 ; ++j )
        {
            equals &= (hash[j] == helper_data[j]);
        }

        if( equals == 1 )
        {
           return 1;
        }
    }

    return equals;
}

