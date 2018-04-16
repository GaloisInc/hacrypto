#ifndef CSPRNG_H
#define CSPRNG_H

#define csprng_state_size 200
#define csprng_seed_rate 32
#define csprng_gen_rate 32

typedef struct
{
    unsigned char state[csprng_state_size];
} csprng;

int csprng_init( csprng* rng );
int csprng_seed( csprng* rng, unsigned short int seed_length, unsigned char * seed );
int csprng_generate( csprng* rng, unsigned int buffer_length, unsigned char * buffer );
unsigned long int csprng_generate_ulong( csprng * rng );
void csprng_print_state( csprng rng );

#endif

