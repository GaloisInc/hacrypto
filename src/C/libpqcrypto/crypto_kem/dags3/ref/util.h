
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include "matrix.h"
#include "time.h"

int weight(unsigned char *r, int size);

unsigned char *random_m(int size);

int indice_in_vec(unsigned int *v, int j, int size);

unsigned char *random_e(int size, int q, int w, unsigned char *sigma);

void recup_pk(const unsigned char *pk, binmat_t G);

void store_pk(binmat_t M, unsigned char *pk);

void store_sk(binmat_t H_alt, unsigned char *sk);

binmat_t read_sk(const unsigned char *sk);
