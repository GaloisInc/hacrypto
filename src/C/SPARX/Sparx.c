/*
 *
 * SPARX - A Family of Lightweight Block Ciphers
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 * Cryptolux <http://www.cryptolux.org/>
 *
 * Written by Leo Perrin <leo.perrin@uni.lu> and Daniel Dinu
 * <dumitru-daniel.dinu@uni.lu>
 *
 * Version 1.0 from 15.10.2016, see <http://www.cryptolux.org/> for updates
 *
 * Copyright (C) 2016 University of Luxembourg
 *
 * SPARX is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * SPARX is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


/* SPARX versions */
#define SPARX_64_128  0
#define SPARX_128_128 1
#define SPARX_128_256 2


/*
 * Select SPARX version from:
 *  - SPARX_64_128
 *  - SPARX_128_128
 *  - SPARX_128_256
 */
#ifndef VERSION
#define VERSION SPARX_64_128
#endif


#define ROTL(x, n) (((x) << n) | ((x) >> (16 - (n))))
#define SWAP(x, y) tmp = x; x = y; y = tmp


#if (VERSION == SPARX_64_128)

#define N_STEPS 8
#define ROUNDS_PER_STEPS 3
#define N_BRANCHES 2
#define K_SIZE 4
#define L L_2
#define L_inv L_2_inv
#define K_perm K_perm_64_128

#elif (VERSION == SPARX_128_128)

#define N_STEPS 8
#define ROUNDS_PER_STEPS 4
#define N_BRANCHES 4
#define K_SIZE 4
#define L L_4
#define L_inv L_4_inv
#define K_perm K_perm_128_128

#elif (VERSION == SPARX_128_256)

#define N_STEPS 10
#define ROUNDS_PER_STEPS 4
#define N_BRANCHES 4
#define K_SIZE 8
#define L L_4
#define L_inv L_4_inv
#define K_perm K_perm_128_256

#endif


/* !SECTION! Basic functions and their inverses */
/* ============================================ */

/* One keyless round of SPECK-32 */
void A(uint16_t * l, uint16_t * r)
{
    (*l) = ROTL((*l), 9);
    (*l) += (*r);
    (*r) = ROTL((*r), 2);
    (*r) ^= (*l);
}

void A_inv(uint16_t * l, uint16_t * r)
{
    (*r) ^= (*l);
    (*r) = ROTL((*r), 14);
    (*l) -= (*r);
    (*l) = ROTL((*l), 7);
}


/* The linear layers */

void L_2(uint16_t * x)
{
    uint16_t tmp = ROTL((x[0] ^ x[1]), 8);
    x[2] ^= x[0] ^ tmp;
    x[3] ^= x[1] ^ tmp;
    SWAP(x[0], x[2]);
    SWAP(x[1], x[3]);
}

void L_2_inv(uint16_t * x)
{
    uint16_t tmp;
    SWAP(x[0], x[2]);
    SWAP(x[1], x[3]);
    tmp = ROTL(x[0] ^ x[1], 8);
    x[2] ^= x[0] ^ tmp;
    x[3] ^= x[1] ^ tmp;
}


void L_4(uint16_t * x)
{
    uint16_t tmp = x[0] ^ x[1] ^ x[2] ^ x[3];
    tmp = ROTL(tmp, 8);

    x[4] ^= x[2] ^ tmp;
    x[5] ^= x[1] ^ tmp;
    x[6] ^= x[0] ^ tmp;
    x[7] ^= x[3] ^ tmp;

    SWAP(x[0], x[4]);
    SWAP(x[1], x[5]);
    SWAP(x[2], x[6]);
    SWAP(x[3], x[7]);
}

void L_4_inv(uint16_t * x)
{
    uint16_t tmp;
    SWAP(x[0], x[4]);
    SWAP(x[1], x[5]);
    SWAP(x[2], x[6]);
    SWAP(x[3], x[7]);

    tmp = x[0] ^ x[1] ^ x[2] ^ x[3];
    tmp = ROTL(tmp, 8);
    x[4] ^= x[2] ^ tmp;
    x[5] ^= x[1] ^ tmp;
    x[6] ^= x[0] ^ tmp;
    x[7] ^= x[3] ^ tmp;
}


/* !SECTION! Key schedule  */
/* ======================= */


/* The permutation of the key state */
void K_perm_64_128(uint16_t * k, uint16_t c)
{
    uint16_t tmp_0, tmp_1, i;
    /* Misty-like transformation */
    A(k+0, k+1);
    k[2] += k[0];
    k[3] += k[1];
    k[7] += c;
    /* Branch rotation */
    tmp_0 = k[6];
    tmp_1 = k[7];
    for (i=7 ; i>=2 ; i--)
    {
        k[i] = k[i-2];
    }
    k[0] = tmp_0;
    k[1] = tmp_1;
}

void K_perm_128_128(uint16_t * k, uint16_t c)
{
    uint16_t tmp_0, tmp_1, i;
    /* Misty-like transformation */
    A(k+0, k+1);
    k[2] += k[0];
    k[3] += k[1];
    A(k+4, k+5);
    k[6] += k[4];
    k[7] += k[5] + c;
    /* Branch rotation */
    tmp_0 = k[6];
    tmp_1 = k[7];
    for (i=7 ; i>=2 ; i--)
    {
        k[i] = k[i-2];
    }
    k[0] = tmp_0;
    k[1] = tmp_1;
}


void K_perm_128_256(uint16_t * k, uint16_t c)
{
    uint16_t tmp[6], i;
    /* Misty-like transformation */
    A(k+0, k+1);
    k[2] += k[0];
    k[3] += k[1];
    A(k+8, k+9);
    k[10] += k[8];
    k[11] += k[9] + c;
    /* Branch rotation */
    for (i=0 ; i<6 ; i++)
    {
        tmp[i] = k[10+i];
    }
    for (i=15 ; i>=6 ; i--)
    {
        k[i] = k[i-6];
    }
    for (i=0 ; i<6 ; i++)
    {
        k[i] = tmp[i];
    }
}


/* Takes a 128 bit master key and turns it into 2*(N_STEPS+1) subkeys
 * of 96 bits */
void key_schedule(uint16_t subkeys[][2*ROUNDS_PER_STEPS], uint16_t * master_key)
{
    uint8_t c, i;
    for (c=0 ; c<(N_BRANCHES*N_STEPS+1) ; c++)
    {
        for (i=0 ; i<2*ROUNDS_PER_STEPS ; i++)
        {
            subkeys[c][i] = master_key[i];
        }
        K_perm(master_key, c+1);
    }
}


/* !SECTION! Encryption and decryption */
/* =================================== */

void sparx_encrypt(uint16_t * x, uint16_t k[][2*ROUNDS_PER_STEPS])
{
    uint8_t s, r, b;

    s=0; b=0; r=0;
    for (s=0 ; s<N_STEPS ; s++)
    {
        for (b=0 ; b<N_BRANCHES ; b++)
        {
            for (r=0 ; r<ROUNDS_PER_STEPS ; r++)
            {
                x[2*b  ] ^= k[N_BRANCHES*s + b][2*r    ];
                x[2*b+1] ^= k[N_BRANCHES*s + b][2*r + 1];
                A(x + 2*b, x + 2*b+1);
            }
        }
        L(x);
    }
    for (b=0 ; b<N_BRANCHES ; b++)
    {
        x[2*b  ] ^= k[N_BRANCHES*N_STEPS][2*b  ];
        x[2*b+1] ^= k[N_BRANCHES*N_STEPS][2*b+1];
    }
}


void sparx_decrypt(uint16_t * x, uint16_t k[][2*ROUNDS_PER_STEPS])
{
    int8_t s, r, b;

    for (b=0 ; b<N_BRANCHES ; b++)
    {
        x[2*b  ] ^= k[N_BRANCHES*N_STEPS][2*b  ];
        x[2*b+1] ^= k[N_BRANCHES*N_STEPS][2*b+1];
    }
    for (s=N_STEPS-1 ; s >= 0 ; s--)
    {
        L_inv(x);
        for (b=0 ; b<N_BRANCHES ; b++)
            for (r=ROUNDS_PER_STEPS-1 ; r >= 0 ; r--)
            {
                A_inv(x + 2*b, x + 2*b+1);
                x[2*b  ] ^= k[N_BRANCHES*s + b][2*r    ];
                x[2*b+1] ^= k[N_BRANCHES*s + b][2*r + 1];
            }
    }
}


/* !SECTION! Test vectors */
/* ====================== */
uint16_t sparx_64_128_key[] = {
    0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xaabb, 0xccdd, 0xeeff};

uint16_t sparx_64_128_plaintext[] = {0x0123, 0x4567, 0x89ab, 0xcdef};
uint16_t sparx_64_128_ciphertext[] = {0x2bbe, 0xf152, 0x01f5, 0x5f98};


uint16_t sparx_128_128_key[] = {
    0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xaabb, 0xccdd, 0xeeff};

uint16_t sparx_128_128_plaintext[] = {
    0x0123, 0x4567, 0x89ab, 0xcdef, 0xfedc, 0xba98, 0x7654, 0x3210};
uint16_t sparx_128_128_ciphertext[] = {
    0x1cee, 0x7540, 0x7dbf, 0x23d8, 0xe0ee, 0x1597, 0xf428, 0x52d8};


uint16_t sparx_128_256_key[] = {
    0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xaabb, 0xccdd, 0xeeff,
    0xffee, 0xddcc, 0xbbaa, 0x9988, 0x7766, 0x5544, 0x3322, 0x1100};

uint16_t sparx_128_256_plaintext[] = {
    0x0123, 0x4567, 0x89ab, 0xcdef, 0xfedc, 0xba98, 0x7654, 0x3210};
uint16_t sparx_128_256_ciphertext[] = {
    0x3328, 0xe637, 0x14c7, 0x6ce6, 0x32d1, 0x5a54, 0xe4b0, 0xc820};



/* !SECTION! Helper functions */
/* ========================== */
void initialize_test_vectors(uint16_t * x, uint16_t * master_key)
{
    uint8_t i;

    uint16_t *p_key;
    uint16_t *p_plaintext;


    if (VERSION == SPARX_64_128)
    {
        printf("SPARX-64/128\n");
        p_key = sparx_64_128_key;
        p_plaintext = sparx_64_128_plaintext;
    }

    if (VERSION == SPARX_128_128)
    {
        printf("SPARX-128/128\n");
        p_key = sparx_128_128_key;
        p_plaintext = sparx_128_128_plaintext;
    }

    if (VERSION == SPARX_128_256)
    {
        printf("SPARX-128/256\n");
        p_key = sparx_128_256_key;
        p_plaintext = sparx_128_256_plaintext;
    }


    /* Set test vectors */
    for (i=0 ; i<2*K_SIZE ; i++)
    {
        master_key[i] = p_key[i];
    }
    for (i=0 ; i<2*N_BRANCHES ; i++)
    {
        x[i] = p_plaintext[i];
    }


    printf("steps=%d, rounds/steps=%d, block=32*%d\n\n",
           N_STEPS,
           ROUNDS_PER_STEPS,
           N_BRANCHES);
}


void check_test_vectors(uint16_t * x, uint8_t op)
{
    uint8_t i;
    uint8_t correct = 1;

    uint16_t *p_tv;
    uint16_t *p_plaintext;
    uint16_t *p_ciphertext;


    if (VERSION == SPARX_64_128)
    {
        p_plaintext = sparx_64_128_plaintext;
        p_ciphertext = sparx_64_128_ciphertext;
    }

    if (VERSION == SPARX_128_128)
    {
        p_plaintext = sparx_128_128_plaintext;
        p_ciphertext = sparx_128_128_ciphertext;
    }

    if (VERSION == SPARX_128_256)
    {
        p_plaintext = sparx_128_256_plaintext;
        p_ciphertext = sparx_128_256_ciphertext;
    }

    if(0 == op)
    {
        p_tv = p_ciphertext;
    }
    else
    {
        p_tv = p_plaintext;
    }

    for (i=0 ; i<2*N_BRANCHES ; i++)
    {
        if (x[i] != p_tv[i])
        {
            correct = 0;
        }
    }

    correct ? printf("\t OK!") : printf("\t WRONG!") ;
}



/* !SECTION! Main function */
/* ======================= */

int main()
{
    uint16_t
        x[2*N_BRANCHES],
        master_key[2*K_SIZE],
        k[N_BRANCHES*N_STEPS+1][2*ROUNDS_PER_STEPS] = {{0}};
    uint8_t i, j;


    initialize_test_vectors(x, master_key);


    printf("master = ");
    for (i=0 ; i<2*K_SIZE ; i++)
    {
        printf("%04x ", master_key[i]);
    }


    key_schedule(k, master_key);
    for (i=0 ; i<N_BRANCHES*N_STEPS+1 ; i++)
    {
        printf("\nk^{%2d} = ", i);
        for (j=0 ; j<2*ROUNDS_PER_STEPS ; j++)
            printf("%04x ", k[i][j]);
    }


    printf("\n\nplaintext  = ");
    for (i=0 ; i<2*N_BRANCHES ; i++)
    {
        printf("%04x ", x[i]);
    }


    sparx_encrypt(x, k);
    printf("\nciphertext = ");
    for (i=0 ; i<2*N_BRANCHES ; i++)
    {
        printf("%04x ", x[i]);
    }
    check_test_vectors(x, 0);


    sparx_decrypt(x, k);
    printf("\ndecryption = ");
    for (i=0 ; i<2*N_BRANCHES ; i++)
    {
        printf("%04x ", x[i]);
    }
    check_test_vectors(x, 1);


    printf("\n");
    return 0;
}
