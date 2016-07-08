/****************************************************************************************
* LatticeCrypto: an efficient post-quantum Ring-Learning With Errors cryptography library
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: testing code
*
*****************************************************************************************/

#include "../LatticeCrypto_priv.h"
#include "test_extras.h"
#include <stdio.h>
#include <malloc.h>

extern const int32_t psi_rev_ntt1024_12289[PARAMETER_N];
extern const int32_t omegainv_rev_ntt1024_12289[PARAMETER_N];
extern const int32_t omegainv7N_rev_ntt1024_12289;
extern const int32_t omegainv10N_rev_ntt1024_12289;
extern const int32_t Ninv8_ntt1024_12289;
extern const int32_t Ninv11_ntt1024_12289;

// Benchmark and test parameters  
#define BENCH_LOOPS       1000       // Number of iterations per bench
#define TEST_LOOPS        100        // Number of iterations per test


bool ntt_test()
{ // Tests for the NTT functions
    bool OK = true;
    int n, passed;
    int32_t a[PARAMETER_N], b[PARAMETER_N], c[PARAMETER_N], d[PARAMETER_N], e[PARAMETER_N], f[PARAMETER_N], g[PARAMETER_N], ff[PARAMETER_N];
    unsigned int pbits = 14;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n"); 
    printf("Testing NTT functions: \n\n"); 

    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {   
        // Testing NTT-based polynomial multiplication
        random_poly_test(a, PARAMETER_Q, pbits, PARAMETER_N); random_poly_test(b, PARAMETER_Q, pbits, PARAMETER_N); 

        mul_test(a, b, c, PARAMETER_Q, PARAMETER_N);
        NTT_CT_std2rev_12289(a, psi_rev_ntt1024_12289, PARAMETER_N);
        NTT_CT_std2rev_12289(b, psi_rev_ntt1024_12289, PARAMETER_N);
        pmul(a, b, d, PARAMETER_N);
        correction(d, PARAMETER_Q, PARAMETER_N);
        INTT_GS_rev2std_12289(d, omegainv_rev_ntt1024_12289, omegainv7N_rev_ntt1024_12289, Ninv8_ntt1024_12289, PARAMETER_N);
        two_reduce12289(d, PARAMETER_N);
        correction(d, PARAMETER_Q, PARAMETER_N);
        if (compare_poly(c, d, PARAMETER_N)!=0) { passed = 0; break; }
                
        // Emulating NTT operations in the key exchange                
        random_poly_test(a, PARAMETER_Q, pbits, PARAMETER_N); random_poly_test(b, PARAMETER_Q, pbits, PARAMETER_N); 
        random_poly_test(c, PARAMETER_Q, pbits, PARAMETER_N); random_poly_test(d, PARAMETER_Q, pbits, PARAMETER_N); 
        random_poly_test(e, PARAMETER_Q, pbits, PARAMETER_N); 

        mul_test(a, b, f, PARAMETER_Q, PARAMETER_N);
        add_test(f, c, f, PARAMETER_Q, PARAMETER_N);
        mul_test(f, d, ff, PARAMETER_Q, PARAMETER_N);
        add_test(ff, e, f, PARAMETER_Q, PARAMETER_N);
        NTT_CT_std2rev_12289(a, psi_rev_ntt1024_12289, PARAMETER_N);
        NTT_CT_std2rev_12289(b, psi_rev_ntt1024_12289, PARAMETER_N);
        NTT_CT_std2rev_12289(c, psi_rev_ntt1024_12289, PARAMETER_N);
        smul(c, 3, PARAMETER_N);
        pmuladd(a, b, c, g, PARAMETER_N);
        correction(g, PARAMETER_Q, PARAMETER_N);
        NTT_CT_std2rev_12289(d, psi_rev_ntt1024_12289, PARAMETER_N);
        NTT_CT_std2rev_12289(e, psi_rev_ntt1024_12289, PARAMETER_N);
        smul(e, 81, PARAMETER_N);
        pmuladd(g, d, e, g, PARAMETER_N);
        correction(g, PARAMETER_Q, PARAMETER_N);
        INTT_GS_rev2std_12289(g, omegainv_rev_ntt1024_12289, omegainv10N_rev_ntt1024_12289, Ninv11_ntt1024_12289, PARAMETER_N);
        two_reduce12289(g, PARAMETER_N);
        correction(g, PARAMETER_Q, PARAMETER_N);
        if (compare_poly(f, g, PARAMETER_N)!=0) { passed = 0; break; }
    } 
    if (passed==1) printf("  INTT/NTT tests................................................................. PASSED");
    else { printf("  NTT/INTT tests... FAILED"); printf("\n"); return false; }
    printf("\n");
    
    return OK;
}


bool ntt_run()
{
    bool OK = true;
    int n;
    unsigned long long cycles, cycles1, cycles2;
    int32_t a[PARAMETER_N];

    printf("\n--------------------------------------------------------------------------------------------------------\n\n"); 
    printf("Benchmarking NTT functions: \n\n");
    
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        NTT_CT_std2rev_12289(a, psi_rev_ntt1024_12289, PARAMETER_N);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  NTT runs in ................................................................... %8lld cycles", cycles/BENCH_LOOPS);
    printf("\n"); 
    
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        INTT_GS_rev2std_12289(a, omegainv_rev_ntt1024_12289, omegainv7N_rev_ntt1024_12289, Ninv8_ntt1024_12289, PARAMETER_N);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  INTT runs in .................................................................. %8lld cycles", cycles/BENCH_LOOPS);
    printf("\n"); 
    
    return OK;
}


CRYPTO_STATUS kex_test()
{ // Tests for the key exchange
    int n, passed;
    int32_t SecretKeyA[PARAMETER_N];
    unsigned char PublicKeyA[PKA_BYTES], PublicKeyB[PKB_BYTES], SharedSecretA[SHAREDKEY_BYTES], SharedSecretB[SHAREDKEY_BYTES];
    PLatticeCryptoStruct pLatticeCrypto;
    RandomBytes RandomBytesFunction = random_bytes_test;
    ExtendableOutput ExtendableOutputFunction = extendable_output_test;
    StreamOutput StreamOutputFunction = stream_output_test;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n"); 
    printf("Testing the key exchange: \n\n"); 

    pLatticeCrypto = LatticeCrypto_allocate();
    Status = LatticeCrypto_initialize(pLatticeCrypto, RandomBytesFunction, ExtendableOutputFunction, StreamOutputFunction);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    passed = 1;
    for (n=0; n<TEST_LOOPS; n++)
    {   
        Status = KeyGeneration_A(SecretKeyA, PublicKeyA, pLatticeCrypto);
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }    
        Status = SecretAgreement_B(PublicKeyA, SharedSecretB, PublicKeyB, pLatticeCrypto);
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }    
        Status = SecretAgreement_A(PublicKeyB, SecretKeyA, SharedSecretA);
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }    

        if (compare_poly((int32_t*)SharedSecretA, (int32_t*)SharedSecretB, SHAREDKEY_BYTES/4)!=0) { passed = 0; break; }
    } 
    if (passed==1) printf("  Key exchange tests............................................................. PASSED");
    else { printf("  Key exchange tests... FAILED"); printf("\n"); Status = CRYPTO_ERROR_SHARED_KEY; goto cleanup; }
    printf("\n");
    
cleanup:
    free(pLatticeCrypto);
    clear_words((void*)SecretKeyA, NBYTES_TO_NWORDS(4*PARAMETER_N));
    clear_words((void*)PublicKeyA, NBYTES_TO_NWORDS(PKA_BYTES));
    clear_words((void*)SharedSecretA, NBYTES_TO_NWORDS(SHAREDKEY_BYTES));
    clear_words((void*)PublicKeyB, NBYTES_TO_NWORDS(PKB_BYTES));
    clear_words((void*)SharedSecretB, NBYTES_TO_NWORDS(SHAREDKEY_BYTES));
    
    return Status;
}


CRYPTO_STATUS kex_run()
{
    int n;
    unsigned long long cycles, cycles1, cycles2;
    int32_t SecretKeyA[PARAMETER_N];
    unsigned char PublicKeyA[PKA_BYTES], PublicKeyB[PKB_BYTES], SharedSecretA[SHAREDKEY_BYTES], SharedSecretB[SHAREDKEY_BYTES];
    PLatticeCryptoStruct pLatticeCrypto;
    RandomBytes RandomBytesFunction = random_bytes_test;
    ExtendableOutput ExtendableOutputFunction = extendable_output_test;
    StreamOutput StreamOutputFunction = stream_output_test;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n"); 
    printf("Benchmarking key exchange functions: \n\n");  
    
    pLatticeCrypto = LatticeCrypto_allocate();
    Status = LatticeCrypto_initialize(pLatticeCrypto, RandomBytesFunction, ExtendableOutputFunction, StreamOutputFunction);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        Status = KeyGeneration_A(SecretKeyA, PublicKeyA, pLatticeCrypto);
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Alice's key generation runs in ................................................ %8lld cycles", cycles/BENCH_LOOPS);
    printf("\n");   
    
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        Status = SecretAgreement_B(PublicKeyA, SharedSecretB, PublicKeyB, pLatticeCrypto);
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Bob's shared key computation runs in .......................................... %8lld cycles", cycles/BENCH_LOOPS);
    printf("\n");   
    
    cycles = 0;
    for (n=0; n<BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles(); 
        Status = SecretAgreement_A(PublicKeyB, SecretKeyA, SharedSecretA);
        if (Status != CRYPTO_SUCCESS) {
            goto cleanup;
        }    
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    printf("  Alice's shared key computation runs in ........................................ %8lld cycles", cycles/BENCH_LOOPS);
    printf("\n");
    
cleanup:
    free(pLatticeCrypto);
    clear_words((void*)SecretKeyA, NBYTES_TO_NWORDS(4*PARAMETER_N));
    clear_words((void*)PublicKeyA, NBYTES_TO_NWORDS(PKA_BYTES));
    clear_words((void*)SharedSecretA, NBYTES_TO_NWORDS(SHAREDKEY_BYTES));
    clear_words((void*)PublicKeyB, NBYTES_TO_NWORDS(PKB_BYTES));
    clear_words((void*)SharedSecretB, NBYTES_TO_NWORDS(SHAREDKEY_BYTES)); 
    
    return Status;
}


int main()
{
    bool OK = true;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;

    OK = OK && ntt_test();   // Test NTT functions
    OK = OK && ntt_run();    // Benchmark NTT functions
    if (OK == false) {
        return true;
    }

    Status = kex_test();     // Test key exchange 
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", LatticeCrypto_get_error_message(Status));
        return false;
    }
    Status = kex_run();      // Benchmark key exchange
    if (Status != CRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", LatticeCrypto_get_error_message(Status));
        return false;
    }

    return true;
}
