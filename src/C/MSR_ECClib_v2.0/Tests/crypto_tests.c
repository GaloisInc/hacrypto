/**************************************************************************
* Suite for benchmarking/testing crypto operations for MSR ECClib
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*    MIT License
*
*    Permission is hereby granted, free of charge, to any person obtaining 
*    a copy of this software and associated documentation files (the 
*    ""Software""), to deal in the Software without restriction, including
*    without limitation the rights to use, copy, modify, merge, publish,
*    distribute, sublicense, and/or sell copies of the Software, and to
*    permit persons to whom the Software is furnished to do so, subject to
*    the following conditions:
*
*    The above copyright notice and this permission notice shall
*    be included in all copies or substantial portions of the Software.
*
*    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND,
*    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
*    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
*    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
*    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
*    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
*    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*
* Abstract: benchmarking/testing cryptographic operations
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
***************************************************************************/  

#include "msr_ecclib_priv.h"
#include "tests.h"
#if OS_TARGET == OS_WIN
    #include <windows.h>
#endif
#include <stdio.h>
#include <string.h>
#include <malloc.h>


#ifdef ECCURVES_256

ECCRYPTO_STATUS crypto_test256_w(PCurveStaticData CurveData)
{ // Crypto tests for curve numsp256d1
    dig256 PrivateKeyA, PrivateKeyB, SharedSecretA, SharedSecretB, R, S;
    point_numsp256d1 PublicKeyA, PublicKeyB, *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[256/8];
    PCurveStruct JacCurve = {0};
    dig ffff[256/8]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL passed, valid = FALSE;

    printf("\n\nTESTING \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp256d1, Weierstrass a=-3 curve over GF(2^256-189) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    /***** Test for ECDH(E) *****/
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp256d1(OP_FIXEDBASE, JacCurve);     // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp256d1(TableGen, JacCurve);            // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecc_full_keygen_numsp256d1(TableGen, PrivateKeyA, PublicKeyA, JacCurve);             // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Alice's public key PK_A = a*P
        goto cleanup;
    }    
    Status = ecc_full_keygen_numsp256d1(TableGen, PrivateKeyB, PublicKeyB, JacCurve);             // Get some value as Bob's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Bob's public key PK_B = b*P
        goto cleanup;
    }

    Status = ecdh_secret_agreement_numsp256d1(PrivateKeyA, PublicKeyB, SharedSecretA, JacCurve);  // Alice computes her shared key using Bob's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }    
    Status = ecdh_secret_agreement_numsp256d1(PrivateKeyB, PublicKeyA, SharedSecretB, JacCurve);  // Bob computes his shared key using Alice's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (fpcompare256(SharedSecretA, SharedSecretB) != 0)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDH(E) tests ........................................................................... PASSED");
    else { printf("  ECDH(E) tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SHARED_KEY; goto cleanup; }
        printf("\n"); 

    if (TableGen != NULL) {
        free(TableGen);
    }

    /***** Test for ECDSA *****/
    // Signing
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp256d1(OP_FIXEDBASE, JacCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp256d1(TableGen, JacCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)256/8);
    random256_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    Status = ecc_full_keygen_numsp256d1(TableGen, PrivateKeyA, PublicKeyA, JacCurve);   // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                   // Compute Alice's public key PK_A = a*P
        goto cleanup;
    }
    
    // Compute signature {R,S}
    Status = ecdsa_sign_numsp256d1(PrivateKeyA, TableGen, HashedMessage, 256/8, R, S, JacCurve); 
    if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
    }
        
    // Signature verification
    TableVer = ecc_allocate_precomp_numsp256d1(OP_DOUBLESCALAR, JacCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp256d1(TableVer, JacCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecdsa_verify_numsp256d1(TableVer, PublicKeyA, HashedMessage, 256/8, R, S, &valid, JacCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == FALSE)
        passed = FALSE;
    
    // Produce invalid signature {R,S} by flipping one bit 
    R[0] = ((R[0] ^ (dig)1) & (dig)1) | (R[0] & ((dig)-1 << 1));
        
    // Signature verification
    Status = ecdsa_verify_numsp256d1(TableVer, PublicKeyA, HashedMessage, 256/8, R, S, &valid, JacCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == TRUE)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDSA tests ............................................................................. PASSED");
    else { printf("  ECDSA tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SIGNATURE_VERIFICATION; goto cleanup; }
        printf("\n");

cleanup:
    ecc_curve_free(JacCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    fpzero256(PrivateKeyA);
    fpzero256(PrivateKeyB);
    fpzero256(SharedSecretA);
    fpzero256(SharedSecretB);

    return Status;
}

ECCRYPTO_STATUS crypto_test256_te(PCurveStaticData CurveData)
{ // Crypto tests for curve numsp256t1
    dig256 PrivateKeyA, PrivateKeyB, SharedSecretA, SharedSecretB, R, S;
    point_numsp256t1 PublicKeyA, PublicKeyB;
    point_extaff_precomp_numsp256t1 *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[256/8];
    PCurveStruct TedCurve = {0};
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL passed, valid = FALSE;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp256t1, twisted Edwards a=1 curve over GF(2^256-189) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Test for ECDH(E)
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp256t1(OP_FIXEDBASE, TedCurve);     // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_generator_table_numsp256t1(TableGen, TedCurve);            // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecc_full_keygen_numsp256t1(TableGen, PrivateKeyA, PublicKeyA, TedCurve);             // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Alice's public key PK_A = a*P
        goto cleanup;
    }    
    Status = ecc_full_keygen_numsp256t1(TableGen, PrivateKeyB, PublicKeyB, TedCurve);             // Get some value as Bob's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Bob's public key PK_B = b*P
        goto cleanup;
    }

    Status = ecdh_secret_agreement_numsp256t1(PrivateKeyA, PublicKeyB, SharedSecretA, TedCurve);  // Alice computes her shared key using Bob's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    Status = ecdh_secret_agreement_numsp256t1(PrivateKeyB, PublicKeyA, SharedSecretB, TedCurve);  // Bob computes his shared key using Alice's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (fpcompare256(SharedSecretA, SharedSecretB) != 0)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDH(E) tests ........................................................................... PASSED");
    else { printf("  ECDH(E) tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SHARED_KEY; goto cleanup; }
    printf("\n");

    if (TableGen != NULL) {
        free(TableGen);
    }

    /***** Test for ECDSA *****/
    // Signing
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp256t1(OP_FIXEDBASE, TedCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp256t1(TableGen, TedCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)256/8);
    random256_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    Status = ecc_full_keygen_numsp256t1(TableGen, PrivateKeyA, PublicKeyA, TedCurve);   // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                   // Compute Alice's public key PK_A = a*P
        goto cleanup;
    }
    
    // Compute signature {R,S}
    Status = ecdsa_sign_numsp256t1(PrivateKeyA, TableGen, HashedMessage, 256/8, R, S, TedCurve); 
    if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
    }
        
    // Signature verification
    TableVer = ecc_allocate_precomp_numsp256t1(OP_DOUBLESCALAR, TedCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp256t1(TableVer, TedCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecdsa_verify_numsp256t1(TableVer, PublicKeyA, HashedMessage, 256/8, R, S, &valid, TedCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == FALSE)
        passed = FALSE;
    
    // Produce invalid signature {R,S} by flipping one bit 
    R[0] = ((R[0] ^ (dig)1) & (dig)1) | (R[0] & ((dig)-1 << 1));
        
    // Signature verification
    Status = ecdsa_verify_numsp256t1(TableVer, PublicKeyA, HashedMessage, 256/8, R, S, &valid, TedCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == TRUE)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDSA tests ............................................................................. PASSED");
    else { printf("  ECDSA tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SIGNATURE_VERIFICATION; goto cleanup; }
        printf("\n");

cleanup:
    ecc_curve_free(TedCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    fpzero256(PrivateKeyA);
    fpzero256(PrivateKeyB);
    fpzero256(SharedSecretA);
    fpzero256(SharedSecretB);

    return Status;
}

#endif


#ifdef ECCURVES_384

ECCRYPTO_STATUS crypto_test384_w(PCurveStaticData CurveData)
{ // Crypto tests for curve numsp384d1
    dig384 PrivateKeyA, PrivateKeyB, SharedSecretA, SharedSecretB, R, S;
    point_numsp384d1 PublicKeyA, PublicKeyB, *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[384/8];
    PCurveStruct JacCurve = {0};
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL passed, valid = FALSE;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp384d1, Weierstrass a=-3 curve over GF(2^384-317) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    /***** Test for ECDH(E) *****/
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp384d1(OP_FIXEDBASE, JacCurve);     // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp384d1(TableGen, JacCurve);            // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecc_full_keygen_numsp384d1(TableGen, PrivateKeyA, PublicKeyA, JacCurve);             // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Alice's public key PK_A = a*P
        goto cleanup;
    }    
    Status = ecc_full_keygen_numsp384d1(TableGen, PrivateKeyB, PublicKeyB, JacCurve);             // Get some value as Bob's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Bob's public key PK_B = b*P
        goto cleanup;
    }

    Status = ecdh_secret_agreement_numsp384d1(PrivateKeyA, PublicKeyB, SharedSecretA, JacCurve);  // Alice computes her shared key using Bob's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }    
    Status = ecdh_secret_agreement_numsp384d1(PrivateKeyB, PublicKeyA, SharedSecretB, JacCurve);  // Bob computes his shared key using Alice's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (fpcompare384(SharedSecretA, SharedSecretB) != 0)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDH(E) tests ........................................................................... PASSED");
    else { printf("  ECDH(E) tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SHARED_KEY; goto cleanup; }
        printf("\n"); 

    if (TableGen != NULL) {
        free(TableGen);
    }

    /***** Test for ECDSA *****/
    // Signing
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp384d1(OP_FIXEDBASE, JacCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp384d1(TableGen, JacCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)384/8);
    random384_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    Status = ecc_full_keygen_numsp384d1(TableGen, PrivateKeyA, PublicKeyA, JacCurve);   // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                   // Compute Alice's public key PK_A = a*P
        goto cleanup;
    }
    
    // Compute signature {R,S}
    Status = ecdsa_sign_numsp384d1(PrivateKeyA, TableGen, HashedMessage, 384/8, R, S, JacCurve); 
    if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
    }
        
    // Signature verification
    TableVer = ecc_allocate_precomp_numsp384d1(OP_DOUBLESCALAR, JacCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp384d1(TableVer, JacCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecdsa_verify_numsp384d1(TableVer, PublicKeyA, HashedMessage, 384/8, R, S, &valid, JacCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == FALSE)
        passed = FALSE;
    
    // Produce invalid signature {R,S} by flipping one bit 
    R[0] = ((R[0] ^ (dig)1) & (dig)1) | (R[0] & ((dig)-1 << 1));
        
    // Signature verification
    Status = ecdsa_verify_numsp384d1(TableVer, PublicKeyA, HashedMessage, 384/8, R, S, &valid, JacCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == TRUE)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDSA tests ............................................................................. PASSED");
    else { printf("  ECDSA tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SIGNATURE_VERIFICATION; goto cleanup; }
        printf("\n");

cleanup:
    ecc_curve_free(JacCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    fpzero384(PrivateKeyA);
    fpzero384(PrivateKeyB);
    fpzero384(SharedSecretA);
    fpzero384(SharedSecretB);

    return Status;
}

ECCRYPTO_STATUS crypto_test384_te(PCurveStaticData CurveData)
{ // Crypto tests for curve numsp384t1
    dig384 PrivateKeyA, PrivateKeyB, SharedSecretA, SharedSecretB, R, S;
    point_numsp384t1 PublicKeyA, PublicKeyB;
    point_extaff_precomp_numsp384t1 *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[384/8];
    PCurveStruct TedCurve = {0};
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL passed, valid = FALSE;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp384t1, twisted Edwards a=1 curve over GF(2^384-317) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Test for ECDH(E)
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp384t1(OP_FIXEDBASE, TedCurve);     // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_generator_table_numsp384t1(TableGen, TedCurve);            // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecc_full_keygen_numsp384t1(TableGen, PrivateKeyA, PublicKeyA, TedCurve);             // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Alice's public key PK_A = a*P
        goto cleanup;
    }    
    Status = ecc_full_keygen_numsp384t1(TableGen, PrivateKeyB, PublicKeyB, TedCurve);             // Get some value as Bob's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Bob's public key PK_B = b*P
        goto cleanup;
    }

    Status = ecdh_secret_agreement_numsp384t1(PrivateKeyA, PublicKeyB, SharedSecretA, TedCurve);  // Alice computes her shared key using Bob's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    Status = ecdh_secret_agreement_numsp384t1(PrivateKeyB, PublicKeyA, SharedSecretB, TedCurve);  // Bob computes his shared key using Alice's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (fpcompare384(SharedSecretA, SharedSecretB) != 0 || fpcompare384(SharedSecretA + ML_WORDS384, SharedSecretA + ML_WORDS384) != 0)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDH(E) tests ........................................................................... PASSED");
    else { printf("  ECDH(E) tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SHARED_KEY; goto cleanup; }
    printf("\n");

    if (TableGen != NULL) {
        free(TableGen);
    }

    /***** Test for ECDSA *****/
    // Signing
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp384t1(OP_FIXEDBASE, TedCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp384t1(TableGen, TedCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)384/8);
    random384_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    Status = ecc_full_keygen_numsp384t1(TableGen, PrivateKeyA, PublicKeyA, TedCurve);   // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                   // Compute Alice's public key PK_A = a*P
        goto cleanup;
    }
    
    // Compute signature {R,S}
    Status = ecdsa_sign_numsp384t1(PrivateKeyA, TableGen, HashedMessage, 384/8, R, S, TedCurve); 
    if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
    }
        
    // Signature verification
    TableVer = ecc_allocate_precomp_numsp384t1(OP_DOUBLESCALAR, TedCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp384t1(TableVer, TedCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecdsa_verify_numsp384t1(TableVer, PublicKeyA, HashedMessage, 384/8, R, S, &valid, TedCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == FALSE)
        passed = FALSE;
    
    // Produce invalid signature {R,S} by flipping one bit 
    R[0] = ((R[0] ^ (dig)1) & (dig)1) | (R[0] & ((dig)-1 << 1));
        
    // Signature verification
    Status = ecdsa_verify_numsp384t1(TableVer, PublicKeyA, HashedMessage, 384/8, R, S, &valid, TedCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == TRUE)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDSA tests ............................................................................. PASSED");
    else { printf("  ECDSA tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SIGNATURE_VERIFICATION; goto cleanup; }
        printf("\n");

cleanup:
    ecc_curve_free(TedCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    fpzero384(PrivateKeyA);
    fpzero384(PrivateKeyB);
    fpzero384(SharedSecretA);
    fpzero384(SharedSecretB);

    return Status;
}

#endif


#ifdef ECCURVES_512

ECCRYPTO_STATUS crypto_test512_w(PCurveStaticData CurveData)
{ // Crypto tests for curve numsp512d1
    dig512 PrivateKeyA, PrivateKeyB, SharedSecretA, SharedSecretB, R, S;
    point_numsp512d1 PublicKeyA, PublicKeyB, *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[512/8];
    PCurveStruct JacCurve = {0};
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL passed, valid = FALSE;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp512d1, Weierstrass a=-3 curve over GF(2^512-569) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    /***** Test for ECDH(E) *****/
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp512d1(OP_FIXEDBASE, JacCurve);     // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp512d1(TableGen, JacCurve);            // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecc_full_keygen_numsp512d1(TableGen, PrivateKeyA, PublicKeyA, JacCurve);             // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Alice's public key PK_A = a*P
        goto cleanup;
    }    
    Status = ecc_full_keygen_numsp512d1(TableGen, PrivateKeyB, PublicKeyB, JacCurve);             // Get some value as Bob's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Bob's public key PK_B = b*P
        goto cleanup;
    }

    Status = ecdh_secret_agreement_numsp512d1(PrivateKeyA, PublicKeyB, SharedSecretA, JacCurve);  // Alice computes her shared key using Bob's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }    
    Status = ecdh_secret_agreement_numsp512d1(PrivateKeyB, PublicKeyA, SharedSecretB, JacCurve);  // Bob computes his shared key using Alice's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (fpcompare512(SharedSecretA, SharedSecretB) != 0)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDH(E) tests ........................................................................... PASSED");
    else { printf("  ECDH(E) tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SHARED_KEY; goto cleanup; }
        printf("\n"); 

    if (TableGen != NULL) {
        free(TableGen);
    }

    /***** Test for ECDSA *****/
    // Signing
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp512d1(OP_FIXEDBASE, JacCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp512d1(TableGen, JacCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)512/8);
    random512_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    Status = ecc_full_keygen_numsp512d1(TableGen, PrivateKeyA, PublicKeyA, JacCurve);   // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                   // Compute Alice's public key PK_A = a*P
        goto cleanup;
    }
    
    // Compute signature {R,S}
    Status = ecdsa_sign_numsp512d1(PrivateKeyA, TableGen, HashedMessage, 512/8, R, S, JacCurve); 
    if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
    }
        
    // Signature verification
    TableVer = ecc_allocate_precomp_numsp512d1(OP_DOUBLESCALAR, JacCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp512d1(TableVer, JacCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecdsa_verify_numsp512d1(TableVer, PublicKeyA, HashedMessage, 512/8, R, S, &valid, JacCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == FALSE)
        passed = FALSE;
    
    // Produce invalid signature {R,S} by flipping one bit 
    R[0] = ((R[0] ^ (dig)1) & (dig)1) | (R[0] & ((dig)-1 << 1));
        
    // Signature verification
    Status = ecdsa_verify_numsp512d1(TableVer, PublicKeyA, HashedMessage, 512/8, R, S, &valid, JacCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == TRUE)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDSA tests ............................................................................. PASSED");
    else { printf("  ECDSA tests ... FAILED"); Status = ECCRYPTO_ERROR_SIGNATURE_VERIFICATION; printf("\n"); goto cleanup; }
        printf("\n");

cleanup:
    ecc_curve_free(JacCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    fpzero512(PrivateKeyA);
    fpzero512(PrivateKeyB);
    fpzero512(SharedSecretA);
    fpzero512(SharedSecretB);

    return Status;
}

ECCRYPTO_STATUS crypto_test512_te(PCurveStaticData CurveData)
{ // Crypto tests for curve numsp512t1
    dig512 PrivateKeyA, PrivateKeyB, SharedSecretA, SharedSecretB, R, S;
    point_numsp512t1 PublicKeyA, PublicKeyB;
    point_extaff_precomp_numsp512t1 *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[512/8];
    PCurveStruct TedCurve = {0};
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL passed, valid = FALSE;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp512t1, twisted Edwards a=1 curve over GF(2^512-569) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Test for ECDH(E)
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp512t1(OP_FIXEDBASE, TedCurve);     // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_generator_table_numsp512t1(TableGen, TedCurve);            // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecc_full_keygen_numsp512t1(TableGen, PrivateKeyA, PublicKeyA, TedCurve);             // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Alice's public key PK_A = a*P
        goto cleanup;
    }    
    Status = ecc_full_keygen_numsp512t1(TableGen, PrivateKeyB, PublicKeyB, TedCurve);             // Get some value as Bob's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                             // and compute Bob's public key PK_B = b*P
        goto cleanup;
    }

    Status = ecdh_secret_agreement_numsp512t1(PrivateKeyA, PublicKeyB, SharedSecretA, TedCurve);  // Alice computes her shared key using Bob's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    Status = ecdh_secret_agreement_numsp512t1(PrivateKeyB, PublicKeyA, SharedSecretB, TedCurve);  // Bob computes his shared key using Alice's public key
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (fpcompare512(SharedSecretA, SharedSecretB) != 0 || fpcompare512(SharedSecretA + ML_WORDS512, SharedSecretA + ML_WORDS512) != 0)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDH(E) tests ........................................................................... PASSED");
    else { printf("  ECDH(E) tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SHARED_KEY; goto cleanup; }
    printf("\n");

    if (TableGen != NULL) {
        free(TableGen);
    }

    /***** Test for ECDSA *****/
    // Signing
    passed = TRUE;
    TableGen = ecc_allocate_precomp_numsp512t1(OP_FIXEDBASE, TedCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp512t1(TableGen, TedCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)512/8);
    random512_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    Status = ecc_full_keygen_numsp512t1(TableGen, PrivateKeyA, PublicKeyA, TedCurve);   // Get some value as Alice's secret key
    if (Status != ECCRYPTO_SUCCESS) {                                                   // Compute Alice's public key PK_A = a*P
        goto cleanup;
    }
    
    // Compute signature {R,S}
    Status = ecdsa_sign_numsp512t1(PrivateKeyA, TableGen, HashedMessage, 512/8, R, S, TedCurve); 
    if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
    }
        
    // Signature verification
    TableVer = ecc_allocate_precomp_numsp512t1(OP_DOUBLESCALAR, TedCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp512t1(TableVer, TedCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    Status = ecdsa_verify_numsp512t1(TableVer, PublicKeyA, HashedMessage, 512/8, R, S, &valid, TedCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == FALSE)
        passed = FALSE;
    
    // Produce invalid signature {R,S} by flipping one bit 
    R[0] = ((R[0] ^ (dig)1) & (dig)1) | (R[0] & ((dig)-1 << 1));
        
    // Signature verification
    Status = ecdsa_verify_numsp512t1(TableVer, PublicKeyA, HashedMessage, 512/8, R, S, &valid, TedCurve);        // Verify signature {R,S}
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == TRUE)
        passed = FALSE;
    if (passed == TRUE) printf("  ECDSA tests ............................................................................. PASSED");
    else { printf("  ECDSA tests ... FAILED"); printf("\n"); Status = ECCRYPTO_ERROR_SIGNATURE_VERIFICATION; goto cleanup; }
        printf("\n");

cleanup:
    ecc_curve_free(TedCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    fpzero512(PrivateKeyA);
    fpzero512(PrivateKeyB);
    fpzero512(SharedSecretA);
    fpzero512(SharedSecretB);

    return Status;
}

#endif


/****************** BENCHMARK TESTS *******************/
/******************************************************/

#ifdef ECCURVES_256

ECCRYPTO_STATUS crypto_run256_w(PCurveStaticData CurveData)
{ // Crypto benchmarking for curve numsp256d1
    dig256 PrivateKeyA, PrivateKeyB, SharedSecretB, R, S;
    point_numsp256d1 PublicKeyA, PublicKeyB, *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[256/8];
    PCurveStruct JacCurve = {0};
    unsigned long long cycles, cycles1, cycles2;
    unsigned int n;
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL valid = FALSE;

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif
        
    printf("\n\nBENCHMARKING \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp256d1, Weierstrass a=-3 curve over GF(2^256-189) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    // Benchmarking ECDH(E)
    TableGen = ecc_allocate_precomp_numsp256d1(OP_FIXEDBASE, JacCurve);            // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_generator_table_numsp256d1(TableGen, JacCurve);                   // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    random_mod_order(PrivateKeyA, JacCurve);                                       // Get some value as Alice's secret key
    Status = ecc_keygen_numsp256d1(PrivateKeyA, TableGen, PublicKeyA, JacCurve);   // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random_mod_order(PrivateKeyB, JacCurve);                                   // Get some value as Bob's secret key

        cycles1 = cpucycles();
        Status = ecc_keygen_numsp256d1(PrivateKeyB, TableGen, PublicKeyB, JacCurve);                  // Compute Bob's public key PK_B = b*P
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        Status = ecdh_secret_agreement_numsp256d1(PrivateKeyB, PublicKeyA, SharedSecretB, JacCurve);  // Bob computes his shared key using Alice's public key
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("ECDH(E)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    if (TableGen != NULL) {
        free(TableGen);
    }
    
    // Benchmarking ECDSA signature generation
    TableGen = ecc_allocate_precomp_numsp256d1(OP_FIXEDBASE, JacCurve);            // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp256d1(TableGen, JacCurve);                   // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)256/8);
    random256_test((dig*)HashedMessage, ffff);                                     // Get some random value to be used as the "hashed message" to be signed
    random_mod_order(PrivateKeyA, JacCurve);                                       // Get some value as Alice's secret key        
    Status = ecc_keygen_numsp256d1(PrivateKeyA, TableGen, PublicKeyA, JacCurve);   // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {                          
        cycles1 = cpucycles();  
        Status = ecdsa_sign_numsp256d1(PrivateKeyA, TableGen, HashedMessage, 256/8, R, S, JacCurve);    // Compute signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA signing", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    // Benchmarking ECDSA signature verification
    TableVer = ecc_allocate_precomp_numsp256d1(OP_DOUBLESCALAR, JacCurve);         // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp256d1(TableVer, JacCurve);              // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = ecdsa_verify_numsp256d1(TableVer, PublicKeyA, HashedMessage, 256/8, R, S, &valid, JacCurve);    // Verify signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA verification", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
cleanup:
    ecc_curve_free(JacCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    
    return Status;
}


ECCRYPTO_STATUS crypto_run256_te(PCurveStaticData CurveData)
{ // Crypto benchmarking for curve numsp256t1
    dig256 PrivateKeyA, PrivateKeyB, SharedSecretB, R, S;
    point_numsp256t1 PublicKeyA, PublicKeyB;
    point_extaff_precomp_numsp256t1 *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[256/8];
    PCurveStruct TedCurve = {0};
    unsigned long long cycles, cycles1, cycles2;
    unsigned int n;
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL valid = FALSE;

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif
        
    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp256t1, twisted Edwards a=1 curve over GF(2^256-189) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    // Benchmarking ECDH(E)
    TableGen = ecc_allocate_precomp_numsp256t1(OP_FIXEDBASE, TedCurve);            // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_generator_table_numsp256t1(TableGen, TedCurve);                   // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    random_mod_order(PrivateKeyA, TedCurve);                                       // Get some value as Alice's secret key
    Status = ecc_keygen_numsp256t1(PrivateKeyA, TableGen, PublicKeyA, TedCurve);   // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random_mod_order(PrivateKeyB, TedCurve);                                             // Get some value as Bob's secret key

        cycles1 = cpucycles();
        Status = ecc_keygen_numsp256t1(PrivateKeyB, TableGen, PublicKeyB, TedCurve);         // Compute Bob's public key PK_B = b*P
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        Status = ecdh_secret_agreement_numsp256t1(PrivateKeyB, PublicKeyA, SharedSecretB, TedCurve);  // Bob computes his shared key using Alice's public key
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("ECDH(E)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    if (TableGen != NULL) {
        free(TableGen);
    }
    
    // Benchmarking ECDSA signature generation
    TableGen = ecc_allocate_precomp_numsp256t1(OP_FIXEDBASE, TedCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp256t1(TableGen, TedCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)256/8);
    random256_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    random_mod_order(PrivateKeyA, TedCurve);                                            // Get some value as Alice's secret key        
    Status = ecc_keygen_numsp256t1(PrivateKeyA, TableGen, PublicKeyA, TedCurve);        // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {  
        cycles1 = cpucycles();  
        Status = ecdsa_sign_numsp256t1(PrivateKeyA, TableGen, HashedMessage, 256/8, R, S, TedCurve);    // Compute signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA signing", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    // Benchmarking ECDSA signature verification
    TableVer = ecc_allocate_precomp_numsp256t1(OP_DOUBLESCALAR, TedCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp256t1(TableVer, TedCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = ecdsa_verify_numsp256t1(TableVer, PublicKeyA, HashedMessage, 256/8, R, S, &valid, TedCurve);    // Verify signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA verification", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
cleanup:
    ecc_curve_free(TedCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    
    return Status;
}

#endif


#ifdef ECCURVES_384

ECCRYPTO_STATUS crypto_run384_w(PCurveStaticData CurveData)
{ // Crypto benchmarking for curve numsp384d1
    dig384 PrivateKeyA, PrivateKeyB, SharedSecretB, R, S;
    point_numsp384d1 PublicKeyA, PublicKeyB, *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[384/8];
    PCurveStruct JacCurve = {0};
    unsigned long long cycles, cycles1, cycles2;
    unsigned int n;
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL valid = FALSE;

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif
        
    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp384d1, Weierstrass a=-3 curve over GF(2^384-189) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    // Benchmarking ECDH(E)
    TableGen = ecc_allocate_precomp_numsp384d1(OP_FIXEDBASE, JacCurve);             // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_generator_table_numsp384d1(TableGen, JacCurve);                    // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    random_mod_order(PrivateKeyA, JacCurve);                                        // Get some value as Alice's secret key
    Status = ecc_keygen_numsp384d1(PrivateKeyA, TableGen, PublicKeyA, JacCurve);    // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random_mod_order(PrivateKeyB, JacCurve);                                              // Get some value as Bob's secret key

        cycles1 = cpucycles();
        Status = ecc_keygen_numsp384d1(PrivateKeyB, TableGen, PublicKeyB, JacCurve);          // Compute Bob's public key PK_B = b*P
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        Status = ecdh_secret_agreement_numsp384d1(PrivateKeyB, PublicKeyA, SharedSecretB, JacCurve);  // Bob computes his shared key using Alice's public key
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("ECDH(E)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    if (TableGen != NULL) {
        free(TableGen);
    }
    
    // Benchmarking ECDSA signature generation
    TableGen = ecc_allocate_precomp_numsp384d1(OP_FIXEDBASE, JacCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp384d1(TableGen, JacCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)384/8);
    random384_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    random_mod_order(PrivateKeyA, JacCurve);                                            // Get some value as Alice's secret key        
    Status = ecc_keygen_numsp384d1(PrivateKeyA, TableGen, PublicKeyA, JacCurve);        // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {  
        cycles1 = cpucycles();  
        Status = ecdsa_sign_numsp384d1(PrivateKeyA, TableGen, HashedMessage, 384/8, R, S, JacCurve);    // Compute signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA signing", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    // Benchmarking ECDSA signature verification
    TableVer = ecc_allocate_precomp_numsp384d1(OP_DOUBLESCALAR, JacCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp384d1(TableVer, JacCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = ecdsa_verify_numsp384d1(TableVer, PublicKeyA, HashedMessage, 384/8, R, S, &valid, JacCurve);    // Verify signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA verification", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
cleanup:
    ecc_curve_free(JacCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    
    return Status;
}


ECCRYPTO_STATUS crypto_run384_te(PCurveStaticData CurveData)
{ // Crypto benchmarking for curve numsp384t1
    dig384 PrivateKeyA, PrivateKeyB, SharedSecretB, R, S;
    point_numsp384t1 PublicKeyA, PublicKeyB;
    point_extaff_precomp_numsp384t1 *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[384/8];
    PCurveStruct TedCurve = {0};
    unsigned long long cycles, cycles1, cycles2;
    unsigned int n;
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL valid = FALSE;

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif
        
    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp384t1, twisted Edwards a=1 curve over GF(2^384-189) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    // Benchmarking ECDH(E)
    TableGen = ecc_allocate_precomp_numsp384t1(OP_FIXEDBASE, TedCurve);             // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_generator_table_numsp384t1(TableGen, TedCurve);                    // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    random_mod_order(PrivateKeyA, TedCurve);                                        // Get some value as Alice's secret key
    Status = ecc_keygen_numsp384t1(PrivateKeyA, TableGen, PublicKeyA, TedCurve);    // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random_mod_order(PrivateKeyB, TedCurve);                                              // Get some value as Bob's secret key

        cycles1 = cpucycles();
        Status = ecc_keygen_numsp384t1(PrivateKeyB, TableGen, PublicKeyB, TedCurve);          // Compute Bob's public key PK_B = b*P
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        Status = ecdh_secret_agreement_numsp384t1(PrivateKeyB, PublicKeyA, SharedSecretB, TedCurve);  // Bob computes his shared key using Alice's public key
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("ECDH(E)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    if (TableGen != NULL) {
        free(TableGen);
    }
    
    // Benchmarking ECDSA signature generation
    TableGen = ecc_allocate_precomp_numsp384t1(OP_FIXEDBASE, TedCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp384t1(TableGen, TedCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)384/8);
    random384_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    random_mod_order(PrivateKeyA, TedCurve);                                            // Get some value as Alice's secret key        
    Status = ecc_keygen_numsp384t1(PrivateKeyA, TableGen, PublicKeyA, TedCurve);        // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {                
        cycles1 = cpucycles();  
        Status = ecdsa_sign_numsp384t1(PrivateKeyA, TableGen, HashedMessage, 384/8, R, S, TedCurve);    // Compute signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA signing", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    // Benchmarking ECDSA signature verification
    TableVer = ecc_allocate_precomp_numsp384t1(OP_DOUBLESCALAR, TedCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp384t1(TableVer, TedCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = ecdsa_verify_numsp384t1(TableVer, PublicKeyA, HashedMessage, 384/8, R, S, &valid, TedCurve);    // Verify signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA verification", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
cleanup:
    ecc_curve_free(TedCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    
    return Status;
}

#endif


#ifdef ECCURVES_512

ECCRYPTO_STATUS crypto_run512_w(PCurveStaticData CurveData)
{ // Crypto benchmarking for curve numsp512d1
    dig512 PrivateKeyA, PrivateKeyB, SharedSecretB, R, S;
    point_numsp512d1 PublicKeyA, PublicKeyB, *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[512/8];
    PCurveStruct JacCurve = {0};
    unsigned long long cycles, cycles1, cycles2;
    unsigned int n;
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL valid = FALSE;

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif
        
    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp512d1, Weierstrass a=-3 curve over GF(2^512-189) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    // Benchmarking ECDH(E)
    TableGen = ecc_allocate_precomp_numsp512d1(OP_FIXEDBASE, JacCurve);             // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_generator_table_numsp512d1(TableGen, JacCurve);                    // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    random_mod_order(PrivateKeyA, JacCurve);                                        // Get some value as Alice's secret key
    Status = ecc_keygen_numsp512d1(PrivateKeyA, TableGen, PublicKeyA, JacCurve);    // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random_mod_order(PrivateKeyB, JacCurve);                                              // Get some value as Bob's secret key

        cycles1 = cpucycles();
        Status = ecc_keygen_numsp512d1(PrivateKeyB, TableGen, PublicKeyB, JacCurve);          // Compute Bob's public key PK_B = b*P
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        Status = ecdh_secret_agreement_numsp512d1(PrivateKeyB, PublicKeyA, SharedSecretB, JacCurve);  // Bob computes his shared key using Alice's public key
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("ECDH(E)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    if (TableGen != NULL) {
        free(TableGen);
    }
    
    // Benchmarking ECDSA signature generation
    TableGen = ecc_allocate_precomp_numsp512d1(OP_FIXEDBASE, JacCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp512d1(TableGen, JacCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)512/8);
    random512_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    random_mod_order(PrivateKeyA, JacCurve);                                            // Get some value as Alice's secret key        
    Status = ecc_keygen_numsp512d1(PrivateKeyA, TableGen, PublicKeyA, JacCurve);        // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {           
        cycles1 = cpucycles();  
        Status = ecdsa_sign_numsp512d1(PrivateKeyA, TableGen, HashedMessage, 512/8, R, S, JacCurve);    // Compute signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA signing", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    // Benchmarking ECDSA signature verification
    TableVer = ecc_allocate_precomp_numsp512d1(OP_DOUBLESCALAR, JacCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp512d1(TableVer, JacCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = ecdsa_verify_numsp512d1(TableVer, PublicKeyA, HashedMessage, 512/8, R, S, &valid, JacCurve);    // Verify signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA verification", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
cleanup:
    ecc_curve_free(JacCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    
    return Status;
}


ECCRYPTO_STATUS crypto_run512_te(PCurveStaticData CurveData)
{ // Crypto benchmarking for curve numsp512t1
    dig512 PrivateKeyA, PrivateKeyB, SharedSecretB, R, S;
    point_numsp512t1 PublicKeyA, PublicKeyB;
    point_extaff_precomp_numsp512t1 *TableGen = NULL, *TableVer = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    unsigned char HashedMessage[512/8];
    PCurveStruct TedCurve = {0};
    unsigned long long cycles, cycles1, cycles2;
    unsigned int n;
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL valid = FALSE;

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif
        
    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Crypto operations: numsp512t1, twisted Edwards a=1 curve over GF(2^512-189) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    // Benchmarking ECDH(E)
    TableGen = ecc_allocate_precomp_numsp512t1(OP_FIXEDBASE, TedCurve);             // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_generator_table_numsp512t1(TableGen, TedCurve);                    // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    random_mod_order(PrivateKeyA, TedCurve);                                        // Get some value as Alice's secret key
    Status = ecc_keygen_numsp512t1(PrivateKeyA, TableGen, PublicKeyA, TedCurve);    // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random_mod_order(PrivateKeyB, TedCurve);                                              // Get some value as Bob's secret key

        cycles1 = cpucycles();
        Status = ecc_keygen_numsp512t1(PrivateKeyB, TableGen, PublicKeyB, TedCurve);          // Compute Bob's public key PK_B = b*P
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        Status = ecdh_secret_agreement_numsp512t1(PrivateKeyB, PublicKeyA, SharedSecretB, TedCurve);  // Bob computes his shared key using Alice's public key
        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("ECDH(E)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    if (TableGen != NULL) {
        free(TableGen);
    }
    
    // Benchmarking ECDSA signature generation
    TableGen = ecc_allocate_precomp_numsp512t1(OP_FIXEDBASE, TedCurve);                 // Generator table allocation
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecc_generator_table_numsp512t1(TableGen, TedCurve);                        // Calculation of the precomputed table to be used during key generation
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    memset(ffff, (int)-1, (unsigned int)512/8);
    random512_test((dig*)HashedMessage, ffff);                                          // Get some random value to be used as the "hashed message" to be signed
    random_mod_order(PrivateKeyA, TedCurve);                                            // Get some value as Alice's secret key        
    Status = ecc_keygen_numsp512t1(PrivateKeyA, TableGen, PublicKeyA, TedCurve);        // Compute Alice's public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {  
        cycles1 = cpucycles();  
        Status = ecdsa_sign_numsp512t1(PrivateKeyA, TableGen, HashedMessage, 512/8, R, S, TedCurve);    // Compute signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA signing", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    // Benchmarking ECDSA signature verification
    TableVer = ecc_allocate_precomp_numsp512t1(OP_DOUBLESCALAR, TedCurve);              // Verification table allocation
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    
    Status = ecdsa_verification_table_numsp512t1(TableVer, TedCurve);                   // Calculation of the precomputed table to be used during signature verification
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        Status = ecdsa_verify_numsp512t1(TableVer, PublicKeyA, HashedMessage, 512/8, R, S, &valid, TedCurve);        // Verify signature {R,S}
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);

        if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
        }
    }
    bench_print("ECDSA verification", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
cleanup:
    ecc_curve_free(TedCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    
    return Status;
}

#endif


int main()
{
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;

    if (is_avx_supported() == FALSE) {
#ifdef AVX_SUPPORT
        printf("\n  SUPPORT FOR AVX CANNOT BE DETECTED BUT USER HAS ENABLED IT IN THE LIBRARY --- _AVX_ compiler flag must be disabled \n");
        return FALSE;
#endif
    } else {
#ifndef AVX_SUPPORT 
        printf("\n  SUPPORT FOR AVX HAS BEEN DETECTED BUT USER HAS NOT ENABLED IT IN THE LIBRARY --- enabling _AVX_ compiler flag is recommended \n");
#endif
    }

#ifdef ECCURVES_256
    Status = crypto_test256_w(&curve_numsp256d1);       // Test "numsp256d1", Weierstrass a=-3 curve with p = 2^256-189
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
    Status = crypto_test256_te(&curve_numsp256t1);      // Test "numsp256t1", twisted Edwards a=1 curve with p = 2^256-189
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif
#ifdef ECCURVES_384
    Status = crypto_test384_w(&curve_numsp384d1);       // Test "numsp384d1", Weierstrass a=-3 curve with p = 2^384-317
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
    Status = crypto_test384_te(&curve_numsp384t1);      // Test "numsp384t1", twisted Edwards a=1 curve with p = 2^384-317
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif
#ifdef ECCURVES_512
    Status = crypto_test512_w(&curve_numsp512d1);       // Test "numsp512d1", Weierstrass a=-3 curve with p = 2^512-569
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
    Status = crypto_test512_te(&curve_numsp512t1);       // Test "numsp512t1", twisted Edwards a=1 curve with p = 2^512-569
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif

#ifdef ECCURVES_256
    Status = crypto_run256_w(&curve_numsp256d1);        // Benchmark "numsp256d1", Weierstrass a=-3 curve with p = 2^256-189
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
    Status = crypto_run256_te(&curve_numsp256t1);       // Benchmark "numsp256t1", twisted Edwards a=1 curve with p = 2^256-189
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif
#ifdef ECCURVES_384
    Status = crypto_run384_w(&curve_numsp384d1);        // Benchmark "numsp384d1", Weierstrass a=-3 curve with p = 2^384-317
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
    Status = crypto_run384_te(&curve_numsp384t1);       // Benchmark "numsp384t1", twisted Edwards a=1 curve with p = 2^384-317
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif
#ifdef ECCURVES_512
    Status = crypto_run512_w(&curve_numsp512d1);        // Benchmark "numsp512d1", Weierstrass a=-3 curve with p = 2^512-569
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
    Status = crypto_run512_te(&curve_numsp512t1);       // Benchmark "numsp512t1", twisted Edwards a=1 curve with p = 2^512-569
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif
    
    return TRUE;
}