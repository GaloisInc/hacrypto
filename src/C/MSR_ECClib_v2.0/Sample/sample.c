/**************************************************************************
* Sample code using MSR ECClib
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
* Abstract: sample code
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
***************************************************************************/  

#include "../Tests/tests.h"
#include <stdio.h>
#if OS_TARGET == OS_WIN
    #include <windows.h>
#endif
#include <string.h>
#include <malloc.h>


static void to_print(dig *value, int number)
{ // From left-to-right, print the digits of a value of digit size "number" from most significant to least significant in hexadecimal format
    int i;
    for (i = (number - 1); i >= 0; i--) {
#if OS_TARGET == OS_WIN
        printf("0x%IX ", *(value + i));
#else
        printf("0x%jX ", (uintmax_t)*(value+i));
#endif
    }
    return;
}


#ifdef ECCURVES_256

ECCRYPTO_STATUS ecc_dh_numsp256d1(PCurveStaticData CurveData)
{ // Run ephemeral Diffie-Hellman (ECDHE) key exchange using curve numsp256d1 (without hashing)
    dig256 PrivateKeyA, PrivateKeyB, SharedSecretA, SharedSecretB;
    point_numsp256d1 PublicKeyA, PublicKeyB, *TableGen = NULL;
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    PCurveStruct JacCurve = {0};
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    
    // NOTE: users must provide their own RANDOM_BYTES_FUNCTION using a cryptographically strong random number generator.
    //       This function should have the same prototype of random_bytes_test() used for this sample code. 
    
    printf("\n\nTESTING OF EPHEMERAL DIFFIE-HELLMAN KEY EXCHANGE (W/O HASHING), CURVE \"numsp256d1\" \n"); 
    printf("--------------------------------------------------------------------------------------------------------\n\n"); 
    
    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
         return ECCRYPTO_ERROR_NO_MEMORY;
    }
    Status = ecc_curve_initialize(JacCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);        // Using the user-selected random_bytes function
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Generator table allocation
    TableGen = ecc_allocate_precomp_numsp256d1(OP_FIXEDBASE, JacCurve);                            // Allocating memory for table
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }

    // Offline calculation of the precomputed table to be used during key generation
    Status = ecc_generator_table_numsp256d1(TableGen, JacCurve);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Alice computes her key-pair
    Status = ecc_full_keygen_numsp256d1(TableGen, PrivateKeyA, PublicKeyA, JacCurve);              // Generate an ephemeral private key "a" and compute public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    printf(" Alice chooses a random integer \"a\" and computes her public key PK_A: \n");
    printf(" a = ");
    to_print(PrivateKeyA, ML_WORDS256);
    printf("\n");
    printf(" PK_A = a*P = (");
    to_print(PublicKeyA->x, ML_WORDS256);
    printf(", ");
    to_print(PublicKeyA->y, ML_WORDS256);
    printf(")\n\n");
    printf("    Alice sends PK_A to Bob. \n\n");
    
    // Bob computes his key-pair
    Status = ecc_full_keygen_numsp256d1(TableGen, PrivateKeyB, PublicKeyB, JacCurve);              // Generate a private key "b" and compute public key PK_B = b*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    printf(" Bob chooses a random integer \"b\" and computes her public key PK_B: \n");
    printf(" b = ");
    to_print(PrivateKeyB, ML_WORDS256);
    printf("\n");
    printf(" PK_B = b*P = (");
    to_print(PublicKeyB->x, ML_WORDS256);
    printf(", ");
    to_print(PublicKeyB->y, ML_WORDS256);
    printf(")\n\n");
    printf("    Bob sends PK_B to Alice. \n\n");
    
    // Alice computes her shared key using Bob's public key
    Status = ecdh_secret_agreement_numsp256d1(PrivateKeyA, PublicKeyB, SharedSecretA, JacCurve);   // SH_A = a*PK_B = a*(b*P)
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    printf(" Alice computes her shared key: \n");
    printf(" SHARED_A = a*PK_B = ");
    to_print(SharedSecretA, ML_WORDS256);
    printf("\n\n");

    // Bob computes his shared key using Alice's public key
    Status = ecdh_secret_agreement_numsp256d1(PrivateKeyB, PublicKeyA, SharedSecretB, JacCurve);   // SH_B = b*PK_A = b*(a*P)
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    printf(" Bob computes his shared key: \n");
    printf(" SHARED_B = b*PK_A = ");
    to_print(SharedSecretB, ML_WORDS256);
    printf("\n\n");

    if (fpcompare256(SharedSecretA, SharedSecretB) == 0) {
        Status = ECCRYPTO_SUCCESS;
    } else {
        Status = ECCRYPTO_ERROR_SHARED_KEY;
    }
    
cleanup:
    ecc_curve_free(JacCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    fpzero256(PrivateKeyA);
    fpzero256(PrivateKeyB);
    fpzero256(SharedSecretA);
    fpzero256(SharedSecretB);

    return Status;
 }


ECCRYPTO_STATUS ecc_dsa_numsp256d1(PCurveStaticData CurveData)
{ // Run ECDSA signature generation and verification using curve numsp256d1
    dig256 PrivateKeyA, R, S;
    point_numsp256d1 PublicKeyA, *TableGen = NULL, *TableVer = NULL;
    unsigned char HashedMessage[256/8];
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
    PCurveStruct JacCurve = {0};
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL valid = FALSE; 
    
    // NOTE: users must provide their own RANDOM_BYTES_FUNCTION using a cryptographically strong random number generator.
    //       This function should have the same prototype of random_bytes_test() used for this sample code. 

    printf("\n\nTESTING OF ECDSA SIGNATURE GENERATION AND VERIFICATION, CURVE \"numsp256d1\" \n"); 
    printf("--------------------------------------------------------------------------------------------------------\n\n"); 
    
    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
         return ECCRYPTO_ERROR_NO_MEMORY;
    }
    Status = ecc_curve_initialize(JacCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);        // Using the user-selected random_bytes function                                                                           
    if (Status != ECCRYPTO_SUCCESS) {                                                          
        goto cleanup;
    }

    // Generator table allocation
    TableGen = ecc_allocate_precomp_numsp256d1(OP_FIXEDBASE, JacCurve);               
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }

    // Offline calculation of the precomputed table to be used during key generation
    Status = ecc_generator_table_numsp256d1(TableGen, JacCurve);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }  
    
    memset(ffff, (int)-1, (unsigned int)256/8);
    random256_test((dig*)HashedMessage, ffff);                                                     // Get some random value to be used -only for testing- as the "hashed message" to be signed
        
    // Alice computes her key-pair
    Status = ecc_full_keygen_numsp256d1(TableGen, PrivateKeyA, PublicKeyA, JacCurve);              // Generate a private key "a" and compute public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    // Compute signature {R,S}
    Status = ecdsa_sign_numsp256d1(PrivateKeyA, TableGen, HashedMessage, 256/8, R, S, JacCurve); 
    if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
    }

    printf(" Alice chooses a random integer \"a\" and computes her public key PK_A: \n");
    printf(" a = ");
    to_print(PrivateKeyA, ML_WORDS256);
    printf("\n");
    printf(" PK_A = a*P = (");
    to_print(PublicKeyA->x, ML_WORDS256);
    printf(", ");
    to_print(PublicKeyA->y, ML_WORDS256);
    printf(")\n\n");
    printf(" The hashed message to be signed: \n");
    printf(" H(m) = ");
    to_print((dig*)HashedMessage, ML_WORDS256);
    printf("\n");
    printf(" The signature: \n");
    printf(" (R, S) = (");
    to_print(R, ML_WORDS256);
    printf(", ");
    to_print(S, ML_WORDS256);
    printf(")\n\n");
        
    // Verification table allocation
    TableVer = ecc_allocate_precomp_numsp256d1(OP_DOUBLESCALAR, JacCurve);              
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    

    // Offline calculation of the precomputed table to be used during signature verification
    Status = ecdsa_verification_table_numsp256d1(TableVer, JacCurve);                   
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Verify signature {R,S}
    Status = ecdsa_verify_numsp256d1(TableVer, PublicKeyA, HashedMessage, 256/8, R, S, &valid, JacCurve);        
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == TRUE) {
        Status = ECCRYPTO_SUCCESS;
    } else {
        Status = ECCRYPTO_ERROR_SIGNATURE_VERIFICATION;
    }
    
cleanup:
    ecc_curve_free(JacCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    ecczero_numsp256d1(PublicKeyA);
    fpzero256(PrivateKeyA);
    fpzero256((dig*)HashedMessage);
    fpzero256(R);
    fpzero256(S);

    return Status;
 }


 ECCRYPTO_STATUS ecc_dh_numsp256t1(PCurveStaticData CurveData)
 { // Run ephemeral Diffie-Hellman (ECDHE) key exchange using curve numsp256t1 (without hashing)
     dig256 PrivateKeyA, PrivateKeyB, SharedSecretA, SharedSecretB;
     point_numsp256t1 PublicKeyA, PublicKeyB;
     point_extaff_precomp_numsp256t1 *TableGen = NULL;
     MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance
     PCurveStruct TedCurve = {0};
     ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
    
    // NOTE: users must provide their own RANDOM_BYTES_FUNCTION using a cryptographically strong random number generator.
    //       This function should have the same prototype of random_bytes_test() used for this sample code. 

     printf("\n\nTESTING OF EPHEMERAL DIFFIE-HELLMAN KEY EXCHANGE (W/O HASHING), CURVE \"numsp256t1\" \n");
     printf("--------------------------------------------------------------------------------------------------------\n\n");

     // Curve initialization
     TedCurve = ecc_curve_allocate(CurveData);
     if (TedCurve == NULL) {
         return ECCRYPTO_ERROR_NO_MEMORY;
     }
     Status = ecc_curve_initialize(TedCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);        // Using the user-selected random_bytes function
     if (Status != ECCRYPTO_SUCCESS) {
         goto cleanup;
     }

     // Generator table allocation
     TableGen = ecc_allocate_precomp_numsp256t1(OP_FIXEDBASE, TedCurve);                            // Allocating memory for table
     if (TableGen == NULL) {
         Status = ECCRYPTO_ERROR_NO_MEMORY;
         goto cleanup;
     }

     // Offline calculation of the precomputed table to be used during key generation
     Status = ecc_generator_table_numsp256t1(TableGen, TedCurve);
     if (Status != ECCRYPTO_SUCCESS) {
         goto cleanup;
     }
    
     // Alice computes her key-pair
     Status = ecc_full_keygen_numsp256t1(TableGen, PrivateKeyA, PublicKeyA, TedCurve);              // Generate an ephemeral private key "a" and compute public key PK_A = a*P
     if (Status != ECCRYPTO_SUCCESS) {
         goto cleanup;
     }

     printf(" Alice chooses a random integer \"a\" and computes her public key PK_A: \n");
     printf(" a = ");
     to_print(PrivateKeyA, ML_WORDS256);
     printf("\n");
     printf(" PK_A = a*P = (");
     to_print(PublicKeyA->x, ML_WORDS256);
     printf(", ");
     to_print(PublicKeyA->y, ML_WORDS256);
     printf(")\n\n");
     printf("    Alice sends PK_A to Bob. \n\n");
    
     // Bob computes his key-pair
     Status = ecc_full_keygen_numsp256t1(TableGen, PrivateKeyB, PublicKeyB, TedCurve);              // Generate a private key "b" and compute public key PK_B = b*P
     if (Status != ECCRYPTO_SUCCESS) {
         goto cleanup;
     }

     printf(" Bob chooses a random integer \"b\" and computes her public key PK_B: \n");
     printf(" b = ");
     to_print(PrivateKeyB, ML_WORDS256);
     printf("\n");
     printf(" PK_B = b*P = (");
     to_print(PublicKeyB->x, ML_WORDS256);
     printf(", ");
     to_print(PublicKeyB->y, ML_WORDS256);
     printf(")\n\n");
     printf("    Bob sends PK_B to Alice. \n\n");

     // Alice computes her shared key using Bob's public key
     Status = ecdh_secret_agreement_numsp256t1(PrivateKeyA, PublicKeyB, SharedSecretA, TedCurve);  // SH_A = a*PK_B = a*(b*P)
     if (Status != ECCRYPTO_SUCCESS) {
         goto cleanup;
     }

     printf(" Alice computes her shared key: \n");
     printf(" SHARED_A = a*PK_B = ");
     to_print(SharedSecretA, ML_WORDS256);
     printf("\n\n");

     // Bob computes his shared key using Alice's public key
     Status = ecdh_secret_agreement_numsp256t1(PrivateKeyB, PublicKeyA, SharedSecretB, TedCurve);  // SH_B = b*PK_A = b*(a*P)
     if (Status != ECCRYPTO_SUCCESS) {
         goto cleanup;
     }

     printf(" Bob computes his shared key: \n");
     printf(" SHARED_B = b*PK_A = ");
     to_print(SharedSecretB, ML_WORDS256);
     printf("\n\n");

     if (fpcompare256(SharedSecretA, SharedSecretB) == 0) {
         Status = ECCRYPTO_SUCCESS;
     } else {
         Status = ECCRYPTO_ERROR_SHARED_KEY;
     }

 cleanup:
     ecc_curve_free(TedCurve);
     if (TableGen != NULL) {
         free(TableGen);
     }
     fpzero256(PrivateKeyA);
     fpzero256(PrivateKeyB);
     fpzero256(SharedSecretA);
     fpzero256(SharedSecretB);

     return Status;
}


ECCRYPTO_STATUS ecc_dsa_numsp256t1(PCurveStaticData CurveData)
{ // Run ECDSA signature generation and verification using curve numsp256t1
    dig256 PrivateKeyA, R, S;
    point_numsp256t1 PublicKeyA;
    point_extaff_precomp_numsp256t1 *TableGen = NULL, *TableVer = NULL;
    unsigned char HashedMessage[256/8];
    MemType memory_use = MEM_LARGE;    // Set max. memory use for highest performance;
    PCurveStruct TedCurve = {0};
    dig ffff[MAXBYTES_FIELD]; 
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    BOOL valid = FALSE;
    
    // NOTE: users must provide their own RANDOM_BYTES_FUNCTION using a cryptographically strong random number generator.
    //       This function should have the same prototype of random_bytes_test() used for this sample code. 
    
    printf("\n\nTESTING OF ECDSA SIGNATURE GENERATION AND VERIFICATION, CURVE \"numsp256t1\" \n"); 
    printf("--------------------------------------------------------------------------------------------------------\n\n"); 
    
    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
         return ECCRYPTO_ERROR_NO_MEMORY;
    }
    Status = ecc_curve_initialize(TedCurve, memory_use, &RANDOM_BYTES_FUNCTION, CurveData);        // Using the user-selected random function                                                                           
    if (Status != ECCRYPTO_SUCCESS) {                                                          
        goto cleanup;
    }

    // Generator table allocation
    TableGen = ecc_allocate_precomp_numsp256t1(OP_FIXEDBASE, TedCurve);               
    if (TableGen == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }

    // Offline calculation of the precomputed table to be used during key generation
    Status = ecc_generator_table_numsp256t1(TableGen, TedCurve);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    } 
    
    memset(ffff, (int)-1, (unsigned int)256/8);
    random256_test((dig*)HashedMessage, ffff);                                                     // Get some random value to be used -only for testing- as the "hashed message" to be signed
        
    // Alice computes her key-pair
    Status = ecc_full_keygen_numsp256t1(TableGen, PrivateKeyA, PublicKeyA, TedCurve);              // Generate a private key "a" and compute public key PK_A = a*P
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
        
    // Compute signature {R,S}
    Status = ecdsa_sign_numsp256t1(PrivateKeyA, TableGen, HashedMessage, 256/8, R, S, TedCurve); 
    if (Status != ECCRYPTO_SUCCESS) {
            goto cleanup;
    }

    printf(" Alice chooses a random integer \"a\" and computes her public key PK_A: \n");
    printf(" a = ");
    to_print(PrivateKeyA, ML_WORDS256);
    printf("\n");
    printf(" PK_A = a*P = (");
    to_print(PublicKeyA->x, ML_WORDS256);
    printf(", ");
    to_print(PublicKeyA->y, ML_WORDS256);
    printf(")\n\n");
    printf(" The hashed message to be signed: \n");
    printf(" H(m) = ");
    to_print((dig*)HashedMessage, ML_WORDS256);
    printf("\n");
    printf(" The signature: \n");
    printf(" (R, S) = (");
    to_print(R, ML_WORDS256);
    printf(", ");
    to_print(S, ML_WORDS256);
    printf(")\n\n");
        
    // Verification table allocation
    TableVer = ecc_allocate_precomp_numsp256t1(OP_DOUBLESCALAR, TedCurve);              
    if (TableVer == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }    

    // Offline calculation of the precomputed table to be used during signature verification
    Status = ecdsa_verification_table_numsp256t1(TableVer, TedCurve);                   
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Verify signature {R,S}
    Status = ecdsa_verify_numsp256t1(TableVer, PublicKeyA, HashedMessage, 256/8, R, S, &valid, TedCurve);        
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    if (valid == TRUE) {
        Status = ECCRYPTO_SUCCESS;
    } else {
        Status = ECCRYPTO_ERROR_SIGNATURE_VERIFICATION;
    }
    
cleanup:
    ecc_curve_free(TedCurve);
    if (TableGen != NULL) {
        free(TableGen);
    }
    if (TableVer != NULL) {
        free(TableVer);
    }
    ecczero_numsp256t1(PublicKeyA);
    fpzero256(PrivateKeyA);
    fpzero256((dig*)HashedMessage);
    fpzero256(R);
    fpzero256(S);

    return Status;
 }

#endif


int main()
{
    const char* message = NULL;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

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

     Status = ecc_dh_numsp256d1(&curve_numsp256d1);       // Diffie-Hellman key exchange test using "numsp256d1"
     if (Status == ECCRYPTO_ERROR_SHARED_KEY) {
         printf("    Shared keys do not match (FAILED)\n\n");
         return FALSE;
     } else if (Status != ECCRYPTO_SUCCESS) {
         message = ecc_get_error_message(Status);
         printf("    Error detected: %s \n\n", message);
         return FALSE;
     } else {
         printf("    Shared keys matched (SUCCESS)\n\n");
     }
     
     Status = ecc_dsa_numsp256d1(&curve_numsp256d1);       // ECDSA signature test using "numsp256d1"
     if (Status == ECCRYPTO_ERROR_SIGNATURE_VERIFICATION) {
         printf("    Signature rejected (FAILED)\n\n");
         return FALSE;
     } else if (Status != ECCRYPTO_SUCCESS) {
         message = ecc_get_error_message(Status);
         printf("    Error detected: %s \n\n", message);
         return FALSE;
     } else {
         printf("    Signature accepted (SUCCESS)\n\n");
     }
     
     Status = ecc_dh_numsp256t1(&curve_numsp256t1);       // Diffie-Hellman key exchange test using "numsp256t1"
     if (Status == ECCRYPTO_ERROR_SHARED_KEY) {
         printf("    Shared keys do not match (FAILED)\n\n");
         return FALSE;
     } else if (Status != ECCRYPTO_SUCCESS) {
         message = ecc_get_error_message(Status);
         printf("    Error detected: %s \n\n", message);
         return FALSE;
     } else {
         printf("    Shared keys matched (SUCCESS)\n\n");
     }
     
     Status = ecc_dsa_numsp256t1(&curve_numsp256t1);       // ECDSA signature test using "numsp256t1"
     if (Status == ECCRYPTO_ERROR_SIGNATURE_VERIFICATION) {
         printf("    Signature rejected (FAILED)\n\n");
         return FALSE;
     } else if (Status != ECCRYPTO_SUCCESS) {
         message = ecc_get_error_message(Status);
         printf("    Error detected: %s \n\n", message);
         return FALSE;
     } else {
         printf("    Signature accepted (SUCCESS)\n\n");
     }
     
#else

     message;    // Unreferenced parameters
     Status;
     printf("\n    This sample code is currently supported for curves over 256-bit fields only (i.e., curves numsp256d1 and numsp256t1). \n");
     printf("\n    CHECK YOUR SELECTION OF CURVES. \n\n");

#endif

     return TRUE;
 }