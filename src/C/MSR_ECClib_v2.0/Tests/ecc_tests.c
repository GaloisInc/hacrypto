/**************************************************************************
* Suite for benchmarking/testing curve operations for MSR ECClib
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
* Abstract: benchmarking/testing curve operations
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
#include <malloc.h>


#ifdef ECCURVES_256

ECCRYPTO_STATUS ecc_test256_w(PCurveStaticData CurveData)
{ // Tests for curve numsp256d1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    dig n;
    BOOL passed = TRUE;
    point_jac_numsp256d1 P, R, complete_table[4] = {0};
    dig k[ML_WORDS256], kk[ML_WORDS256];
    point_numsp256d1 A, AA, B, BB, *T_fixed = NULL;
    PCurveStruct JacCurve = {0};
    
    printf("\n\nTESTING \n"); 
    printf("--------------------------------------------------------------------------------------------------------\n\n"); 
    printf("Curve arithmetic: numsp256d1, Weierstrass a=-3 curve over GF(2^256-189) \n\n"); 

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Point doubling (Weierstrass a=-3)
    passed = TRUE;
    eccset_numsp256d1(A, JacCurve); 
    eccconvert_aff_to_jac_numsp256d1(A, P);

    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        eccdouble_jac_numsp256d1(P, JacCurve);          // 2*P
        eccdouble_waff_256(A, JacCurve);                // 2*A
    }
    eccnorm_numsp256d1(P, AA, JacCurve);

    if (fpcompare256(A->x,AA->x)!=0 || fpcompare256(A->y,AA->y)!=0) passed=FALSE;
    if (passed==TRUE) printf("  Point doubling tests .................................................................... PASSED");
    else { printf("  Point doubling tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // "Complete" point addition (Weierstrass a=-3)
    passed = TRUE;
    eccset_numsp256d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp256d1(A, P);
    ecccopy_jac_numsp256d1(P, R); 
    eccdouble_jac_numsp256d1(P, JacCurve);              // P = 2P 
    eccset_numsp256d1(AA, JacCurve);
    eccdouble_waff_256(AA, JacCurve);                   // AA = 2A

    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        eccadd_jac_numsp256d1(R, P, JacCurve);          // P = P+Q
        eccadd_waff_256(A, AA, JacCurve);               // AA = AA+A
    }    
    eccnorm_numsp256d1(P, A, JacCurve);    
    if (fpcompare256(A->x,AA->x)!=0 || fpcompare256(A->y,AA->y)!=0) passed=FALSE;
    
    eccset_numsp256d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp256d1(A, P);
    ecccopy_jac_numsp256d1(P, R);
    fpneg256(JacCurve->prime, R->Y); 
    eccadd_jac_numsp256d1(R, P, JacCurve);                  // P+(-P)
    if (ecc_is_infinity_jac_numsp256d1(P, JacCurve) == FALSE) passed=FALSE;
    
    eccset_numsp256d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp256d1(A, R);
    ecczero_jac_numsp256d1(P); P->Y[0] = 1;
    eccadd_jac_numsp256d1(R, P, JacCurve);                  // 0+R   
    eccnorm_numsp256d1(P, AA, JacCurve); 
    if (fpcompare256(A->x,AA->x)!=0 || fpcompare256(A->y,AA->y)!=0) passed=FALSE;
    
    eccset_numsp256d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp256d1(A, P);
    ecczero_jac_numsp256d1(R); R->Y[0] = 1;
    eccadd_jac_numsp256d1(R, P, JacCurve);                  // P+0   
    eccnorm_numsp256d1(P, AA, JacCurve); 
    if (fpcompare256(A->x,AA->x)!=0 || fpcompare256(A->y,AA->y)!=0) passed=FALSE;
    
    eccset_numsp256d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp256d1(A, P);
    ecccopy_jac_numsp256d1(P, R);
    eccadd_jac_numsp256d1(R, P, JacCurve);                  // P+P   
    eccnorm_numsp256d1(P, AA, JacCurve); 
    eccdouble_jac_numsp256d1(R, JacCurve);                  // 2P  
    eccnorm_numsp256d1(R, A, JacCurve);
    if (fpcompare256(A->x,AA->x)!=0 || fpcompare256(A->y,AA->y)!=0) passed=FALSE;    
    
    // Case of mixed addition    
    complete_table[0]->Y[0] = 1;                            // Initialize complete_table[0] with the point at infinity (0:1:0)   
    eccset_numsp256d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp256d1(A, complete_table[1]); // Initialize complete_table[1] with A = (X_A:Y_A:1)
    eccconvert_aff_to_jac_numsp256d1(A, P);
    fpneg256(JacCurve->prime, P->Y); 
    eccadd_mixed_jac_numsp256d1(A, P, complete_table, JacCurve);  // P+(-P)
    if (ecc_is_infinity_jac_numsp256d1(P, JacCurve) == FALSE) passed=FALSE;
      
    eccset_numsp256d1(A, JacCurve);
    ecczero_jac_numsp256d1(P); P->Y[0] = 1;
    eccadd_mixed_jac_numsp256d1(A, P, complete_table, JacCurve);  // 0+R   
    eccnorm_numsp256d1(P, AA, JacCurve); 
    if (fpcompare256(A->x,AA->x)!=0 || fpcompare256(A->y,AA->y)!=0) passed=FALSE;
    
    eccset_numsp256d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp256d1(A, P);
    ecccopy_jac_numsp256d1(P, R);
    eccadd_mixed_jac_numsp256d1(A, P, complete_table, JacCurve);  // P+P   
    eccnorm_numsp256d1(P, AA, JacCurve); 
    eccdouble_jac_numsp256d1(R, JacCurve);                        // 2P  
    eccnorm_numsp256d1(R, A, JacCurve);
    if (fpcompare256(A->x,AA->x)!=0 || fpcompare256(A->y,AA->y)!=0) passed=FALSE;    
    
    eccset_numsp256d1(A, JacCurve);
    eccset_numsp256d1(AA, JacCurve);
    eccconvert_aff_to_jac_numsp256d1(A, P);
    eccdouble_jac_numsp256d1(P, JacCurve);                        
    eccadd_mixed_jac_numsp256d1(A, P, complete_table, JacCurve);  // P+2P 
    eccdouble_waff_256(AA, JacCurve);                         
    eccadd_waff_256(A, AA, JacCurve);                             // P+2P
    eccnorm_numsp256d1(P, A, JacCurve);
    if (fpcompare256(A->x,AA->x)!=0 || fpcompare256(A->y,AA->y)!=0) passed=FALSE;    
    
    if (passed==TRUE) printf("  (Complete) point addition tests ......................................................... PASSED");
    else { printf("  (Complete) point addition tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Variable-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp256d1(A, JacCurve); 
    
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(k, JacCurve->order); 

        ecc_mul_waff_256(A, k, AA, JacCurve);    
        Status = ecc_scalar_mul_numsp256d1(A, k, B, JacCurve);
        
        if (fpcompare256(AA->x,B->x)!=0 || fpcompare256(AA->y,B->y)!=0) { passed=FALSE; break; }
    }    

    if (passed==TRUE) printf("  Variable-base scalar multiplication tests ............................................... PASSED");
    else { printf("  Variable-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
        
    // Fixed-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp256d1(A, JacCurve); 
    
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(k, JacCurve->order); 
        ecc_mul_waff_256(A, k, AA, JacCurve);  

        T_fixed = ecc_allocate_precomp_numsp256d1(OP_FIXEDBASE, JacCurve);
        ecc_precomp_fixed_numsp256d1(A, T_fixed, JacCurve);
        Status = ecc_scalar_mul_fixed_numsp256d1(T_fixed, k, B, JacCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }
        
        if (fpcompare256(AA->x,B->x)!=0 || fpcompare256(AA->y,B->y)!=0) { passed=FALSE; break; }
    }    

    if (passed==TRUE) printf("  Fixed-base scalar multiplication tests .................................................. PASSED");
    else { printf("  Fixed-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Double-scalar multiplication (Weierstrass a=-3)
    passed = TRUE;
    eccset_numsp256d1(A, JacCurve); 
    random256_test(k, JacCurve->order); 
    ecc_mul_waff_256(A, k, B, JacCurve);    // Base points are A and B
    
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(k, JacCurve->order); 
        random256_test(kk, JacCurve->order); 

        ecc_mul_waff_256(A, k, AA, JacCurve);    
        ecc_mul_waff_256(B, kk, BB, JacCurve);
        eccadd_waff_256(BB, AA, JacCurve);

        T_fixed = ecc_allocate_precomp_numsp256d1(OP_DOUBLESCALAR, JacCurve);
        ecc_precomp_dblmul_numsp256d1(A, T_fixed, JacCurve);
        Status = ecc_double_scalar_mul_numsp256d1(T_fixed, k, B, kk, BB, JacCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }
        
        if (fpcompare256(AA->x,BB->x)!=0 || fpcompare256(AA->y,BB->y)!=0) { passed=FALSE; break; }
    }      

    if (passed==TRUE) printf("  Double-scalar multiplication tests ...................................................... PASSED");
    else { printf("  Double-scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

cleanup:
    if (passed == FALSE) {
        Status = ECCRYPTO_ERROR_DURING_TEST;
    }
    ecc_curve_free(JacCurve);
    
    return Status;
}


ECCRYPTO_STATUS ecc_test256_te(PCurveStaticData CurveData)
{ // Tests for curve numsp256t1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    dig n;
    BOOL passed = TRUE;
    point_numsp256t1 A, AA, U, V;
    point_extproj_numsp256t1 P, R;
    point_numsp256d1 PP, QQ, RR, UU, VV;
    dig256 a, d, t1, t2, t3;
    dig k[ML_WORDS256], kk[ML_WORDS256];
    point_extaff_precomp_numsp256t1 *T_fixed = NULL;
    PCurveStruct WeierstrassCurve = {0};
    PCurveStruct TedCurve = {0};

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp256t1, twisted Edwards a=1 curve over GF(2^256-189) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Weierstrass curve allocation
    WeierstrassCurve = ecc_curve_allocate(CurveData);
    if (WeierstrassCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }

    // Set Weierstrass curve isomorphic to TedCurve
    fpcopy256(TedCurve->parameter1, a);
    fpcopy256(TedCurve->parameter2, d);
    fpzero256(t3); t3[0] = 14;
    fpmul256(t3, d, t1);   
    fpmul256(t1, a, t1);                               // t1 = 14ad
    fpsqr256(d, t2);                                   // t2 = d^2
    fpadd256(t1, t2, t2);                              // t2 = 14ad+d^2
    fpsqr256(a, t3);                                   // t3 = a^2    
    fpadd256(t2, t3, t2);                              // t2 = a^2+14ad+d^2
    fpneg256(TedCurve->prime, t2);                     // t2 = -(a^2+14ad+d^2)
    fpzero256(t1); t1[0] = 48;
    fpinv256(t1);                                      // t1 = 1/48
    fpmul256(t1, t2, WeierstrassCurve->parameter1);    // aW = -(a^2+14ad+d^2)/48
    WeierstrassCurve->nbits = TedCurve->nbits;
    WeierstrassCurve->rbits = TedCurve->rbits;
    WeierstrassCurve->pbits = TedCurve->pbits;

    // Point doubling (twisted Edwards a=1)
    passed = TRUE;
    eccset_numsp256t1(A, TedCurve); 
    eccconvert_aff_to_extproj_numsp256t1(A, P);
    ecc_numsp256t1_to_weierstrass(A, PP, TedCurve);

    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        eccdouble_extproj_numsp256t1(P, TedCurve);         // 2*P
        eccdouble_waff_256(PP, WeierstrassCurve);          // 2*PP
    }
    eccnorm_numsp256t1(P, A, TedCurve);
    ecc_weierstrass_to_numsp256t1(PP, AA, TedCurve);

    if (fpcompare256(A->x,AA->x)!=0 || fpcompare256(A->y,AA->y)!=0) passed=FALSE;
    if (passed==TRUE) printf("  Point doubling tests .................................................................... PASSED");
    else { printf("  Point doubling tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Point addition (twisted Edwards a=1)
    passed = TRUE;        
    eccset_numsp256t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp256t1(A, P);
    ecccopy_extproj_numsp256t1(P, R);
    eccdouble_extproj_numsp256t1(P, TedCurve);             // P = 2P    
        
    eccset_numsp256t1(A, TedCurve); 
    ecc_numsp256t1_to_weierstrass(A, QQ, TedCurve);
    ecc_numsp256t1_to_weierstrass(A, PP, TedCurve);
    eccdouble_waff_256(PP, WeierstrassCurve);              // PP = 2P

    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        eccadd_extproj_numsp256t1(R, P, TedCurve);         // P = P+Q
        eccadd_waff_256(QQ, PP, WeierstrassCurve);         // PP = PP+QQ
    }    
    eccnorm_numsp256t1(P, A, TedCurve);
    ecc_weierstrass_to_numsp256t1(PP, AA, TedCurve);
    if (passed==TRUE) printf("  Point addition tests .................................................................... PASSED");
    else { printf("  Point addition tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Variable-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp256t1(A, TedCurve); 
    ecc_numsp256t1_to_weierstrass(A, PP, TedCurve);
    eccdouble_waff_256(PP, WeierstrassCurve);
    eccdouble_waff_256(PP, WeierstrassCurve);
        
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(k, TedCurve->order); 
        
        ecc_mul_waff_256(PP, k, RR, WeierstrassCurve);    
        Status = ecc_scalar_mul_numsp256t1(A, k, AA, TedCurve);
        ecc_numsp256t1_to_weierstrass(AA, QQ, TedCurve);
        
        if (fpcompare256(QQ->x,RR->x)!=0 || fpcompare256(QQ->y,RR->y)!=0) { passed=FALSE; break; }
    }    

    if (passed==TRUE) printf("  Variable-base scalar multiplication tests ............................................... PASSED");
    else { printf("  Variable-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fixed-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp256t1(A, TedCurve); 
    ecc_numsp256t1_to_weierstrass(A, PP, TedCurve);
    eccdouble_waff_256(PP, WeierstrassCurve);
    eccdouble_waff_256(PP, WeierstrassCurve);
    
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(k, TedCurve->order); 
        ecc_mul_waff_256(PP, k, RR, WeierstrassCurve);   

        T_fixed = ecc_allocate_precomp_numsp256t1(OP_FIXEDBASE, TedCurve);
        ecc_precomp_fixed_numsp256t1(A, T_fixed, TedCurve);
        Status = ecc_scalar_mul_fixed_numsp256t1(T_fixed, k, AA, TedCurve);
        ecc_numsp256t1_to_weierstrass(AA, QQ, TedCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }
        
        if (fpcompare256(QQ->x,RR->x)!=0 || fpcompare256(QQ->y,RR->y)!=0) { passed=FALSE; break; }
    }    

    if (passed==TRUE) printf("  Fixed-base scalar multiplication tests .................................................. PASSED");
    else { printf("  Fixed-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Double-scalar multiplication (twisted Edwards a=1)
    passed = TRUE;
    eccset_numsp256t1(A, TedCurve); 
    ecc_numsp256t1_to_weierstrass(A, PP, TedCurve);
    random256_test(k, TedCurve->order); 
    ecc_mul_waff_256(PP, k, RR, WeierstrassCurve);    
    ecc_weierstrass_to_numsp256t1(RR, AA, TedCurve);       // Base points are (A, AA) in twisted Edwards, (PP, RR) in Weierstrass
    
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(k, TedCurve->order); 
        random256_test(kk, TedCurve->order); 

        ecc_mul_waff_256(PP, k, UU, WeierstrassCurve);    
        ecc_mul_waff_256(RR, kk, VV, WeierstrassCurve);
        eccadd_waff_256(VV, UU, WeierstrassCurve);  
        ecc_weierstrass_to_numsp256t1(UU, U, TedCurve); 

        T_fixed = ecc_allocate_precomp_numsp256t1(OP_DOUBLESCALAR, TedCurve);
        ecc_precomp_dblmul_numsp256t1(A, T_fixed, TedCurve);
        Status = ecc_double_scalar_mul_numsp256t1(T_fixed, k, AA, kk, V, TedCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }
        
        if (fpcompare256(U->x,V->x)!=0 || fpcompare256(U->y,V->y)!=0) { passed=FALSE; break; }
    }      

    if (passed==TRUE) printf("  Double-scalar multiplication tests ...................................................... PASSED");
    else { printf("  Double-scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

cleanup:
    if (passed == FALSE) {
        Status = ECCRYPTO_ERROR_DURING_TEST;
    }
    ecc_curve_free(TedCurve);
    ecc_curve_free(WeierstrassCurve);

    return Status;
}

#endif


#ifdef ECCURVES_384

ECCRYPTO_STATUS ecc_test384_w(PCurveStaticData CurveData)
{ // Tests for curve numsp384d1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    dig n;
    BOOL passed = TRUE;
    point_jac_numsp384d1 P, R, complete_table[4] = {0};
    dig k[ML_WORDS384], kk[ML_WORDS384];
    point_numsp384d1 A, AA, B, BB, *T_fixed = NULL;
    PCurveStruct JacCurve = {0};

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp384d1, Weierstrass a=-3 curve over GF(2^384-317) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Point doubling (Weierstrass a=-3)
    passed = TRUE;
    eccset_numsp384d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, P);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        eccdouble_jac_numsp384d1(P, JacCurve);          // 2*P
        eccdouble_waff_384(A, JacCurve);                // 2*A
    }
    eccnorm_numsp384d1(P, AA, JacCurve);

    if (fpcompare384(A->x, AA->x) != 0 || fpcompare384(A->y, AA->y) != 0) passed = FALSE;
    if (passed == TRUE) printf("  Point doubling tests .................................................................... PASSED");
    else { printf("  Point doubling tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // "Complete" point addition (Weierstrass a=-3)
    passed = TRUE;
    eccset_numsp384d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, P);
    ecccopy_jac_numsp384d1(P, R);
    eccdouble_jac_numsp384d1(P, JacCurve);                  // P = 2P 
    eccset_numsp384d1(AA, JacCurve);
    eccdouble_waff_384(AA, JacCurve);                       // AA = 2A
    
    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        eccadd_jac_numsp384d1(R, P, JacCurve);              // P = P+Q
        eccadd_waff_384(A, AA, JacCurve);                   // AA = AA+A
    }
    eccnorm_numsp384d1(P, A, JacCurve);
    if (fpcompare384(A->x, AA->x) != 0 || fpcompare384(A->y, AA->y) != 0) passed = FALSE;
    
    eccset_numsp384d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, P);
    ecccopy_jac_numsp384d1(P, R);
    fpneg384(JacCurve->prime, R->Y); 
    eccadd_jac_numsp384d1(R, P, JacCurve);                  // P+(-P)
    if (ecc_is_infinity_jac_numsp384d1(P, JacCurve) == FALSE) passed=FALSE;
    
    eccset_numsp384d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, R);
    ecczero_jac_numsp384d1(P); P->Y[0] = 1;
    eccadd_jac_numsp384d1(R, P, JacCurve);                  // 0+R   
    eccnorm_numsp384d1(P, AA, JacCurve); 
    if (fpcompare384(A->x,AA->x)!=0 || fpcompare384(A->y,AA->y)!=0) passed=FALSE;
    
    eccset_numsp384d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, P);
    ecczero_jac_numsp384d1(R); R->Y[0] = 1;
    eccadd_jac_numsp384d1(R, P, JacCurve);                  // P+0   
    eccnorm_numsp384d1(P, AA, JacCurve); 
    if (fpcompare384(A->x,AA->x)!=0 || fpcompare384(A->y,AA->y)!=0) passed=FALSE;
    
    eccset_numsp384d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, P);
    ecccopy_jac_numsp384d1(P, R);
    eccadd_jac_numsp384d1(R, P, JacCurve);                  // P+P   
    eccnorm_numsp384d1(P, AA, JacCurve); 
    eccdouble_jac_numsp384d1(R, JacCurve);                  // 2P  
    eccnorm_numsp384d1(R, A, JacCurve);
    if (fpcompare384(A->x,AA->x)!=0 || fpcompare384(A->y,AA->y)!=0) passed=FALSE;    
    
    // Case of mixed addition    
    complete_table[0]->Y[0] = 1;                            // Initialize complete_table[0] with the point at infinity (0:1:0)   
    eccset_numsp384d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, complete_table[1]); // Initialize complete_table[1] with A = (X_A:Y_A:1)
    eccconvert_aff_to_jac_numsp384d1(A, P);
    fpneg384(JacCurve->prime, P->Y); 
    eccadd_mixed_jac_numsp384d1(A, P, complete_table, JacCurve);  // P+(-P)
    if (ecc_is_infinity_jac_numsp384d1(P, JacCurve) == FALSE) passed=FALSE;
      
    eccset_numsp384d1(A, JacCurve);
    ecczero_jac_numsp384d1(P); P->Y[0] = 1;
    eccadd_mixed_jac_numsp384d1(A, P, complete_table, JacCurve);  // 0+R   
    eccnorm_numsp384d1(P, AA, JacCurve); 
    if (fpcompare384(A->x,AA->x)!=0 || fpcompare384(A->y,AA->y)!=0) passed=FALSE;
    
    eccset_numsp384d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, P);
    ecccopy_jac_numsp384d1(P, R);
    eccadd_mixed_jac_numsp384d1(A, P, complete_table, JacCurve);  // P+P   
    eccnorm_numsp384d1(P, AA, JacCurve); 
    eccdouble_jac_numsp384d1(R, JacCurve);                        // 2P  
    eccnorm_numsp384d1(R, A, JacCurve);
    if (fpcompare384(A->x,AA->x)!=0 || fpcompare384(A->y,AA->y)!=0) passed=FALSE;    
    
    eccset_numsp384d1(A, JacCurve);
    eccset_numsp384d1(AA, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, P);
    eccdouble_jac_numsp384d1(P, JacCurve);                        
    eccadd_mixed_jac_numsp384d1(A, P, complete_table, JacCurve);  // P+2P 
    eccdouble_waff_384(AA, JacCurve);                         
    eccadd_waff_384(A, AA, JacCurve);                             // P+2P
    eccnorm_numsp384d1(P, A, JacCurve);
    if (fpcompare384(A->x,AA->x)!=0 || fpcompare384(A->y,AA->y)!=0) passed=FALSE;    

    if (passed == TRUE) printf("  (Complete) point addition tests ......................................................... PASSED");
    else { printf("  (Complete) point addition tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Variable-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp384d1(A, JacCurve);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(k, JacCurve->order);

        ecc_mul_waff_384(A, k, AA, JacCurve);
        Status = ecc_scalar_mul_numsp384d1(A, k, B, JacCurve);

        if (fpcompare384(AA->x, B->x) != 0 || fpcompare384(AA->y, B->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Variable-base scalar multiplication tests ............................................... PASSED");
    else { printf("  Variable-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fixed-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp384d1(A, JacCurve);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(k, JacCurve->order);
        ecc_mul_waff_384(A, k, AA, JacCurve);

        T_fixed = ecc_allocate_precomp_numsp384d1(OP_FIXEDBASE, JacCurve);
        ecc_precomp_fixed_numsp384d1(A, T_fixed, JacCurve);
        Status = ecc_scalar_mul_fixed_numsp384d1(T_fixed, k, B, JacCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }

        if (fpcompare384(AA->x, B->x) != 0 || fpcompare384(AA->y, B->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Fixed-base scalar multiplication tests .................................................. PASSED");
    else { printf("  Fixed-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Double-scalar multiplication (Weierstrass a=-3)
    passed = TRUE;
    eccset_numsp384d1(A, JacCurve);
    random384_test(k, JacCurve->order);
    ecc_mul_waff_384(A, k, B, JacCurve);    // Base points are A and B

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(k, JacCurve->order);
        random384_test(kk, JacCurve->order);

        ecc_mul_waff_384(A, k, AA, JacCurve);
        ecc_mul_waff_384(B, kk, BB, JacCurve);
        eccadd_waff_384(BB, AA, JacCurve);

        T_fixed = ecc_allocate_precomp_numsp384d1(OP_DOUBLESCALAR, JacCurve);
        ecc_precomp_dblmul_numsp384d1(A, T_fixed, JacCurve);
        Status = ecc_double_scalar_mul_numsp384d1(T_fixed, k, B, kk, BB, JacCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }

        if (fpcompare384(AA->x, BB->x) != 0 || fpcompare384(AA->y, BB->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Double-scalar multiplication tests ...................................................... PASSED");
    else { printf("  Double-scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

cleanup:
    if (passed == FALSE) {
        Status = ECCRYPTO_ERROR_DURING_TEST;
    }
    ecc_curve_free(JacCurve);

    return Status;
}


ECCRYPTO_STATUS ecc_test384_te(PCurveStaticData CurveData)
{ // Tests for curve numsp384t1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    dig n;
    BOOL passed = TRUE;
    point_numsp384t1 A, AA, U, V;
    point_extproj_numsp384t1 P, R;
    point_numsp384d1 PP, QQ, RR, UU, VV;
    dig384 a, d, t1, t2, t3;
    dig k[ML_WORDS384], kk[ML_WORDS384];
    point_extaff_precomp_numsp384t1 *T_fixed = NULL;
    PCurveStruct WeierstrassCurve = {0};
    PCurveStruct TedCurve = {0};

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp384t1, twisted Edwards a=1 curve over GF(2^384-317) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Weierstrass curve allocation
    WeierstrassCurve = ecc_curve_allocate(CurveData);
    if (WeierstrassCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }

    // Set Weierstrass curve isomorphic to TedCurve
    fpcopy384(TedCurve->parameter1, a);
    fpcopy384(TedCurve->parameter2, d);
    fpzero384(t3); t3[0] = 14;
    fpmul384(t3, d, t1);   
    fpmul384(t1, a, t1);                               // t1 = 14ad
    fpsqr384(d, t2);                                   // t2 = d^2
    fpadd384(t1, t2, t2);                              // t2 = 14ad+d^2
    fpsqr384(a, t3);                                   // t3 = a^2    
    fpadd384(t2, t3, t2);                              // t2 = a^2+14ad+d^2
    fpneg384(TedCurve->prime, t2);                     // t2 = -(a^2+14ad+d^2)
    fpzero384(t1); t1[0] = 48;
    fpinv384(t1);                                      // t1 = 1/48
    fpmul384(t1, t2, WeierstrassCurve->parameter1);    // aW = -(a^2+14ad+d^2)/48
    WeierstrassCurve->nbits = TedCurve->nbits;
    WeierstrassCurve->rbits = TedCurve->rbits;
    WeierstrassCurve->pbits = TedCurve->pbits;

    // Point doubling (twisted Edwards a=1)
    passed = TRUE;
    eccset_numsp384t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp384t1(A, P);
    ecc_numsp384t1_to_weierstrass(A, PP, TedCurve);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        eccdouble_extproj_numsp384t1(P, TedCurve);         // 2*P
        eccdouble_waff_384(PP, WeierstrassCurve);          // 2*PP
    }
    eccnorm_numsp384t1(P, A, TedCurve);
    ecc_weierstrass_to_numsp384t1(PP, AA, TedCurve);

    if (fpcompare384(A->x, AA->x) != 0 || fpcompare384(A->y, AA->y) != 0) passed = FALSE;
    if (passed == TRUE) printf("  Point doubling tests .................................................................... PASSED");
    else { printf("  Point doubling tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Point addition (twisted Edwards a=1)
    passed = TRUE;
    eccset_numsp384t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp384t1(A, P);
    ecccopy_extproj_numsp384t1(P, R);
    eccdouble_extproj_numsp384t1(P, TedCurve);             // P = 2P    

    eccset_numsp384t1(A, TedCurve);
    ecc_numsp384t1_to_weierstrass(A, QQ, TedCurve);
    ecc_numsp384t1_to_weierstrass(A, PP, TedCurve);
    eccdouble_waff_384(PP, WeierstrassCurve);              // PP = 2P

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        eccadd_extproj_numsp384t1(R, P, TedCurve);        // P = P+Q
        eccadd_waff_384(QQ, PP, WeierstrassCurve);        // PP = PP+QQ
    }
    eccnorm_numsp384t1(P, A, TedCurve);
    ecc_weierstrass_to_numsp384t1(PP, AA, TedCurve);
    if (passed == TRUE) printf("  Point addition tests .................................................................... PASSED");
    else { printf("  Point addition tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Variable-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp384t1(A, TedCurve);
    ecc_numsp384t1_to_weierstrass(A, PP, TedCurve);
    eccdouble_waff_384(PP, WeierstrassCurve);
    eccdouble_waff_384(PP, WeierstrassCurve);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(k, TedCurve->order);

        ecc_mul_waff_384(PP, k, RR, WeierstrassCurve);
        Status = ecc_scalar_mul_numsp384t1(A, k, AA, TedCurve);
        ecc_numsp384t1_to_weierstrass(AA, QQ, TedCurve);

        if (fpcompare384(QQ->x, RR->x) != 0 || fpcompare384(QQ->y, RR->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Variable-base scalar multiplication tests ............................................... PASSED");
    else { printf("  Variable-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fixed-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp384t1(A, TedCurve);
    ecc_numsp384t1_to_weierstrass(A, PP, TedCurve);
    eccdouble_waff_384(PP, WeierstrassCurve);
    eccdouble_waff_384(PP, WeierstrassCurve);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(k, TedCurve->order);
        ecc_mul_waff_384(PP, k, RR, WeierstrassCurve);

        T_fixed = ecc_allocate_precomp_numsp384t1(OP_FIXEDBASE, TedCurve);
        ecc_precomp_fixed_numsp384t1(A, T_fixed, TedCurve);
        Status = ecc_scalar_mul_fixed_numsp384t1(T_fixed, k, AA, TedCurve);
        ecc_numsp384t1_to_weierstrass(AA, QQ, TedCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }

        if (fpcompare384(QQ->x, RR->x) != 0 || fpcompare384(QQ->y, RR->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Fixed-base scalar multiplication tests .................................................. PASSED");
    else { printf("  Fixed-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Double-scalar multiplication (twisted Edwards a=1)
    passed = TRUE;
    eccset_numsp384t1(A, TedCurve);
    ecc_numsp384t1_to_weierstrass(A, PP, TedCurve);
    random384_test(k, TedCurve->order);
    ecc_mul_waff_384(PP, k, RR, WeierstrassCurve);
    ecc_weierstrass_to_numsp384t1(RR, AA, TedCurve);    // Base points are (A, AA) in twisted Edwards, (PP, RR) in Weierstrass

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(k, TedCurve->order);
        random384_test(kk, TedCurve->order);

        ecc_mul_waff_384(PP, k, UU, WeierstrassCurve);
        ecc_mul_waff_384(RR, kk, VV, WeierstrassCurve);
        eccadd_waff_384(VV, UU, WeierstrassCurve);
        ecc_weierstrass_to_numsp384t1(UU, U, TedCurve);

        T_fixed = ecc_allocate_precomp_numsp384t1(OP_DOUBLESCALAR, TedCurve);
        ecc_precomp_dblmul_numsp384t1(A, T_fixed, TedCurve);
        Status = ecc_double_scalar_mul_numsp384t1(T_fixed, k, AA, kk, V, TedCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }

        if (fpcompare384(U->x, V->x) != 0 || fpcompare384(U->y, V->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Double-scalar multiplication tests ...................................................... PASSED");
    else { printf("  Double-scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

cleanup:
    if (passed == FALSE) {
        Status = ECCRYPTO_ERROR_DURING_TEST;
    }
    ecc_curve_free(TedCurve);
    ecc_curve_free(WeierstrassCurve);

    return Status;
}

#endif


#ifdef ECCURVES_512

ECCRYPTO_STATUS ecc_test512_w(PCurveStaticData CurveData)
{ // Tests for curve numsp512d1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    dig n;
    BOOL passed = TRUE;
    point_jac_numsp512d1 P, R, complete_table[4] = {0};
    dig k[ML_WORDS512], kk[ML_WORDS512];
    point_numsp512d1 A, AA, B, BB, *T_fixed = NULL;
    PCurveStruct JacCurve = {0};

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp512d1, Weierstrass a=-3 curve over GF(2^512-569) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Point doubling (Weierstrass a=-3)
    passed = TRUE;
    eccset_numsp512d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, P);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        eccdouble_jac_numsp512d1(P, JacCurve);          // 2*P
        eccdouble_waff_512(A, JacCurve);                // 2*A
    }
    eccnorm_numsp512d1(P, AA, JacCurve);

    if (fpcompare512(A->x, AA->x) != 0 || fpcompare512(A->y, AA->y) != 0) passed = FALSE;
    if (passed == TRUE) printf("  Point doubling tests .................................................................... PASSED");
    else { printf("  Point doubling tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // "Complete" point addition (Weierstrass a=-3)
    passed = TRUE;
    eccset_numsp512d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, P);
    ecccopy_jac_numsp512d1(P, R);
    eccdouble_jac_numsp512d1(P, JacCurve);                  // P = 2P 
    eccset_numsp512d1(AA, JacCurve);
    eccdouble_waff_512(AA, JacCurve);                       // AA = 2A

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        eccadd_jac_numsp512d1(R, P, JacCurve);              // P = P+Q
        eccadd_waff_512(A, AA, JacCurve);                   // AA = AA+A
    }
    eccnorm_numsp512d1(P, A, JacCurve);
    if (fpcompare512(A->x, AA->x) != 0 || fpcompare512(A->y, AA->y) != 0) passed = FALSE;
    
    eccset_numsp512d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, P);
    ecccopy_jac_numsp512d1(P, R);
    fpneg512(JacCurve->prime, R->Y); 
    eccadd_jac_numsp512d1(R, P, JacCurve);                  // P+(-P)
    if (ecc_is_infinity_jac_numsp512d1(P, JacCurve) == FALSE) passed=FALSE;
    
    eccset_numsp512d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, R);
    ecczero_jac_numsp512d1(P); P->Y[0] = 1;
    eccadd_jac_numsp512d1(R, P, JacCurve);                  // 0+R   
    eccnorm_numsp512d1(P, AA, JacCurve); 
    if (fpcompare512(A->x,AA->x)!=0 || fpcompare512(A->y,AA->y)!=0) passed=FALSE;
    
    eccset_numsp512d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, P);
    ecczero_jac_numsp512d1(R); R->Y[0] = 1;
    eccadd_jac_numsp512d1(R, P, JacCurve);                  // P+0   
    eccnorm_numsp512d1(P, AA, JacCurve); 
    if (fpcompare512(A->x,AA->x)!=0 || fpcompare512(A->y,AA->y)!=0) passed=FALSE;
    
    eccset_numsp512d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, P);
    ecccopy_jac_numsp512d1(P, R);
    eccadd_jac_numsp512d1(R, P, JacCurve);                  // P+P   
    eccnorm_numsp512d1(P, AA, JacCurve); 
    eccdouble_jac_numsp512d1(R, JacCurve);                  // 2P  
    eccnorm_numsp512d1(R, A, JacCurve);
    if (fpcompare512(A->x,AA->x)!=0 || fpcompare512(A->y,AA->y)!=0) passed=FALSE;    
    
    // Case of mixed addition    
    complete_table[0]->Y[0] = 1;                            // Initialize complete_table[0] with the point at infinity (0:1:0)   
    eccset_numsp512d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, complete_table[1]); // Initialize complete_table[1] with A = (X_A:Y_A:1)
    eccconvert_aff_to_jac_numsp512d1(A, P);
    fpneg512(JacCurve->prime, P->Y); 
    eccadd_mixed_jac_numsp512d1(A, P, complete_table, JacCurve);  // P+(-P)
    if (ecc_is_infinity_jac_numsp512d1(P, JacCurve) == FALSE) passed=FALSE;
      
    eccset_numsp512d1(A, JacCurve);
    ecczero_jac_numsp512d1(P); P->Y[0] = 1;
    eccadd_mixed_jac_numsp512d1(A, P, complete_table, JacCurve);  // 0+R   
    eccnorm_numsp512d1(P, AA, JacCurve); 
    if (fpcompare512(A->x,AA->x)!=0 || fpcompare512(A->y,AA->y)!=0) passed=FALSE;
    
    eccset_numsp512d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, P);
    ecccopy_jac_numsp512d1(P, R);
    eccadd_mixed_jac_numsp512d1(A, P, complete_table, JacCurve);  // P+P   
    eccnorm_numsp512d1(P, AA, JacCurve); 
    eccdouble_jac_numsp512d1(R, JacCurve);                        // 2P  
    eccnorm_numsp512d1(R, A, JacCurve);
    if (fpcompare512(A->x,AA->x)!=0 || fpcompare512(A->y,AA->y)!=0) passed=FALSE;    
    
    eccset_numsp512d1(A, JacCurve);
    eccset_numsp512d1(AA, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, P);
    eccdouble_jac_numsp512d1(P, JacCurve);                        
    eccadd_mixed_jac_numsp512d1(A, P, complete_table, JacCurve);  // P+2P 
    eccdouble_waff_512(AA, JacCurve);                         
    eccadd_waff_512(A, AA, JacCurve);                             // P+2P
    eccnorm_numsp512d1(P, A, JacCurve);
    if (fpcompare512(A->x,AA->x)!=0 || fpcompare512(A->y,AA->y)!=0) passed=FALSE;       

    if (passed == TRUE) printf("  (Complete) point addition tests ......................................................... PASSED");
    else { printf("  (Complete) point addition tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Variable-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp512d1(A, JacCurve);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(k, JacCurve->order);

        ecc_mul_waff_512(A, k, AA, JacCurve);
        Status = ecc_scalar_mul_numsp512d1(A, k, B, JacCurve);

        if (fpcompare512(AA->x, B->x) != 0 || fpcompare512(AA->y, B->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Variable-base scalar multiplication tests ............................................... PASSED");
    else { printf("  Variable-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fixed-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp512d1(A, JacCurve);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(k, JacCurve->order);
        ecc_mul_waff_512(A, k, AA, JacCurve);

        T_fixed = ecc_allocate_precomp_numsp512d1(OP_FIXEDBASE, JacCurve);
        ecc_precomp_fixed_numsp512d1(A, T_fixed, JacCurve);
        Status = ecc_scalar_mul_fixed_numsp512d1(T_fixed, k, B, JacCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }

        if (fpcompare512(AA->x, B->x) != 0 || fpcompare512(AA->y, B->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Fixed-base scalar multiplication tests .................................................. PASSED");
    else { printf("  Fixed-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Double-scalar multiplication (Weierstrass a=-3)
    passed = TRUE;
    eccset_numsp512d1(A, JacCurve);
    random512_test(k, JacCurve->order);
    ecc_mul_waff_512(A, k, B, JacCurve);    // Base points are A and B

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(k, JacCurve->order);
        random512_test(kk, JacCurve->order);

        ecc_mul_waff_512(A, k, AA, JacCurve);
        ecc_mul_waff_512(B, kk, BB, JacCurve);
        eccadd_waff_512(BB, AA, JacCurve);

        T_fixed = ecc_allocate_precomp_numsp512d1(OP_DOUBLESCALAR, JacCurve);
        ecc_precomp_dblmul_numsp512d1(A, T_fixed, JacCurve);
        Status = ecc_double_scalar_mul_numsp512d1(T_fixed, k, B, kk, BB, JacCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }

        if (fpcompare512(AA->x, BB->x) != 0 || fpcompare512(AA->y, BB->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Double-scalar multiplication tests ...................................................... PASSED");
    else { printf("  Double-scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

cleanup:
    if (passed == FALSE) {
        Status = ECCRYPTO_ERROR_DURING_TEST;
    }
    ecc_curve_free(JacCurve);

    return Status;
}


ECCRYPTO_STATUS ecc_test512_te(PCurveStaticData CurveData)
{ // Tests for curve numsp512t1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    dig n;
    BOOL passed = TRUE;
    point_numsp512t1 A, AA, U, V;
    point_extproj_numsp512t1 P, R;
    point_numsp512d1 PP, QQ, RR, UU, VV;
    dig512 a, d, t1, t2, t3;
    dig k[ML_WORDS512], kk[ML_WORDS512];
    point_extaff_precomp_numsp512t1 *T_fixed = NULL;
    PCurveStruct WeierstrassCurve = {0};
    PCurveStruct TedCurve = {0};

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp512t1, twisted Edwards a=1 curve over GF(2^512-569) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Weierstrass curve allocation
    WeierstrassCurve = ecc_curve_allocate(CurveData);
    if (WeierstrassCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }

    // Set Weierstrass curve isomorphic to TedCurve
    fpcopy512(TedCurve->parameter1, a);
    fpcopy512(TedCurve->parameter2, d);
    fpzero512(t3); t3[0] = 14;
    fpmul512(t3, d, t1);   
    fpmul512(t1, a, t1);                               // t1 = 14ad
    fpsqr512(d, t2);                                   // t2 = d^2
    fpadd512(t1, t2, t2);                              // t2 = 14ad+d^2
    fpsqr512(a, t3);                                   // t3 = a^2    
    fpadd512(t2, t3, t2);                              // t2 = a^2+14ad+d^2
    fpneg512(TedCurve->prime, t2);                     // t2 = -(a^2+14ad+d^2)
    fpzero512(t1); t1[0] = 48;
    fpinv512(t1);                                      // t1 = 1/48
    fpmul512(t1, t2, WeierstrassCurve->parameter1);    // aW = -(a^2+14ad+d^2)/48
    WeierstrassCurve->nbits = TedCurve->nbits;
    WeierstrassCurve->rbits = TedCurve->rbits;
    WeierstrassCurve->pbits = TedCurve->pbits;

    // Point doubling (twisted Edwards a=1)
    passed = TRUE;
    eccset_numsp512t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp512t1(A, P);
    ecc_numsp512t1_to_weierstrass(A, PP, TedCurve);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        eccdouble_extproj_numsp512t1(P, TedCurve);         // 2*P
        eccdouble_waff_512(PP, WeierstrassCurve);          // 2*PP
    }
    eccnorm_numsp512t1(P, A, TedCurve);
    ecc_weierstrass_to_numsp512t1(PP, AA, TedCurve);

    if (fpcompare512(A->x, AA->x) != 0 || fpcompare512(A->y, AA->y) != 0) passed = FALSE;
    if (passed == TRUE) printf("  Point doubling tests .................................................................... PASSED");
    else { printf("  Point doubling tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Point addition (twisted Edwards a=1)
    passed = TRUE;
    eccset_numsp512t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp512t1(A, P);
    ecccopy_extproj_numsp512t1(P, R);
    eccdouble_extproj_numsp512t1(P, TedCurve);             // P = 2P    

    eccset_numsp512t1(A, TedCurve);
    ecc_numsp512t1_to_weierstrass(A, QQ, TedCurve);
    ecc_numsp512t1_to_weierstrass(A, PP, TedCurve);
    eccdouble_waff_512(PP, WeierstrassCurve);              // PP = 2P

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        eccadd_extproj_numsp512t1(R, P, TedCurve);         // P = P+Q
        eccadd_waff_512(QQ, PP, WeierstrassCurve);         // PP = PP+QQ
    }
    eccnorm_numsp512t1(P, A, TedCurve);
    ecc_weierstrass_to_numsp512t1(PP, AA, TedCurve);
    if (passed == TRUE) printf("  Point addition tests .................................................................... PASSED");
    else { printf("  Point addition tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Variable-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp512t1(A, TedCurve);
    ecc_numsp512t1_to_weierstrass(A, PP, TedCurve);
    eccdouble_waff_512(PP, WeierstrassCurve);
    eccdouble_waff_512(PP, WeierstrassCurve);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(k, TedCurve->order);

        ecc_mul_waff_512(PP, k, RR, WeierstrassCurve);
        Status = ecc_scalar_mul_numsp512t1(A, k, AA, TedCurve);
        ecc_numsp512t1_to_weierstrass(AA, QQ, TedCurve);

        if (fpcompare512(QQ->x, RR->x) != 0 || fpcompare512(QQ->y, RR->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Variable-base scalar multiplication tests ............................................... PASSED");
    else { printf("  Variable-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fixed-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp512t1(A, TedCurve);
    ecc_numsp512t1_to_weierstrass(A, PP, TedCurve);
    eccdouble_waff_512(PP, WeierstrassCurve);
    eccdouble_waff_512(PP, WeierstrassCurve);

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(k, TedCurve->order);
        ecc_mul_waff_512(PP, k, RR, WeierstrassCurve);

        T_fixed = ecc_allocate_precomp_numsp512t1(OP_FIXEDBASE, TedCurve);
        ecc_precomp_fixed_numsp512t1(A, T_fixed, TedCurve);
        Status = ecc_scalar_mul_fixed_numsp512t1(T_fixed, k, AA, TedCurve);
        ecc_numsp512t1_to_weierstrass(AA, QQ, TedCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }

        if (fpcompare512(QQ->x, RR->x) != 0 || fpcompare512(QQ->y, RR->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Fixed-base scalar multiplication tests .................................................. PASSED");
    else { printf("  Fixed-base scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Double-scalar multiplication (twisted Edwards a=1)
    passed = TRUE;
    eccset_numsp512t1(A, TedCurve);
    ecc_numsp512t1_to_weierstrass(A, PP, TedCurve);
    random512_test(k, TedCurve->order);
    ecc_mul_waff_512(PP, k, RR, WeierstrassCurve);
    ecc_weierstrass_to_numsp512t1(RR, AA, TedCurve);    // Base points are (A, AA) in twisted Edwards, (PP, RR) in Weierstrass

    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(k, TedCurve->order);
        random512_test(kk, TedCurve->order);

        ecc_mul_waff_512(PP, k, UU, WeierstrassCurve);
        ecc_mul_waff_512(RR, kk, VV, WeierstrassCurve);
        eccadd_waff_512(VV, UU, WeierstrassCurve);
        ecc_weierstrass_to_numsp512t1(UU, U, TedCurve);

        T_fixed = ecc_allocate_precomp_numsp512t1(OP_DOUBLESCALAR, TedCurve);
        ecc_precomp_dblmul_numsp512t1(A, T_fixed, TedCurve);
        Status = ecc_double_scalar_mul_numsp512t1(T_fixed, k, AA, kk, V, TedCurve);
        if (T_fixed != NULL) {
            free(T_fixed);
        }

        if (fpcompare512(U->x, V->x) != 0 || fpcompare512(U->y, V->y) != 0) { passed = FALSE; break; }
    }

    if (passed == TRUE) printf("  Double-scalar multiplication tests ...................................................... PASSED");
    else { printf("  Double-scalar multiplication tests ... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

cleanup:
    if (passed == FALSE) {
        Status = ECCRYPTO_ERROR_DURING_TEST;
    }
    ecc_curve_free(TedCurve);
    ecc_curve_free(WeierstrassCurve);

    return Status;
}

#endif


/****************** BENCHMARK TESTS *******************/
/******************************************************/

#ifdef ECCURVES_256

ECCRYPTO_STATUS ecc_run256_w(PCurveStaticData CurveData)
{ // Benchmarking for curve numsp256d1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    unsigned int n;
    unsigned long long cycles, cycles1, cycles2;
    point_jac_numsp256d1 P, R;
    point_numsp256d1 A, AA, B;
    dig k[ML_WORDS256], kk[ML_WORDS256];
    point_numsp256d1 *T_fixed = NULL;
    PCurveStruct JacCurve = {0};

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif
        
    printf("\n\nBENCHMARKING \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp256d1, Weierstrass a=-3 curve over GF(2^256-189) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    
    // Point doubling (Weierstrass a=-3)
    eccset_numsp256d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp256d1(A, P);

    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccdouble_jac_numsp256d1(P, JacCurve);
        eccdouble_jac_numsp256d1(P, JacCurve);
        eccdouble_jac_numsp256d1(P, JacCurve);
        eccdouble_jac_numsp256d1(P, JacCurve);
        eccdouble_jac_numsp256d1(P, JacCurve);
        eccdouble_jac_numsp256d1(P, JacCurve);
        eccdouble_jac_numsp256d1(P, JacCurve);
        eccdouble_jac_numsp256d1(P, JacCurve);
        eccdouble_jac_numsp256d1(P, JacCurve);
        eccdouble_jac_numsp256d1(P, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Point doubling", cycles, ML_BENCH_LOOPS*10);
    printf("\n"); 
    
    // "Complete" point addition (Weierstrass a=-3)    
    eccset_numsp256d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp256d1(A, P);
    ecccopy_jac_numsp256d1(P, R); 
    eccdouble_jac_numsp256d1(P, JacCurve);

    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccadd_jac_numsp256d1(R, P, JacCurve);
        eccadd_jac_numsp256d1(R, P, JacCurve);
        eccadd_jac_numsp256d1(R, P, JacCurve);
        eccadd_jac_numsp256d1(R, P, JacCurve);
        eccadd_jac_numsp256d1(R, P, JacCurve);
        eccadd_jac_numsp256d1(R, P, JacCurve);
        eccadd_jac_numsp256d1(R, P, JacCurve);
        eccadd_jac_numsp256d1(R, P, JacCurve);
        eccadd_jac_numsp256d1(R, P, JacCurve);
        eccadd_jac_numsp256d1(R, P, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("(Complete) point addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n"); 
    
    // Variable-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp256d1(A, JacCurve);
    random256_test(k, JacCurve->order); 
    
    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        ecc_scalar_mul_numsp256d1(A, k, AA, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    } 
    bench_print("Variable-base scalar mul", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 

    // Fixed-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp256d1(A, JacCurve);
    T_fixed = ecc_allocate_precomp_numsp256d1(OP_FIXEDBASE, JacCurve);
    ecc_precomp_fixed_numsp256d1(A, T_fixed, JacCurve);

    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random256_test(k, JacCurve->order);  
        cycles1 = cpucycles();
        ecc_scalar_mul_fixed_numsp256d1(T_fixed, k, AA, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Fixed-base scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    // Double-scalar multiplication (Weierstrass a=-3)
    eccset_numsp256d1(A, JacCurve); 
    random256_test(k, JacCurve->order); 
    ecc_mul_waff_256(A, k, AA, JacCurve);    // Base points are A and AA

    T_fixed = ecc_allocate_precomp_numsp256d1(OP_DOUBLESCALAR, JacCurve);
    ecc_precomp_dblmul_numsp256d1(AA, T_fixed, JacCurve);
    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random256_test(k, JacCurve->order); 
        random256_test(kk, JacCurve->order);
        cycles1 = cpucycles();
        ecc_double_scalar_mul_numsp256d1(T_fixed, k, A, kk, B, JacCurve);  
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Double-scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

cleanup:
    ecc_curve_free(JacCurve);
    
    return Status;
}


ECCRYPTO_STATUS ecc_run256_te(PCurveStaticData CurveData)
{ // Benchmarking for curve numsp256t1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    unsigned int n;
    unsigned long long cycles, cycles1, cycles2;
    point_numsp256t1 A, AA;
    point_extproj_numsp256t1 P, R;
    dig k[ML_WORDS256], kk[ML_WORDS256];
    point_extaff_precomp_numsp256t1 *T_fixed = NULL;
    PCurveStruct TedCurve = {0};

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif
        
    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp256t1, twisted Edwards a=1 curve over GF(2^256-189) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Point doubling (twisted Edwards a=1)
    eccset_numsp256t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp256t1(A, P);

    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccdouble_extproj_numsp256t1(P, TedCurve);
        eccdouble_extproj_numsp256t1(P, TedCurve);
        eccdouble_extproj_numsp256t1(P, TedCurve);
        eccdouble_extproj_numsp256t1(P, TedCurve);
        eccdouble_extproj_numsp256t1(P, TedCurve);
        eccdouble_extproj_numsp256t1(P, TedCurve);
        eccdouble_extproj_numsp256t1(P, TedCurve);
        eccdouble_extproj_numsp256t1(P, TedCurve);
        eccdouble_extproj_numsp256t1(P, TedCurve);
        eccdouble_extproj_numsp256t1(P, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Point doubling", cycles, ML_BENCH_LOOPS*10);
    printf("\n"); 

    // Point addition (twisted Edwards a=1) 
    eccset_numsp256t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp256t1(A, P);
    ecccopy_extproj_numsp256t1(P, R);
    eccdouble_extproj_numsp256t1(P, TedCurve);

    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccadd_extproj_numsp256t1(R, P, TedCurve);
        eccadd_extproj_numsp256t1(R, P, TedCurve);
        eccadd_extproj_numsp256t1(R, P, TedCurve);
        eccadd_extproj_numsp256t1(R, P, TedCurve);
        eccadd_extproj_numsp256t1(R, P, TedCurve);
        eccadd_extproj_numsp256t1(R, P, TedCurve);
        eccadd_extproj_numsp256t1(R, P, TedCurve);
        eccadd_extproj_numsp256t1(R, P, TedCurve);
        eccadd_extproj_numsp256t1(R, P, TedCurve);
        eccadd_extproj_numsp256t1(R, P, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("(Complete) point addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n"); 

    // Variable-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp256t1(A, TedCurve);
    random256_test(k, TedCurve->order); 
    
    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        ecc_scalar_mul_numsp256t1(A, k, AA, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Variable-base scalar mul", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 

    // Fixed-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp256t1(A, TedCurve);
    T_fixed = ecc_allocate_precomp_numsp256t1(OP_FIXEDBASE, TedCurve);
    ecc_precomp_fixed_numsp256t1(A, T_fixed, TedCurve);

    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random256_test(k, TedCurve->order);  
        cycles1 = cpucycles();
        ecc_scalar_mul_fixed_numsp256t1(T_fixed, k, AA, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Fixed-base scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n"); 
    
    // Double-scalar multiplication (twisted Edwards a=1)
    eccset_numsp256t1(A, TedCurve); 
    random256_test(k, TedCurve->order); 
    ecc_scalar_mul_numsp256t1(A, k, AA, TedCurve);    // Base points are A and AA

    T_fixed = ecc_allocate_precomp_numsp256t1(OP_DOUBLESCALAR, TedCurve);
    ecc_precomp_dblmul_numsp256t1(AA, T_fixed, TedCurve);
    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random256_test(k, TedCurve->order); 
        random256_test(kk, TedCurve->order);
        cycles1 = cpucycles();
        ecc_double_scalar_mul_numsp256t1(T_fixed, k, A, kk, AA, TedCurve); 
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Double-scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

cleanup:
    ecc_curve_free(TedCurve);

    return Status;
}

#endif


#ifdef ECCURVES_384

ECCRYPTO_STATUS ecc_run384_w(PCurveStaticData CurveData)
{ // Benchmarking for curve numsp384d1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    unsigned int n;
    unsigned long long cycles, cycles1, cycles2;
    point_jac_numsp384d1 P, R;
    point_numsp384d1 A, AA, B;
    dig k[ML_WORDS384], kk[ML_WORDS384];
    point_numsp384d1 *T_fixed = NULL;
    PCurveStruct JacCurve = {0};

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp384d1, Weierstrass a=-3 curve over GF(2^384-317) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Point doubling (Weierstrass a=-3)
    eccset_numsp384d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, P);

    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccdouble_jac_numsp384d1(P, JacCurve);
        eccdouble_jac_numsp384d1(P, JacCurve);
        eccdouble_jac_numsp384d1(P, JacCurve);
        eccdouble_jac_numsp384d1(P, JacCurve);
        eccdouble_jac_numsp384d1(P, JacCurve);
        eccdouble_jac_numsp384d1(P, JacCurve);
        eccdouble_jac_numsp384d1(P, JacCurve);
        eccdouble_jac_numsp384d1(P, JacCurve);
        eccdouble_jac_numsp384d1(P, JacCurve);
        eccdouble_jac_numsp384d1(P, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Point doubling", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // "Complete" point addition (Weierstrass a=-3)    
    eccset_numsp384d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp384d1(A, P);
    ecccopy_jac_numsp384d1(P, R);
    eccdouble_jac_numsp384d1(P, JacCurve);

    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccadd_jac_numsp384d1(R, P, JacCurve);
        eccadd_jac_numsp384d1(R, P, JacCurve);
        eccadd_jac_numsp384d1(R, P, JacCurve);
        eccadd_jac_numsp384d1(R, P, JacCurve);
        eccadd_jac_numsp384d1(R, P, JacCurve);
        eccadd_jac_numsp384d1(R, P, JacCurve);
        eccadd_jac_numsp384d1(R, P, JacCurve);
        eccadd_jac_numsp384d1(R, P, JacCurve);
        eccadd_jac_numsp384d1(R, P, JacCurve);
        eccadd_jac_numsp384d1(R, P, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("(Complete) point addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Variable-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp384d1(A, JacCurve);
    random384_test(k, JacCurve->order);

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        ecc_scalar_mul_numsp384d1(A, k, AA, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    } 
    bench_print("Variable-base scalar mul", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

    // Fixed-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp384d1(A, JacCurve);
    T_fixed = ecc_allocate_precomp_numsp384d1(OP_FIXEDBASE, JacCurve);
    ecc_precomp_fixed_numsp384d1(A, T_fixed, JacCurve);

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random384_test(k, JacCurve->order);
        cycles1 = cpucycles();
        ecc_scalar_mul_fixed_numsp384d1(T_fixed, k, AA, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Fixed-base scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

    // Double-scalar multiplication (Weierstrass a=-3)
    eccset_numsp384d1(A, JacCurve);
    random384_test(k, JacCurve->order);
    ecc_mul_waff_384(A, k, AA, JacCurve);    // Base points are A and AA

    T_fixed = ecc_allocate_precomp_numsp384d1(OP_DOUBLESCALAR, JacCurve);
    ecc_precomp_dblmul_numsp384d1(AA, T_fixed, JacCurve);
    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random384_test(k, JacCurve->order);
        random384_test(kk, JacCurve->order);
        cycles1 = cpucycles();
        ecc_double_scalar_mul_numsp384d1(T_fixed, k, A, kk, B, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Double-scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

cleanup:
    ecc_curve_free(JacCurve);

    return Status;
}


ECCRYPTO_STATUS ecc_run384_te(PCurveStaticData CurveData)
{ // Benchmarking for curve numsp384t1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    unsigned int n;
    unsigned long long cycles, cycles1, cycles2;
    point_numsp384t1 A, AA;
    point_extproj_numsp384t1 P, R;
    dig k[ML_WORDS384], kk[ML_WORDS384];
    point_extaff_precomp_numsp384t1 *T_fixed = NULL;
    PCurveStruct TedCurve = {0};

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp384t1, twisted Edwards a=1 curve over GF(2^384-317) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Point doubling (twisted Edwards a=1)
    eccset_numsp384t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp384t1(A, P);

    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccdouble_extproj_numsp384t1(P, TedCurve);
        eccdouble_extproj_numsp384t1(P, TedCurve);
        eccdouble_extproj_numsp384t1(P, TedCurve);
        eccdouble_extproj_numsp384t1(P, TedCurve);
        eccdouble_extproj_numsp384t1(P, TedCurve);
        eccdouble_extproj_numsp384t1(P, TedCurve);
        eccdouble_extproj_numsp384t1(P, TedCurve);
        eccdouble_extproj_numsp384t1(P, TedCurve);
        eccdouble_extproj_numsp384t1(P, TedCurve);
        eccdouble_extproj_numsp384t1(P, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Point doubling", cycles, ML_BENCH_LOOPS*10);
    printf("\n"); 

    // Point addition (twisted Edwards a=1)  
    eccset_numsp384t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp384t1(A, P);
    ecccopy_extproj_numsp384t1(P, R);
    eccdouble_extproj_numsp384t1(P, TedCurve);

    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccadd_extproj_numsp384t1(R, P, TedCurve);
        eccadd_extproj_numsp384t1(R, P, TedCurve);
        eccadd_extproj_numsp384t1(R, P, TedCurve);
        eccadd_extproj_numsp384t1(R, P, TedCurve);
        eccadd_extproj_numsp384t1(R, P, TedCurve);
        eccadd_extproj_numsp384t1(R, P, TedCurve);
        eccadd_extproj_numsp384t1(R, P, TedCurve);
        eccadd_extproj_numsp384t1(R, P, TedCurve);
        eccadd_extproj_numsp384t1(R, P, TedCurve);
        eccadd_extproj_numsp384t1(R, P, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("(Complete) point addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n"); 

    // Variable-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp384t1(A, TedCurve);
    random384_test(k, TedCurve->order);

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        ecc_scalar_mul_numsp384t1(A, k, AA, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Variable-base scalar mul", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

    // Fixed-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp384t1(A, TedCurve);
    T_fixed = ecc_allocate_precomp_numsp384t1(OP_FIXEDBASE, TedCurve);
    ecc_precomp_fixed_numsp384t1(A, T_fixed, TedCurve);

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random384_test(k, TedCurve->order);
        cycles1 = cpucycles();
        ecc_scalar_mul_fixed_numsp384t1(T_fixed, k, AA, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Fixed-base scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

    // Double-scalar multiplication (twisted Edwards a=1)
    eccset_numsp384t1(A, TedCurve);
    random384_test(k, TedCurve->order);
    ecc_scalar_mul_numsp384t1(A, k, AA, TedCurve);    // Base points are A and AA

    T_fixed = ecc_allocate_precomp_numsp384t1(OP_DOUBLESCALAR, TedCurve);
    ecc_precomp_dblmul_numsp384t1(AA, T_fixed, TedCurve);
    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random384_test(k, TedCurve->order);
        random384_test(kk, TedCurve->order);
        cycles1 = cpucycles();
        ecc_double_scalar_mul_numsp384t1(T_fixed, k, A, kk, AA, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Double-scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

cleanup:
    ecc_curve_free(TedCurve);

    return Status;
}

#endif


#ifdef ECCURVES_512

ECCRYPTO_STATUS ecc_run512_w(PCurveStaticData CurveData)
{ // Benchmarking for curve numsp512d1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    unsigned int n;
    unsigned long long cycles, cycles1, cycles2;
    point_jac_numsp512d1 P, R;
    point_numsp512d1 A, AA, B;
    dig k[ML_WORDS512], kk[ML_WORDS512];
    point_numsp512d1 *T_fixed = NULL;
    PCurveStruct JacCurve = {0};

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp512d1, Weierstrass a=-3 curve over GF(2^512-569) \n\n");

    // Curve initialization
    JacCurve = ecc_curve_allocate(CurveData);
    if (JacCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(JacCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Point doubling (Weierstrass a=-3)
    eccset_numsp512d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, P);

    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccdouble_jac_numsp512d1(P, JacCurve);
        eccdouble_jac_numsp512d1(P, JacCurve);
        eccdouble_jac_numsp512d1(P, JacCurve);
        eccdouble_jac_numsp512d1(P, JacCurve);
        eccdouble_jac_numsp512d1(P, JacCurve);
        eccdouble_jac_numsp512d1(P, JacCurve);
        eccdouble_jac_numsp512d1(P, JacCurve);
        eccdouble_jac_numsp512d1(P, JacCurve);
        eccdouble_jac_numsp512d1(P, JacCurve);
        eccdouble_jac_numsp512d1(P, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Point doubling", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // "Complete" point addition (Weierstrass a=-3)    
    eccset_numsp512d1(A, JacCurve);
    eccconvert_aff_to_jac_numsp512d1(A, P);
    ecccopy_jac_numsp512d1(P, R);
    eccdouble_jac_numsp512d1(P, JacCurve);

    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccadd_jac_numsp512d1(R, P, JacCurve);
        eccadd_jac_numsp512d1(R, P, JacCurve);
        eccadd_jac_numsp512d1(R, P, JacCurve);
        eccadd_jac_numsp512d1(R, P, JacCurve);
        eccadd_jac_numsp512d1(R, P, JacCurve);
        eccadd_jac_numsp512d1(R, P, JacCurve);
        eccadd_jac_numsp512d1(R, P, JacCurve);
        eccadd_jac_numsp512d1(R, P, JacCurve);
        eccadd_jac_numsp512d1(R, P, JacCurve);
        eccadd_jac_numsp512d1(R, P, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("(Complete) point addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Variable-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp512d1(A, JacCurve);
    random512_test(k, JacCurve->order);

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        ecc_scalar_mul_numsp512d1(A, k, AA, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Variable-base scalar mul", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

    // Fixed-base scalar multiplication (Weierstrass a=-3)
    eccset_numsp512d1(A, JacCurve);
    T_fixed = ecc_allocate_precomp_numsp512d1(OP_FIXEDBASE, JacCurve);
    ecc_precomp_fixed_numsp512d1(A, T_fixed, JacCurve);

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random512_test(k, JacCurve->order);
        cycles1 = cpucycles();
        ecc_scalar_mul_fixed_numsp512d1(T_fixed, k, AA, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Fixed-base scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

    // Double-scalar multiplication (Weierstrass a=-3)
    eccset_numsp512d1(A, JacCurve);
    random512_test(k, JacCurve->order);
    ecc_mul_waff_512(A, k, AA, JacCurve);    // Base points are A and AA

    T_fixed = ecc_allocate_precomp_numsp512d1(OP_DOUBLESCALAR, JacCurve);
    ecc_precomp_dblmul_numsp512d1(AA, T_fixed, JacCurve);
    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random512_test(k, JacCurve->order);
        random512_test(kk, JacCurve->order);
        cycles1 = cpucycles();
        ecc_double_scalar_mul_numsp512d1(T_fixed, k, A, kk, B, JacCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Double-scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

cleanup:
    ecc_curve_free(JacCurve);

    return Status;
}


ECCRYPTO_STATUS ecc_run512_te(PCurveStaticData CurveData)
{ // Benchmarking for curve numsp512t1
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    unsigned int n;
    unsigned long long cycles, cycles1, cycles2;
    point_numsp512t1 A, AA;
    point_extproj_numsp512t1 P, R;
    dig k[ML_WORDS512], kk[ML_WORDS512];
    point_extaff_precomp_numsp512t1 *T_fixed = NULL;
    PCurveStruct TedCurve = {0};

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Curve arithmetic: numsp512t1, twisted Edwards a=1 curve over GF(2^512-569) \n\n");

    // Curve initialization
    TedCurve = ecc_curve_allocate(CurveData);
    if (TedCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(TedCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Point doubling (twisted Edwards a=1)
    eccset_numsp512t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp512t1(A, P);

    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccdouble_extproj_numsp512t1(P, TedCurve);
        eccdouble_extproj_numsp512t1(P, TedCurve);
        eccdouble_extproj_numsp512t1(P, TedCurve);
        eccdouble_extproj_numsp512t1(P, TedCurve);
        eccdouble_extproj_numsp512t1(P, TedCurve);
        eccdouble_extproj_numsp512t1(P, TedCurve);
        eccdouble_extproj_numsp512t1(P, TedCurve);
        eccdouble_extproj_numsp512t1(P, TedCurve);
        eccdouble_extproj_numsp512t1(P, TedCurve);
        eccdouble_extproj_numsp512t1(P, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Point doubling", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Point addition (twisted Edwards a=1) 
    eccset_numsp512t1(A, TedCurve);
    eccconvert_aff_to_extproj_numsp512t1(A, P);
    ecccopy_extproj_numsp512t1(P, R);
    eccdouble_extproj_numsp512t1(P, TedCurve);

    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        eccadd_extproj_numsp512t1(R, P, TedCurve);
        eccadd_extproj_numsp512t1(R, P, TedCurve);
        eccadd_extproj_numsp512t1(R, P, TedCurve);
        eccadd_extproj_numsp512t1(R, P, TedCurve);
        eccadd_extproj_numsp512t1(R, P, TedCurve);
        eccadd_extproj_numsp512t1(R, P, TedCurve);
        eccadd_extproj_numsp512t1(R, P, TedCurve);
        eccadd_extproj_numsp512t1(R, P, TedCurve);
        eccadd_extproj_numsp512t1(R, P, TedCurve);
        eccadd_extproj_numsp512t1(R, P, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("(Complete) point addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Variable-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp512t1(A, TedCurve);
    random512_test(k, TedCurve->order);

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        cycles1 = cpucycles();
        ecc_scalar_mul_numsp512t1(A, k, AA, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Variable-base scalar mul", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

    // Fixed-base scalar multiplication (twisted Edwards a=1)
    eccset_numsp512t1(A, TedCurve);
    T_fixed = ecc_allocate_precomp_numsp512t1(OP_FIXEDBASE, TedCurve);
    ecc_precomp_fixed_numsp512t1(A, T_fixed, TedCurve);

    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random512_test(k, TedCurve->order);
        cycles1 = cpucycles();
        ecc_scalar_mul_fixed_numsp512t1(T_fixed, k, AA, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Fixed-base scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

    // Double-scalar multiplication (twisted Edwards a=1)
    eccset_numsp512t1(A, TedCurve);
    random512_test(k, TedCurve->order);
    ecc_scalar_mul_numsp512t1(A, k, AA, TedCurve);    // Base points are A and AA

    T_fixed = ecc_allocate_precomp_numsp512t1(OP_DOUBLESCALAR, TedCurve);
    ecc_precomp_dblmul_numsp512t1(AA, T_fixed, TedCurve);
    cycles = 0;
    for (n = 0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random512_test(k, TedCurve->order);
        random512_test(kk, TedCurve->order);
        cycles1 = cpucycles();
        ecc_double_scalar_mul_numsp512t1(T_fixed, k, A, kk, AA, TedCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    if (T_fixed != NULL) {
        free(T_fixed);
    }

    bench_print("Double-scalar mul (memory model=MEM_LARGE)", cycles, ML_SHORT_BENCH_LOOPS);
    printf("\n");

cleanup:
    ecc_curve_free(TedCurve);

    return Status;
}

#endif


int main()
{
    const char* message = NULL;
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
    Status = ecc_test256_w(&curve_numsp256d1);       // Test "numsp256d1", Weierstrass a=-3 curve with p = 2^256-189
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    }
    Status = ecc_test256_te(&curve_numsp256t1);      // Test "numsp256t1", twisted Edwards a=1 curve with p = 2^256-189
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    }
#endif
#ifdef ECCURVES_384
    Status = ecc_test384_w(&curve_numsp384d1);       // Test "numsp384d1", Weierstrass a=-3 curve with p = 2^384-317
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    } 
    Status = ecc_test384_te(&curve_numsp384t1);      // Test "numsp384t1", twisted Edwards a=1 curve with p = 2^384-317
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    } 
#endif
#ifdef ECCURVES_512
    Status = ecc_test512_w(&curve_numsp512d1);       // Test "numsp512d1", Weierstrass a=-3 curve with p = 2^512-569
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    }
    Status = ecc_test512_te(&curve_numsp512t1);      // Test "numsp512t1", twisted Edwards a=1 curve with p = 2^512-569
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    }
#endif

#ifdef ECCURVES_256
    Status = ecc_run256_w(&curve_numsp256d1);        // Benchmark "numsp256d1", Weierstrass a=-3 curve with p = 2^256-189
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    }
    Status = ecc_run256_te(&curve_numsp256t1);       // Benchmark "numsp256t1", twisted Edwards a=1 curve with p = 2^256-189
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    }
#endif
#ifdef ECCURVES_384
    Status = ecc_run384_w(&curve_numsp384d1);        // Benchmark "numsp384d1", Weierstrass a=-3 curve with p = 2^384-317
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    }
    Status = ecc_run384_te(&curve_numsp384t1);       // Benchmark "numsp384t1", twisted Edwards a=1 curve with p = 2^384-317
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    }
#endif
#ifdef ECCURVES_512
    Status = ecc_run512_w(&curve_numsp512d1);        // Benchmark "numsp512d1", Weierstrass a=-3 curve with p = 2^512-569
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    }
    Status = ecc_run512_te(&curve_numsp512t1);       // Benchmark "numsp512t1", twisted Edwards a=1 curve with p = 2^512-569
    if (Status != ECCRYPTO_SUCCESS) {
        message = ecc_get_error_message(Status);
        printf("\n\n   Error detected: %s \n\n", message);
        return FALSE;
    }
#endif
    
    return TRUE;
}