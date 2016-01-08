/**************************************************************************
* Suite for benchmarking/testing field operations for MSR ECClib
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
* Abstract: benchmarking/testing field operations
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
***************************************************************************/  

#include "tests.h"
#if OS_TARGET == OS_WIN
    #include <windows.h>
#endif
#include <stdio.h>
#include <malloc.h>


#ifdef ECCURVES_256

ECCRYPTO_STATUS fp_test256(PCurveStaticData CurveData)
{ // Tests of field arithmetic over GF(2^256-189)
    BOOL passed = TRUE;    
    dig n;
    dig256 a, b, c, d, e, f, p;
    PCurveStruct PCurve = {0};
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;

    if (CurveData->Curve == numsp256d1) printf("\n\nTESTING"); 
    printf("\n--------------------------------------------------------------------------------------------------------\n\n"); 
    if (CurveData->Curve == numsp256d1) printf("Field arithmetic over GF(2^256-189), curve numsp256d1: \n\n");
    if (CurveData->Curve == numsp256t1) printf("Field arithmetic over GF(2^256-189), curve numsp256t1: \n\n");
    
    // Curve initialization
    PCurve = ecc_curve_allocate(CurveData);
    if (PCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(PCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    fp_prime256(p, PCurve);

    // Fp addition with p = 2^256-189
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); random256_test(f, PCurve->prime); 
        
        fpadd256(a, b, d); fpadd256(d, c, e);                 // e = (a+b)+c
        fpadd256(b, c, d); fpadd256(d, a, f);                 // f = a+(b+c)
        if (fpcompare256(e,f)!=0) { passed=FALSE; break; }

        fpadd256(a, b, d);                                     // d = a+b 
        fpadd256(b, a, e);                                     // e = b+a
        if (fpcompare256(d,e)!=0) { passed=FALSE; break; }

        fpzero256(b);
        fpadd256(a, b, d);                                     // d = a+0 
        if (fpcompare256(a,d)!=0) { passed=FALSE; break; }
        
        fpzero256(b);
        fpcopy256(a, d);     
        fpneg256(PCurve->prime, d);                      
        fpadd256(a, d, e);                                     // e = a+(-a)
        if (fpcompare256(e,b)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Addition tests (associativity, commutativity, identity, inverse)......................... PASSED");
    else { printf("  Addition tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Fp subtraction with p = 2^256-189
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {        
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); 

        fpsub256(a, b, d);                                    // d = a-b 
        fpsub256(b, a, e);                                    // e = b-a     
        fpneg256(PCurve->prime, e);     
        if (fpcompare256(d,e)!=0) { passed=FALSE; break; }

        fpzero256(b);
        fpsub256(a, b, d);                                    // d = a-0 
        if (fpcompare256(a,d)!=0) { passed=FALSE; break; }
                 
        fpsub256(a, a, d);                                    // e = a-(a)
        if (fp_iszero256(d) == FALSE) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Subtraction tests (anti-commutativity, identity, inverse)................................ PASSED");
    else { printf("  Subtraction tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Fp division by 2 with p = 2^256-189
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {        
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); 

        fpdiv2_256(a, c);                                  // c = a/2
        fpadd256(c, c, b);                                 // b = a 
        if (fpcompare256(a,b)!=0) { passed=FALSE; break; }

        fpdiv2_256(a, c);                                  // c = a/2
        fpzero256(b); b[0] = 2;
        fpmul256(c, b, d);                                 // d = a 
        if (fpcompare256(a,d)!=0) { passed=FALSE; break; }

        fpzero256(b);
        fpdiv2_256(b, c);                                  // 0 
        if (fpcompare256(c,b)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Division by 2 tests ..................................................................... PASSED");
    else { printf("  Division by 2 tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Fp negation with p = 2^256-189
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {        
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); 

        fpcopy256(a, c);
        fpneg256(PCurve->prime, a);                        // -a 
        fpneg256(PCurve->prime, a);                        // -(-a) 
        if (fpcompare256(a,c)!=0) { passed=FALSE; break; }

        fpsub256(a, b, c);                                 // c = a-b 
        fpneg256(PCurve->prime, b);                        // -b 
        fpadd256(a, b, d);                                 // d = a+(-b) 
        if (fpcompare256(c,d)!=0) { passed=FALSE; break; }

        fpzero256(b);
        fpneg256(PCurve->prime, b);                        // -0 
        if (fpcompare256(p,b)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Negation tests .......................................................................... PASSED");
    else { printf("  Negation tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fp multiplication with p = 2^256-189
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {    
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); random256_test(f, PCurve->prime);

        fpmul256(a, b, d); fpmul256(d, c, e);                        // e = (a*b)*c
        fpmul256(b, c, d); fpmul256(d, a, f);                        // f = a*(b*c)
        if (fpcompare256(e,f)!=0) { passed=FALSE; break; }

        fpadd256(b, c, d); fpmul256(a, d, e);                        // e = a*(b+c)
        fpmul256(a, b, d); fpmul256(a, c, f); fpadd256(d, f, f);     // f = a*b+a*c
        if (fpcompare256(e,f)!=0) { passed=FALSE; break; }

        fpmul256(a, b, d);                                           // d = a*b 
        fpmul256(b, a, e);                                           // e = b*a 
        if (fpcompare256(d,e)!=0) { passed=FALSE; break; }

        fpzero256(b); b[0]=1; 
        fpmul256(a, b, d);                                           // d = a*1 
        if (fpcompare256(a,d)!=0) { passed=FALSE; break; }

        fpzero256(b);
        fpmul256(a, b, d);                                           // d = a*0 
        if (fpcompare256(b,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Multiplication tests (associativity, distributive, commutativity, identity, null)........ PASSED");
    else { printf("  Multiplication tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fp squaring with p = 2^256-189
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); 

        fpsqr256(a, b);                                            // b = a^2
        fpmul256(a, a, c);                                         // c = a*a 
        if (fpcompare256(b,c)!=0) { passed=FALSE; break; }

        fpzero256(a);
        fpsqr256(a, d);                                            // d = 0^2 
        if (fpcompare256(a,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Squaring tests........................................................................... PASSED");
    else { printf("  Squaring tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fp inversion with p = 2^256-189
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime);   

        fpzero256(d); d[0]=1; 
        fpcopy256(a, b);                            
        fpinv256(a);                                
        fpmul256(a, b, c);                                      // c = a*a^-1 
        if (fpcompare256(c,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Inversion tests.......................................................................... PASSED");
    else { printf("  Inversion tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    printf("\nOther functions: \n\n");

    // Modular addition, modulo the order of a curve
    passed = TRUE;
    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(a, PCurve->order); random256_test(b, PCurve->order); random256_test(c, PCurve->order);

        addition_mod_order(a, b, d, PCurve); addition_mod_order(d, c, e, PCurve);    // e = (a+b)+c
        addition_mod_order(b, c, d, PCurve); addition_mod_order(d, a, f, PCurve);    // f = a+(b+c)
        if (fpcompare256(e, f) != 0) { passed = FALSE; break; }

        addition_mod_order(a, b, d, PCurve);                                         // d = a+b 
        addition_mod_order(b, a, e, PCurve);                                         // e = b+a
        if (fpcompare256(d, e) != 0) { passed = FALSE; break; }

        fpzero256(b);
        addition_mod_order(a, b, d, PCurve);                                         // d = a+0 
        if (fpcompare256(a, d) != 0) { passed = FALSE; break; }
    }
    if (passed==TRUE) printf("  Modular addition tests .................................................................. PASSED");
    else { printf("  Modular addition tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Modular correction, modulo the order of a curve
    passed = TRUE;
    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        fpcopy256(PCurve->prime, a);
        a[0] = a[0] & ((dig)-1 << 1);                                               // a = p-1 
        correction_mod_order(a, c, PCurve);                                         // p-1 (mod r) 
        if (fpcompare256(c, PCurve->order) != -1) { passed = FALSE; break; }

        fpzero256(b);
        correction_mod_order(b, d, PCurve);                                         // 0 (mod r) 
        if (fpcompare256(b, d) != 0) { passed = FALSE; break; }

        fpzero256(b);
        correction_mod_order(PCurve->order, d, PCurve);                             // r (mod r) 
        if (fpcompare256(b, d) != 0) { passed = FALSE; break; }
    }
    if (passed==TRUE) printf("  Modular correction tests ................................................................ PASSED");
    else { printf("  Modular correction tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Montgomery multiplication, modulo the order of a curve 
    passed = TRUE;
    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(a, PCurve->order); random256_test(b, PCurve->order); random256_test(c, PCurve->order);
        
        toMontgomery_mod_order256(a, d, PCurve);                                                                 // Conversion to/from Montgomery
        fromMontgomery_mod_order256(d, e, PCurve);
        if (fpcompare256(a, e) != 0) { passed = FALSE; break; }

        Montgomery_multiply_mod_order256(a, b, d, PCurve); Montgomery_multiply_mod_order256(d, c, e, PCurve);    // e = (a*b)*c
        Montgomery_multiply_mod_order256(b, c, d, PCurve); Montgomery_multiply_mod_order256(d, a, f, PCurve);    // f = a*(b*c)
        if (fpcompare256(e, f) != 0) { passed = FALSE; break; }

        addition_mod_order(b, c, d, PCurve); Montgomery_multiply_mod_order256(a, d, e, PCurve);                                                       // e = a*(b+c)
        Montgomery_multiply_mod_order256(a, b, d, PCurve); Montgomery_multiply_mod_order256(a, c, f, PCurve); addition_mod_order(d, f, f, PCurve);    // f = a*b+a*c
        if (fpcompare256(e, f) != 0) { passed = FALSE; break; }
        
        Montgomery_multiply_mod_order256(a, b, d, PCurve);                                                       // d = a*b 
        Montgomery_multiply_mod_order256(b, a, e, PCurve);                                                       // e = b*a 
        if (fpcompare256(d, e) != 0) { passed = FALSE; break; }

        fpzero256(b); b[0] = 1;
        toMontgomery_mod_order256(b, b, PCurve);
        Montgomery_multiply_mod_order256(a, b, d, PCurve);                                                    // d = a*1 
        if (fpcompare256(a, d) != 0) { passed = FALSE; break; }

        fpzero256(b);
        Montgomery_multiply_mod_order256(a, b, d, PCurve);                                                    // d = a*0 
        if (fpcompare256(b, d) != 0) { passed = FALSE; break; }
    }
    if (passed==TRUE) printf("  Montgomery multiplication and conversion tests .......................................... PASSED");
    else { printf("  Montgomery multiplication and conversion tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Montgomery inversion, modulo the order of a curve 
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random256_test(a, PCurve->order); random256_test(b, PCurve->order); random256_test(c, PCurve->order);   

        fpzero256(d); d[0]=1; 
        toMontgomery_mod_order256(d, d, PCurve);
        fpcopy256(a, b);                            
        Montgomery_inversion_mod_order256(a, a, PCurve);                                
        Montgomery_multiply_mod_order256(a, b, c, PCurve);                                      // c = a*a^-1 
        if (fpcompare256(c,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Montgomery inversion tests............................................................... PASSED");
    else { printf("  Montgomery inversion tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
cleanup:
    if (passed == FALSE) {
        Status = ECCRYPTO_ERROR_DURING_TEST;
    }
    ecc_curve_free(PCurve);

    return Status;
}

#endif


#ifdef ECCURVES_384

ECCRYPTO_STATUS fp_test384(PCurveStaticData CurveData)
{ // Tests of field arithmetic over GF(2^384-317)
    BOOL passed = TRUE;
    dig n;
    dig384 a, b, c, d, e, f, p;
    PCurveStruct PCurve = { 0 };
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    if (CurveData->Curve == numsp384d1) printf("Field arithmetic over GF(2^384-317), curve numsp384d1: \n\n");
    if (CurveData->Curve == numsp384t1) printf("Field arithmetic over GF(2^384-317), curve numsp384t1: \n\n");


    // Curve initialization
    PCurve = ecc_curve_allocate(CurveData);
    if (PCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(PCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    fp_prime384(p, PCurve);

    // Fp addition with p = 2^384-317
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); random384_test(f, PCurve->prime); 

        fpadd384(a, b, d); fpadd384(d, c, e);                  // e = (a+b)+c
        fpadd384(b, c, d); fpadd384(d, a, f);                  // f = a+(b+c)
        if (fpcompare384(e,f)!=0) { passed=FALSE; break; }

        fpadd384(a, b, d);                                     // d = a+b 
        fpadd384(b, a, e);                                     // e = b+a
        if (fpcompare384(d,e)!=0) { passed=FALSE; break; }

        fpzero384(b);
        fpadd384(a, b, d);                                     // d = a+0 
        if (fpcompare384(a,d)!=0) { passed=FALSE; break; }
        
        fpzero384(b);
        fpcopy384(a, d);     
        fpneg384(PCurve->prime, d);                      
        fpadd384(a, d, e);                                     // e = a+(-a)
        if (fpcompare384(e,b)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Addition tests (associativity, commutativity, identity, inverse)......................... PASSED");
    else { printf("Addition tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fp subtraction with p = 2^384-317
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {        
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); 

        fpsub384(a, b, d);                                    // d = a-b 
        fpsub384(b, a, e);                                    // e = b-a     
        fpneg384(PCurve->prime, e);     
        if (fpcompare384(d,e)!=0) { passed=FALSE; break; }

        fpzero384(b);
        fpsub384(a, b, d);                                    // d = a-0 
        if (fpcompare384(a,d)!=0) { passed=FALSE; break; }
                 
        fpsub384(a, a, d);                                    // e = a-(a)
        if (fp_iszero384(d) == FALSE) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Subtraction tests (anti-commutativity, identity, inverse)................................ PASSED");
    else { printf("  Subtraction tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fp division by 2 with p = 2^384-317
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {        
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); 

        fpdiv2_384(a, c);                                  // c = a/2
        fpadd384(c, c, b);                                 // b = a 
        if (fpcompare384(a,b)!=0) { passed=FALSE; break; }
        
        fpdiv2_384(a, c);                                  // c = a/2
        fpzero384(b); b[0] = 2;
        fpmul384(c, b, d);                                 // d = a 
        if (fpcompare384(a,d)!=0) { passed=FALSE; break; }
        
        fpzero384(b);
        fpdiv2_384(b, c);                                  // 0 
        if (fpcompare384(c,b)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Division by 2 tests ..................................................................... PASSED");
    else { printf("  Division by 2 tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fp negation with p = 2^384-317
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {        
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); 

        fpcopy384(a, c);
        fpneg384(PCurve->prime, a);                        // -a 
        fpneg384(PCurve->prime, a);                        // -(-a) 
        if (fpcompare384(a,c)!=0) { passed=FALSE; break; }

        fpsub384(a, b, c);                                 // c = a-b 
        fpneg384(PCurve->prime, b);                        // -b 
        fpadd384(a, b, d);                                 // d = a+(-b) 
        if (fpcompare384(c,d)!=0) { passed=FALSE; break; }

        fpzero384(b);
        fpneg384(PCurve->prime, b);                        // -0 
        if (fpcompare384(p,b)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Negation tests .......................................................................... PASSED");
    else { printf("  Negation tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Fp multiplication with p = 2^384-317
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {    
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); random384_test(f, PCurve->prime);

        fpmul384(a, b, d); fpmul384(d, c, e);                     // e = (a*b)*c
        fpmul384(b, c, d); fpmul384(d, a, f);                     // f = a*(b*c)
        if (fpcompare384(e,f)!=0) { passed=FALSE; break; }

        fpadd384(b, c, d); fpmul384(a, d, e);                     // e = a*(b+c)
        fpmul384(a, b, d); fpmul384(a, c, f); fpadd384(d, f, f);  // f = a*b+a*c
        if (fpcompare384(e,f)!=0) { passed=FALSE; break; }

        fpmul384(a, b, d);                                        // d = a*b 
        fpmul384(b, a, e);                                        // e = b*a 
        if (fpcompare384(d,e)!=0) { passed=FALSE; break; }
        
        fpzero384(b); b[0] = 1;
        fpmul384(a, b, d);                                        // d = a*1 
        if (fpcompare384(a,d)!=0) { passed=FALSE; break; }

        fpzero384(b);
        fpmul384(a, b, d);                                        // d = a*0 
        if (fpcompare384(b,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Multiplication tests (associativity, distributive, commutativity, identity, null)........ PASSED");
    else { printf("  Multiplication tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fp squaring with p = 2^384-317
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); 

        fpsqr384(a, b);                                            // b = a^2
        fpmul384(a, a, c);                                         // c = a*a 
        if (fpcompare384(b,c)!=0) { passed=FALSE; break; }
        
        fpzero384(a);
        fpsqr384(a, d);                                            // d = 0^2 
        if (fpcompare384(a,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Squaring tests........................................................................... PASSED");
    else { printf("  Squaring tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Fp inversion with p = 2^384-317
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime);   
                
        fpzero384(d); d[0]=1;  
        fpcopy384(a, b);                            
        fpinv384(a);                                
        fpmul384(a, b, c);                                        // c = a*a^-1 
        if (fpcompare384(c,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Inversion tests.......................................................................... PASSED");
    else { printf("  Inversion tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    printf("\nOther functions: \n\n");

    // Modular addition, modulo the order of a curve
    passed = TRUE;
    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(a, PCurve->order); random384_test(b, PCurve->order); random384_test(c, PCurve->order);

        addition_mod_order(a, b, d, PCurve); addition_mod_order(d, c, e, PCurve);    // e = (a+b)+c
        addition_mod_order(b, c, d, PCurve); addition_mod_order(d, a, f, PCurve);    // f = a+(b+c)
        if (fpcompare384(e, f) != 0) { passed = FALSE; break; }

        addition_mod_order(a, b, d, PCurve);                                         // d = a+b 
        addition_mod_order(b, a, e, PCurve);                                         // e = b+a
        if (fpcompare384(d, e) != 0) { passed = FALSE; break; }

        fpzero384(b);
        addition_mod_order(a, b, d, PCurve);                                         // d = a+0 
        if (fpcompare384(a, d) != 0) { passed = FALSE; break; }
    }
    if (passed==TRUE) printf("  Modular addition tests .................................................................. PASSED");
    else { printf("  Modular addition tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Modular correction, modulo the order of a curve
    passed = TRUE;
    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        fpcopy384(PCurve->prime, a);
        a[0] = a[0] & ((dig)-1 << 1);                                               // a = p-1 
        correction_mod_order(a, c, PCurve);                                         // p-1 (mod r) 
        if (fpcompare384(c, PCurve->order) != -1) { passed = FALSE; break; }

        fpzero384(b);
        correction_mod_order(b, d, PCurve);                                         // 0 (mod r) 
        if (fpcompare256(b, d) != 0) { passed = FALSE; break; }

        fpzero384(b);
        correction_mod_order(PCurve->order, d, PCurve);                             // r (mod r) 
        if (fpcompare256(b, d) != 0) { passed = FALSE; break; }
    }
    if (passed==TRUE) printf("  Modular correction tests ................................................................ PASSED");
    else { printf("  Modular correction tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Montgomery multiplication, modulo the order of a curve 
    passed = TRUE;
    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(a, PCurve->order); random384_test(b, PCurve->order); random384_test(c, PCurve->order);

        toMontgomery_mod_order384(a, d, PCurve);                                                                 // Conversion to/from Montgomery
        fromMontgomery_mod_order384(d, e, PCurve);
        if (fpcompare384(a, e) != 0) { passed = FALSE; break; }

        Montgomery_multiply_mod_order384(a, b, d, PCurve); Montgomery_multiply_mod_order384(d, c, e, PCurve);    // e = (a*b)*c
        Montgomery_multiply_mod_order384(b, c, d, PCurve); Montgomery_multiply_mod_order384(d, a, f, PCurve);    // f = a*(b*c)
        if (fpcompare384(e, f) != 0) { passed = FALSE; break; }

        addition_mod_order(b, c, d, PCurve); Montgomery_multiply_mod_order384(a, d, e, PCurve);                                                       // e = a*(b+c)
        Montgomery_multiply_mod_order384(a, b, d, PCurve); Montgomery_multiply_mod_order384(a, c, f, PCurve); addition_mod_order(d, f, f, PCurve);    // f = a*b+a*c
        if (fpcompare384(e, f) != 0) { passed = FALSE; break; }

        Montgomery_multiply_mod_order384(a, b, d, PCurve);                                                       // d = a*b 
        Montgomery_multiply_mod_order384(b, a, e, PCurve);                                                       // e = b*a 
        if (fpcompare384(d, e) != 0) { passed = FALSE; break; }

        fpzero384(b); b[0] = 1;
        toMontgomery_mod_order384(b, b, PCurve);
        Montgomery_multiply_mod_order384(a, b, d, PCurve);                                                       // d = a*1 
        if (fpcompare384(a, d) != 0) { passed = FALSE; break; }

        fpzero384(b);
        Montgomery_multiply_mod_order384(a, b, d, PCurve);                                                       // d = a*0 
        if (fpcompare384(b, d) != 0) { passed = FALSE; break; }
    }
    if (passed==TRUE) printf("  Montgomery multiplication and conversion tests .......................................... PASSED");
    else { printf("  Montgomery multiplication and conversion tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Montgomery inversion, modulo the order of a curve 
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random384_test(a, PCurve->order); random384_test(b, PCurve->order); random384_test(c, PCurve->order);   

        fpzero384(d); d[0]=1; 
        toMontgomery_mod_order384(d, d, PCurve);
        fpcopy384(a, b);                            
        Montgomery_inversion_mod_order384(a, a, PCurve);                                
        Montgomery_multiply_mod_order384(a, b, c, PCurve);                                      // c = a*a^-1 
        if (fpcompare384(c,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Montgomery inversion tests............................................................... PASSED");
    else { printf("  Montgomery inversion tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

cleanup:
    if (passed == FALSE) {
        Status = ECCRYPTO_ERROR_DURING_TEST;
    }
    ecc_curve_free(PCurve);
    
    return Status;
}

#endif


#ifdef ECCURVES_512

ECCRYPTO_STATUS fp_test512(PCurveStaticData CurveData)
{ // Tests of field arithmetic over GF(2^512-569)
    BOOL passed = TRUE;
    dig n;
    dig512 a, b, c, d, e, f, p;
    PCurveStruct PCurve = { 0 };
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    if (CurveData->Curve == numsp512d1) printf("Field arithmetic over GF(2^512-569), curve numsp512d1: \n\n");
    if (CurveData->Curve == numsp512t1) printf("Field arithmetic over GF(2^512-569), curve numsp512t1: \n\n");

    // Curve initialization
    PCurve = ecc_curve_allocate(CurveData);
    if (PCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(PCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    fp_prime512(p, PCurve);

    // Fp addition with p = 2^512-569
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); random512_test(f, PCurve->prime); 

        fpadd512(a, b, d); fpadd512(d, c, e);                  // e = (a+b)+c
        fpadd512(b, c, d); fpadd512(d, a, f);                  // f = a+(b+c)
        if (fpcompare512(e,f)!=0) { passed=FALSE; break; }

        fpadd512(a, b, d);                                     // d = a+b 
        fpadd512(b, a, e);                                     // e = b+a
        if (fpcompare512(d,e)!=0) { passed=FALSE; break; }

        fpzero512(b);
        fpadd512(a, b, d);                                     // d = a+0 
        if (fpcompare512(a,d)!=0) { passed=FALSE; break; }
        
        fpzero512(b);
        fpcopy512(a, d);     
        fpneg512(PCurve->prime, d);                      
        fpadd512(a, d, e);                                     // e = a+(-a)
        if (fpcompare512(e,b)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Addition tests (associativity, commutativity, identity, inverse)......................... PASSED");
    else { printf("Addition tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fp subtraction with p = 2^512-569
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {        
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); 

        fpsub512(a, b, d);                                    // d = a-b 
        fpsub512(b, a, e);                                    // e = b-a     
        fpneg512(PCurve->prime, e);     
        if (fpcompare512(d,e)!=0) { passed=FALSE; break; }

        fpzero512(b);
        fpsub512(a, b, d);                                    // d = a-0 
        if (fpcompare512(a,d)!=0) { passed=FALSE; break; }
                 
        fpsub512(a, a, d);                                    // e = a-(a)
        if (fp_iszero512(d) == FALSE) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Subtraction tests (anti-commutativity, identity, inverse)................................ PASSED");
    else { printf("  Subtraction tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fp division by 2 with p = 2^512-569
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {        
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); 

        fpdiv2_512(a, c);                                  // c = a/2
        fpadd512(c, c, b);                                 // b = a 
        if (fpcompare512(a,b)!=0) { passed=FALSE; break; }
        
        fpdiv2_512(a, c);                                  // c = a/2
        fpzero512(b); b[0] = 2;
        fpmul512(c, b, d);                                 // d = a 
        if (fpcompare512(a,d)!=0) { passed=FALSE; break; }
        
        fpzero512(b);
        fpdiv2_512(b, c);                                  // 0 
        if (fpcompare512(c,b)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Division by 2 tests ..................................................................... PASSED");
    else { printf("  Division by 2 tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Fp negation with p = 2^512-569
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {        
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); 

        fpcopy512(a, c);
        fpneg512(PCurve->prime, a);                        // -a 
        fpneg512(PCurve->prime, a);                        // -(-a) 
        if (fpcompare512(a,c)!=0) { passed=FALSE; break; }

        fpsub512(a, b, c);                                 // c = a-b 
        fpneg512(PCurve->prime, b);                        // -b 
        fpadd512(a, b, d);                                 // d = a+(-b) 
        if (fpcompare512(c,d)!=0) { passed=FALSE; break; }

        fpzero512(b);
        fpneg512(PCurve->prime, b);                        // -0 
        if (fpcompare512(p,b)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Negation tests .......................................................................... PASSED");
    else { printf("  Negation tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Fp multiplication with p = 2^512-569
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {    
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); random512_test(f, PCurve->prime);

        fpmul512(a, b, d); fpmul512(d, c, e);                     // e = (a*b)*c
        fpmul512(b, c, d); fpmul512(d, a, f);                     // f = a*(b*c)
        if (fpcompare512(e,f)!=0) { passed=FALSE; break; }

        fpadd512(b, c, d); fpmul512(a, d, e);                     // e = a*(b+c)
        fpmul512(a, b, d); fpmul512(a, c, f); fpadd512(d, f, f);  // f = a*b+a*c
        if (fpcompare512(e,f)!=0) { passed=FALSE; break; }

        fpmul512(a, b, d);                                        // d = a*b 
        fpmul512(b, a, e);                                        // e = b*a 
        if (fpcompare512(d,e)!=0) { passed=FALSE; break; }
        
        fpzero512(b); b[0] = 1;
        fpmul512(a, b, d);                                        // d = a*1 
        if (fpcompare512(a,d)!=0) { passed=FALSE; break; }

        fpzero512(b);
        fpmul512(a, b, d);                                        // d = a*0 
        if (fpcompare512(b,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Multiplication tests (associativity, distributive, commutativity, identity, null)........ PASSED");
    else { printf("  Multiplication tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
    
    // Fp squaring with p = 2^512-569
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); 

        fpsqr512(a, b);                                            // b = a^2
        fpmul512(a, a, c);                                         // c = a*a 
        if (fpcompare512(b,c)!=0) { passed=FALSE; break; }
        
        fpzero512(a);
        fpsqr512(a, d);                                            // d = 0^2 
        if (fpcompare512(a,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Squaring tests........................................................................... PASSED");
    else { printf("  Squaring tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");
        
    // Fp inversion with p = 2^512-569
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime);   
                
        fpzero512(d); d[0]=1;  
        fpcopy512(a, b);                            
        fpinv512(a);                                
        fpmul512(a, b, c);                                        // c = a*a^-1 
        if (fpcompare512(c,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Inversion tests.......................................................................... PASSED");
    else { printf("  Inversion tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    printf("\nOther functions: \n\n");

    // Modular addition, modulo the order of a curve
    passed = TRUE;
    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(a, PCurve->order); random512_test(b, PCurve->order); random512_test(c, PCurve->order);

        addition_mod_order(a, b, d, PCurve); addition_mod_order(d, c, e, PCurve);    // e = (a+b)+c
        addition_mod_order(b, c, d, PCurve); addition_mod_order(d, a, f, PCurve);    // f = a+(b+c)
        if (fpcompare512(e, f) != 0) { passed = FALSE; break; }

        addition_mod_order(a, b, d, PCurve);                                         // d = a+b 
        addition_mod_order(b, a, e, PCurve);                                         // e = b+a
        if (fpcompare512(d, e) != 0) { passed = FALSE; break; }

        fpzero512(b);
        addition_mod_order(a, b, d, PCurve);                                         // d = a+0 
        if (fpcompare512(a, d) != 0) { passed = FALSE; break; }
    }
    if (passed==TRUE) printf("  Modular addition tests .................................................................. PASSED");
    else { printf("  Modular addition tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Modular correction, modulo the order of a curve
    passed = TRUE;
    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        fpcopy512(PCurve->prime, a);
        a[0] = a[0] & ((dig)-1 << 1);                                               // a = p-1 
        correction_mod_order(a, c, PCurve);                                         // p-1 (mod r) 
        if (fpcompare512(c, PCurve->order) != -1) { passed = FALSE; break; }

        fpzero512(b);
        correction_mod_order(b, d, PCurve);                                         // 0 (mod r) 
        if (fpcompare256(b, d) != 0) { passed = FALSE; break; }

        fpzero512(b);
        correction_mod_order(PCurve->order, d, PCurve);                             // r (mod r) 
        if (fpcompare256(b, d) != 0) { passed = FALSE; break; }
    }
    if (passed==TRUE) printf("  Modular correction tests ................................................................ PASSED");
    else { printf("  Modular correction tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Montgomery multiplication, modulo the order of a curve 
    passed = TRUE;
    for (n = 0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(a, PCurve->order); random512_test(b, PCurve->order); random512_test(c, PCurve->order);

        toMontgomery_mod_order512(a, d, PCurve);                                                                 // Conversion to/from Montgomery
        fromMontgomery_mod_order512(d, e, PCurve);
        if (fpcompare512(a, e) != 0) { passed = FALSE; break; }

        Montgomery_multiply_mod_order512(a, b, d, PCurve); Montgomery_multiply_mod_order512(d, c, e, PCurve);    // e = (a*b)*c
        Montgomery_multiply_mod_order512(b, c, d, PCurve); Montgomery_multiply_mod_order512(d, a, f, PCurve);    // f = a*(b*c)
        if (fpcompare512(e, f) != 0) { passed = FALSE; break; }

        addition_mod_order(b, c, d, PCurve); Montgomery_multiply_mod_order512(a, d, e, PCurve);                                                       // e = a*(b+c)
        Montgomery_multiply_mod_order512(a, b, d, PCurve); Montgomery_multiply_mod_order512(a, c, f, PCurve); addition_mod_order(d, f, f, PCurve);    // f = a*b+a*c
        if (fpcompare512(e, f) != 0) { passed = FALSE; break; }

        Montgomery_multiply_mod_order512(a, b, d, PCurve);                                                       // d = a*b 
        Montgomery_multiply_mod_order512(b, a, e, PCurve);                                                       // e = b*a 
        if (fpcompare512(d, e) != 0) { passed = FALSE; break; }

        fpzero512(b); b[0] = 1;
        toMontgomery_mod_order512(b, b, PCurve);
        Montgomery_multiply_mod_order512(a, b, d, PCurve);                                                       // d = a*1 
        if (fpcompare512(a, d) != 0) { passed = FALSE; break; }

        fpzero512(b);
        Montgomery_multiply_mod_order512(a, b, d, PCurve);                                                       // d = a*0 
        if (fpcompare512(b, d) != 0) { passed = FALSE; break; }
    }
    if (passed==TRUE) printf("  Montgomery multiplication and conversion tests .......................................... PASSED");
    else { printf("  Montgomery multiplication and conversion tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

    // Montgomery inversion, modulo the order of a curve 
    passed = TRUE;
    for (n=0; n<ML_TEST_LOOPS; n++)
    {
        random512_test(a, PCurve->order); random512_test(b, PCurve->order); random512_test(c, PCurve->order);   

        fpzero512(d); d[0]=1; 
        toMontgomery_mod_order512(d, d, PCurve);
        fpcopy512(a, b);                            
        Montgomery_inversion_mod_order512(a, a, PCurve);                                
        Montgomery_multiply_mod_order512(a, b, c, PCurve);                                      // c = a*a^-1 
        if (fpcompare512(c,d)!=0) { passed=FALSE; break; }
    }
    if (passed==TRUE) printf("  Montgomery inversion tests............................................................... PASSED");
    else { printf("  Montgomery inversion tests... FAILED"); printf("\n"); goto cleanup; }
    printf("\n");

cleanup:
    if (passed == FALSE) {
        Status = ECCRYPTO_ERROR_DURING_TEST;
    }
    ecc_curve_free(PCurve);
    
    return Status;
}

#endif


#ifdef ECCURVES_256

ECCRYPTO_STATUS fp_run256(PCurveStaticData CurveData)
{ // Benchmarking of field arithmetic over GF(2^256-189)
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    dig n;
    unsigned long long cycles, cycles1, cycles2;
    dig256 a, b, c, d, e, f, p;
    PCurveStruct PCurve = {0};

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif

    printf("\n\nBENCHMARKING \n");
    printf("--------------------------------------------------------------------------------------------------------\n\n");
    printf("Field arithmetic over GF(2^256-189): \n\n");

    // Curve initialization
    PCurve = ecc_curve_allocate(CurveData);
    if (PCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(PCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    fp_prime256(p, PCurve);

    // Fp addition with p = 2^256-189
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); random256_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpadd256(a, b, c);
        fpadd256(d, e, f);
        fpadd256(b, c, d);
        fpadd256(e, f, a);
        fpadd256(c, d, e);
        fpadd256(f, a, b);
        fpadd256(d, e, f);
        fpadd256(a, b, c);
        fpadd256(e, f, a);
        fpadd256(b, c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n"); 

    // Fp subtraction with p = 2^256-189
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); random256_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpsub256(a, b, c);
        fpsub256(d, e, f);
        fpsub256(b, c, d);
        fpsub256(e, f, a);
        fpsub256(c, d, e);
        fpsub256(f, a, b);
        fpsub256(d, e, f);
        fpsub256(a, b, c);
        fpsub256(e, f, a);
        fpsub256(b, c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Subtraction", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp division by 2 with p = 2^256-189
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); random256_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpdiv2_256(a, b);
        fpdiv2_256(c, d);
        fpdiv2_256(e, f);
        fpdiv2_256(b, c);
        fpdiv2_256(d, e);
        fpdiv2_256(f, a);
        fpdiv2_256(c, d);
        fpdiv2_256(e, f);
        fpdiv2_256(a, b);
        fpdiv2_256(c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Division by 2", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp negation with p = 2^256-189
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); random256_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpneg256(PCurve->prime, a);
        fpneg256(PCurve->prime, b);
        fpneg256(PCurve->prime, c);
        fpneg256(PCurve->prime, d);
        fpneg256(PCurve->prime, e);
        fpneg256(PCurve->prime, f);
        fpneg256(PCurve->prime, a);
        fpneg256(PCurve->prime, b);
        fpneg256(PCurve->prime, c);
        fpneg256(PCurve->prime, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Negation", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp squaring with p = 2^256-189
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); random256_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpsqr256(a, b);
        fpsqr256(c, d);
        fpsqr256(e, f);
        fpsqr256(b, c);
        fpsqr256(d, e);
        fpsqr256(f, a);
        fpsqr256(c, d);
        fpsqr256(e, f);
        fpsqr256(a, c);
        fpsqr256(d, e);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Squaring", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp multiplication with p = 2^256-189
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); random256_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpmul256(a, b, c);
        fpmul256(d, e, f);
        fpmul256(b, c, d);
        fpmul256(e, f, a);
        fpmul256(c, d, e);
        fpmul256(f, a, b);
        fpmul256(d, e, f);
        fpmul256(a, b, c);
        fpmul256(e, f, a);
        fpmul256(b, c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Multiplication", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp inversion with p = 2^256-189
    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random256_test(a, PCurve->prime); random256_test(b, PCurve->prime); random256_test(c, PCurve->prime); random256_test(d, PCurve->prime); random256_test(e, PCurve->prime); random256_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpinv256(a);
        fpinv256(b);
        fpinv256(c);
        fpinv256(d);
        fpinv256(e);
        fpinv256(f);
        fpinv256(a);
        fpinv256(b);
        fpinv256(c);
        fpinv256(d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Inversion", cycles, ML_SHORT_BENCH_LOOPS*10);
    printf("\n");

    printf("\nOther functions: \n\n");

    // Modular addition modulo the order of a curve
    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        random256_test(a, PCurve->order); random256_test(b, PCurve->order); random256_test(c, PCurve->order); random256_test(d, PCurve->order); random256_test(e, PCurve->order); random256_test(f, PCurve->order);

        cycles1 = cpucycles();
        addition_mod_order(a, b, c, PCurve);
        addition_mod_order(d, e, f, PCurve);
        addition_mod_order(b, c, d, PCurve);
        addition_mod_order(e, f, a, PCurve);
        addition_mod_order(c, d, e, PCurve);
        addition_mod_order(f, a, b, PCurve);
        addition_mod_order(d, e, f, PCurve);
        addition_mod_order(a, b, c, PCurve);
        addition_mod_order(e, f, a, PCurve);
        addition_mod_order(b, c, d, PCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Modular addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Montgomery multiplication modulo the order of a curve
    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        random256_test(a, PCurve->order); random256_test(b, PCurve->order); random256_test(c, PCurve->order); random256_test(d, PCurve->order); random256_test(e, PCurve->order); random256_test(f, PCurve->order);

        cycles1 = cpucycles();
        Montgomery_multiply_mod_order256(a, b, c, PCurve);
        Montgomery_multiply_mod_order256(d, e, f, PCurve);
        Montgomery_multiply_mod_order256(b, c, d, PCurve);
        Montgomery_multiply_mod_order256(e, f, a, PCurve);
        Montgomery_multiply_mod_order256(c, d, e, PCurve);
        Montgomery_multiply_mod_order256(f, a, b, PCurve);
        Montgomery_multiply_mod_order256(d, e, f, PCurve);
        Montgomery_multiply_mod_order256(a, b, c, PCurve);
        Montgomery_multiply_mod_order256(e, f, a, PCurve);
        Montgomery_multiply_mod_order256(b, c, d, PCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Montgomery multiplication", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Montgomery inversion modulo the order of a curve
    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random256_test(a, PCurve->order); random256_test(b, PCurve->order); random256_test(c, PCurve->order); random256_test(d, PCurve->order); random256_test(e, PCurve->order); random256_test(f, PCurve->order); 

        cycles1 = cpucycles();
        Montgomery_inversion_mod_order256(a, a, PCurve);
        Montgomery_inversion_mod_order256(b, b, PCurve);
        Montgomery_inversion_mod_order256(c, c, PCurve);
        Montgomery_inversion_mod_order256(d, d, PCurve);
        Montgomery_inversion_mod_order256(e, e, PCurve);
        Montgomery_inversion_mod_order256(f, f, PCurve);
        Montgomery_inversion_mod_order256(a, a, PCurve);
        Montgomery_inversion_mod_order256(b, b, PCurve);
        Montgomery_inversion_mod_order256(c, c, PCurve);
        Montgomery_inversion_mod_order256(d, d, PCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Montgomery inversion", cycles, ML_SHORT_BENCH_LOOPS*10);
    printf("\n");

cleanup:
    ecc_curve_free(PCurve);

    return Status;

}

#endif


#ifdef ECCURVES_384

ECCRYPTO_STATUS fp_run384(PCurveStaticData CurveData)
{ // Benchmarking of field arithmetic over GF(2^384-317)
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    dig n;
    unsigned long long cycles, cycles1, cycles2;
    dig384 a, b, c, d, e, f, p;
    PCurveStruct PCurve = {0};

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Field arithmetic over GF(2^384-317): \n\n");

    // Curve initialization
    PCurve = ecc_curve_allocate(CurveData);
    if (PCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(PCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    fp_prime384(p, PCurve);

    // Fp addition with p = 2^384-317
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); random384_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpadd384(a, b, c);
        fpadd384(d, e, f);
        fpadd384(b, c, d);
        fpadd384(e, f, a);
        fpadd384(c, d, e);
        fpadd384(f, a, b);
        fpadd384(d, e, f);
        fpadd384(a, b, c);
        fpadd384(e, f, a);
        fpadd384(b, c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n"); 

    // Fp subtraction with p = 2^384-317
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); random384_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpsub384(a, b, c);
        fpsub384(d, e, f);
        fpsub384(b, c, d);
        fpsub384(e, f, a);
        fpsub384(c, d, e);
        fpsub384(f, a, b);
        fpsub384(d, e, f);
        fpsub384(a, b, c);
        fpsub384(e, f, a);
        fpsub384(b, c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Subtraction", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp division by 2 with p = 2^384-317
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); random384_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpdiv2_384(a, b);
        fpdiv2_384(c, d);
        fpdiv2_384(e, f);
        fpdiv2_384(b, c);
        fpdiv2_384(d, e);
        fpdiv2_384(f, a);
        fpdiv2_384(c, d);
        fpdiv2_384(e, f);
        fpdiv2_384(a, b);
        fpdiv2_384(c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Division by 2", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp negation with p = 2^384-317
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); random384_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpneg384(PCurve->prime, a);
        fpneg384(PCurve->prime, b);
        fpneg384(PCurve->prime, c);
        fpneg384(PCurve->prime, d);
        fpneg384(PCurve->prime, e);
        fpneg384(PCurve->prime, f);
        fpneg384(PCurve->prime, a);
        fpneg384(PCurve->prime, b);
        fpneg384(PCurve->prime, c);
        fpneg384(PCurve->prime, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Negation", cycles, ML_BENCH_LOOPS*10);
    printf("\n");
    
    // Fp squaring with p = 2^384-317
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); random384_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpsqr384(a, b);
        fpsqr384(c, d);
        fpsqr384(e, f);
        fpsqr384(b, c);
        fpsqr384(d, e);
        fpsqr384(f, a);
        fpsqr384(c, d);
        fpsqr384(e, f);
        fpsqr384(a, c);
        fpsqr384(d, e);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Squaring", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp multiplication with p = 2^384-317
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); random384_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpmul384(a, b, c);
        fpmul384(d, e, f);
        fpmul384(b, c, d);
        fpmul384(e, f, a);
        fpmul384(c, d, e);
        fpmul384(f, a, b);
        fpmul384(d, e, f);
        fpmul384(a, b, c);
        fpmul384(e, f, a);
        fpmul384(b, c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Multiplication", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp inversion with p = 2^384-317
    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random384_test(a, PCurve->prime); random384_test(b, PCurve->prime); random384_test(c, PCurve->prime); random384_test(d, PCurve->prime); random384_test(e, PCurve->prime); random384_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpinv384(a);
        fpinv384(b);
        fpinv384(c);
        fpinv384(d);
        fpinv384(e);
        fpinv384(f);
        fpinv384(a);
        fpinv384(b);
        fpinv384(c);
        fpinv384(d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Inversion", cycles, ML_SHORT_BENCH_LOOPS*10);
    printf("\n");

    printf("\nOther functions: \n\n");

    // Modular addition modulo the order of a curve
    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        random384_test(a, PCurve->order); random384_test(b, PCurve->order); random384_test(c, PCurve->order); random384_test(d, PCurve->order); random384_test(e, PCurve->order); random384_test(f, PCurve->order);

        cycles1 = cpucycles();
        addition_mod_order(a, b, c, PCurve);
        addition_mod_order(d, e, f, PCurve);
        addition_mod_order(b, c, d, PCurve);
        addition_mod_order(e, f, a, PCurve);
        addition_mod_order(c, d, e, PCurve);
        addition_mod_order(f, a, b, PCurve);
        addition_mod_order(d, e, f, PCurve);
        addition_mod_order(a, b, c, PCurve);
        addition_mod_order(e, f, a, PCurve);
        addition_mod_order(b, c, d, PCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Modular addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Montgomery multiplication modulo the order of a curve
    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        random384_test(a, PCurve->order); random384_test(b, PCurve->order); random384_test(c, PCurve->order); random384_test(d, PCurve->order); random384_test(e, PCurve->order); random384_test(f, PCurve->order);

        cycles1 = cpucycles();
        Montgomery_multiply_mod_order384(a, b, c, PCurve);
        Montgomery_multiply_mod_order384(d, e, f, PCurve);
        Montgomery_multiply_mod_order384(b, c, d, PCurve);
        Montgomery_multiply_mod_order384(e, f, a, PCurve);
        Montgomery_multiply_mod_order384(c, d, e, PCurve);
        Montgomery_multiply_mod_order384(f, a, b, PCurve);
        Montgomery_multiply_mod_order384(d, e, f, PCurve);
        Montgomery_multiply_mod_order384(a, b, c, PCurve);
        Montgomery_multiply_mod_order384(e, f, a, PCurve);
        Montgomery_multiply_mod_order384(b, c, d, PCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Montgomery multiplication", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Montgomery inversion modulo the order of a curve
    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random384_test(a, PCurve->order); random384_test(b, PCurve->order); random384_test(c, PCurve->order); random384_test(d, PCurve->order); random384_test(e, PCurve->order); random384_test(f, PCurve->order); 

        cycles1 = cpucycles();
        Montgomery_inversion_mod_order384(a, a, PCurve);
        Montgomery_inversion_mod_order384(b, b, PCurve);
        Montgomery_inversion_mod_order384(c, c, PCurve);
        Montgomery_inversion_mod_order384(d, d, PCurve);
        Montgomery_inversion_mod_order384(e, e, PCurve);
        Montgomery_inversion_mod_order384(f, f, PCurve);
        Montgomery_inversion_mod_order384(a, a, PCurve);
        Montgomery_inversion_mod_order384(b, b, PCurve);
        Montgomery_inversion_mod_order384(c, c, PCurve);
        Montgomery_inversion_mod_order384(d, d, PCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Montgomery inversion", cycles, ML_SHORT_BENCH_LOOPS*10);
    printf("\n");

cleanup:
    ecc_curve_free(PCurve);
    
    return Status;
}

#endif


#ifdef ECCURVES_512

ECCRYPTO_STATUS fp_run512(PCurveStaticData CurveData)
{ // Benchmarking of field arithmetic over GF(2^512-569)
    ECCRYPTO_STATUS Status = ECCRYPTO_SUCCESS;
    dig n;
    unsigned long long cycles, cycles1, cycles2;
    dig512 a, b, c, d, e, f, p;
    PCurveStruct PCurve = {0};

#if OS_TARGET == OS_WIN
    SetThreadAffinityMask(GetCurrentThread(), 1);       // All threads are set to run in the same node
    SetThreadPriority(GetCurrentThread(), 2);           // Set to highest priority
#endif

    printf("\n--------------------------------------------------------------------------------------------------------\n\n");
    printf("Field arithmetic over GF(2^512-569): \n\n");

    // Curve initialization
    PCurve = ecc_curve_allocate(CurveData);
    if (PCurve == NULL) {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = ecc_curve_initialize(PCurve, MEM_LARGE, NULL, CurveData);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
    fp_prime512(p, PCurve);

    // Fp addition with p = 2^512-569
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); random512_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpadd512(a, b, c);
        fpadd512(d, e, f);
        fpadd512(b, c, d);
        fpadd512(e, f, a);
        fpadd512(c, d, e);
        fpadd512(f, a, b);
        fpadd512(d, e, f);
        fpadd512(a, b, c);
        fpadd512(e, f, a);
        fpadd512(b, c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n"); 

    // Fp subtraction with p = 2^512-569
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); random512_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpsub512(a, b, c);
        fpsub512(d, e, f);
        fpsub512(b, c, d);
        fpsub512(e, f, a);
        fpsub512(c, d, e);
        fpsub512(f, a, b);
        fpsub512(d, e, f);
        fpsub512(a, b, c);
        fpsub512(e, f, a);
        fpsub512(b, c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Subtraction", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp division by 2 with p = 2^512-569
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); random512_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpdiv2_512(a, b);
        fpdiv2_512(c, d);
        fpdiv2_512(e, f);
        fpdiv2_512(b, c);
        fpdiv2_512(d, e);
        fpdiv2_512(f, a);
        fpdiv2_512(c, d);
        fpdiv2_512(e, f);
        fpdiv2_512(a, b);
        fpdiv2_512(c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Division by 2", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp negation with p = 2^512-569
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); random512_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpneg512(PCurve->prime, a);
        fpneg512(PCurve->prime, b);
        fpneg512(PCurve->prime, c);
        fpneg512(PCurve->prime, d);
        fpneg512(PCurve->prime, e);
        fpneg512(PCurve->prime, f);
        fpneg512(PCurve->prime, a);
        fpneg512(PCurve->prime, b);
        fpneg512(PCurve->prime, c);
        fpneg512(PCurve->prime, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Negation", cycles, ML_BENCH_LOOPS*10);
    printf("\n");
    
    // Fp squaring with p = 2^512-569
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); random512_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpsqr512(a, b);
        fpsqr512(c, d);
        fpsqr512(e, f);
        fpsqr512(b, c);
        fpsqr512(d, e);
        fpsqr512(f, a);
        fpsqr512(c, d);
        fpsqr512(e, f);
        fpsqr512(a, c);
        fpsqr512(d, e);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Squaring", cycles, ML_BENCH_LOOPS*10);
    printf("\n");
    
    // Fp multiplication with p = 2^512-569
    cycles = 0;
    for (n=0; n<ML_BENCH_LOOPS; n++)
    {
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); random512_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpmul512(a, b, c);
        fpmul512(d, e, f);
        fpmul512(b, c, d);
        fpmul512(e, f, a);
        fpmul512(c, d, e);
        fpmul512(f, a, b);
        fpmul512(d, e, f);
        fpmul512(a, b, c);
        fpmul512(e, f, a);
        fpmul512(b, c, d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Multiplication", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Fp inversion with p = 2^512-569
    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random512_test(a, PCurve->prime); random512_test(b, PCurve->prime); random512_test(c, PCurve->prime); random512_test(d, PCurve->prime); random512_test(e, PCurve->prime); random512_test(f, PCurve->prime); 

        cycles1 = cpucycles();
        fpinv512(a);
        fpinv512(b);
        fpinv512(c);
        fpinv512(d);
        fpinv512(e);
        fpinv512(f);
        fpinv512(a);
        fpinv512(b);
        fpinv512(c);
        fpinv512(d);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Inversion", cycles, ML_SHORT_BENCH_LOOPS*10);
    printf("\n");

    printf("\nOther functions: \n\n");

    // Modular addition modulo the order of a curve
    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        random512_test(a, PCurve->order); random512_test(b, PCurve->order); random512_test(c, PCurve->order); random512_test(d, PCurve->order); random512_test(e, PCurve->order); random512_test(f, PCurve->order);

        cycles1 = cpucycles();
        addition_mod_order(a, b, c, PCurve);
        addition_mod_order(d, e, f, PCurve);
        addition_mod_order(b, c, d, PCurve);
        addition_mod_order(e, f, a, PCurve);
        addition_mod_order(c, d, e, PCurve);
        addition_mod_order(f, a, b, PCurve);
        addition_mod_order(d, e, f, PCurve);
        addition_mod_order(a, b, c, PCurve);
        addition_mod_order(e, f, a, PCurve);
        addition_mod_order(b, c, d, PCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Modular addition", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Montgomery multiplication modulo the order of a curve
    cycles = 0;
    for (n = 0; n<ML_BENCH_LOOPS; n++)
    {
        random512_test(a, PCurve->order); random512_test(b, PCurve->order); random512_test(c, PCurve->order); random512_test(d, PCurve->order); random512_test(e, PCurve->order); random512_test(f, PCurve->order);

        cycles1 = cpucycles();
        Montgomery_multiply_mod_order512(a, b, c, PCurve);
        Montgomery_multiply_mod_order512(d, e, f, PCurve);
        Montgomery_multiply_mod_order512(b, c, d, PCurve);
        Montgomery_multiply_mod_order512(e, f, a, PCurve);
        Montgomery_multiply_mod_order512(c, d, e, PCurve);
        Montgomery_multiply_mod_order512(f, a, b, PCurve);
        Montgomery_multiply_mod_order512(d, e, f, PCurve);
        Montgomery_multiply_mod_order512(a, b, c, PCurve);
        Montgomery_multiply_mod_order512(e, f, a, PCurve);
        Montgomery_multiply_mod_order512(b, c, d, PCurve);
        cycles2 = cpucycles();
        cycles = cycles + (cycles2 - cycles1);
    }
    bench_print("Montgomery multiplication", cycles, ML_BENCH_LOOPS*10);
    printf("\n");

    // Montgomery inversion modulo the order of a curve
    cycles = 0;
    for (n=0; n<ML_SHORT_BENCH_LOOPS; n++)
    {
        random512_test(a, PCurve->order); random512_test(b, PCurve->order); random512_test(c, PCurve->order); random512_test(d, PCurve->order); random512_test(e, PCurve->order); random512_test(f, PCurve->order); 

        cycles1 = cpucycles();
        Montgomery_inversion_mod_order512(a, a, PCurve);
        Montgomery_inversion_mod_order512(b, b, PCurve);
        Montgomery_inversion_mod_order512(c, c, PCurve);
        Montgomery_inversion_mod_order512(d, d, PCurve);
        Montgomery_inversion_mod_order512(e, e, PCurve);
        Montgomery_inversion_mod_order512(f, f, PCurve);
        Montgomery_inversion_mod_order512(a, a, PCurve);
        Montgomery_inversion_mod_order512(b, b, PCurve);
        Montgomery_inversion_mod_order512(c, c, PCurve);
        Montgomery_inversion_mod_order512(d, d, PCurve);
        cycles2 = cpucycles();
        cycles = cycles+(cycles2-cycles1);
    }
    bench_print("Montgomery inversion", cycles, ML_SHORT_BENCH_LOOPS*10);
    printf("\n");

cleanup:
    ecc_curve_free(PCurve);
    
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
    Status = fp_test256(&curve_numsp256d1);      // Test field operations with p = 2^256-189, numsp256d1
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
    Status = fp_test256(&curve_numsp256t1);      // Test field operations with p = 2^256-189, numsp256t1
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif
#ifdef ECCURVES_384
    Status = fp_test384(&curve_numsp384d1);      // Test field operations with p = 2^384-317, numsp384d1
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
    Status = fp_test384(&curve_numsp384t1);      // Test field operations with p = 2^384-317, numsp384t1
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif
#ifdef ECCURVES_512
    Status = fp_test512(&curve_numsp512d1);      // Test field operations with p = 2^512-569, numsp512d1
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
    Status = fp_test512(&curve_numsp512t1);      // Test field operations with p = 2^512-569, numsp512t1
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif

#ifdef ECCURVES_256
    Status = fp_run256(&curve_numsp256d1);       // Benchmark field operations with p = 2^256-189
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif
#ifdef ECCURVES_384
    Status = fp_run384(&curve_numsp384d1);       // Benchmark field operations with p = 2^384-317
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif
#ifdef ECCURVES_512
    Status = fp_run512(&curve_numsp512d1);       // Benchmark field operations with p = 2^512-569
    if (Status != ECCRYPTO_SUCCESS) {
        printf("\n\n   Error detected: %s \n\n", ecc_get_error_message(Status));
        return FALSE;
    }
#endif
    
    return TRUE;
}