/*******************************************************************************
* MSR ECClib v2.0, an efficient and secure elliptic curve cryptographic library
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
* Abstract: cryptographic functions
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
******************************************************************************/  

#include <malloc.h>
#include "msr_ecclib.h"


/***************************************************************************************/
/******************** CRYPTO FUNCTIONS FOR WEIERSTRASS a=-3 CURVES *********************/

static ECCRYPTO_STATUS HashLeftmostExtraction(dig* HashMessage, unsigned int HashedMessageBitlength, unsigned int OrderBitlength)  
{ // Outputs the leftmost "rbits" of a hashed message following FIPS.186-4
  // It is required that HashedMessageBitlength >= OrderBitlength
    unsigned int i, ndigits = NBITS_TO_NWORDS(HashedMessageBitlength);
    int diff = HashedMessageBitlength - OrderBitlength;  

    if (diff < 0) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    while (diff >= ML_WORD) {
        for (i = 0; i < (ndigits-1); i++)
        {
            HashMessage[i] = HashMessage[i+1];
        }
        HashMessage[ndigits-1] = 0;
        diff -= ML_WORD;
    }
    if (diff > 0) {
        for (i = 0; i < (ndigits-1); i++)
        {
            HashMessage[i] = (HashMessage[i] >> diff);
            HashMessage[i] = (HashMessage[i] ^ (HashMessage[i+1] << (ML_WORD - diff)));
        }
        HashMessage[ndigits-1] = (HashMessage[ndigits-1] >> diff);
    } 

    return ECCRYPTO_SUCCESS;
}


ECCRYPTO_STATUS ECC_GENERATOR_TABLE_W(POINT_WAFF* pTableGen, PCurveStruct JacCurve)
{ // Computes precomputed table for the generator
  // This function can be used to speedup scalar multiplications with a fixed-base in ECDHE or ECDSA signing
  // It computes table pTableGen containing generator G and several of its multiples: 3*G, 5*G, ..., n*G
  // Curve, field and table parameters are passed through the curve structure JacCurve
  // JacCurve must be set up in advance using ecc_curve_initialize()
    POINT_WAFF P;  
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (pTableGen == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    ECCSET_W(P, JacCurve);                                   // Set generator
    Status = ECC_PRECOMP_FIXED_W(P, pTableGen, JacCurve);    // Compute table

    return Status;
}


ECCRYPTO_STATUS ECC_KEYGEN_W(BASE_ELM pPrivateKey, POINT_WAFF* pTableGen, POINT_WAFF pPublicKey, PCurveStruct JacCurve)
{ // Generation of a public key using the private key as input
  // It computes the public key pPublicKey = pPrivateKey*G, where G is the generator (G and its multiples are passed through pTableGen)
  // Curve, field and table parameters are passed through the curve structure JacCurve
  // JacCurve must be set up in advance using ecc_curve_initialize()
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (pPrivateKey == NULL || pTableGen == NULL || pPublicKey == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    Status = ECC_MUL_FIXED_W(pTableGen, pPrivateKey, pPublicKey, JacCurve);      // Compute public key
    if (Status != ECCRYPTO_SUCCESS) {
        ECCZERO_WAFF(pPublicKey);
    }

    return Status;
}


ECCRYPTO_STATUS ECC_FULL_KEYGEN_W(POINT_WAFF* pTableGen, BASE_ELM pPrivateKey, POINT_WAFF pPublicKey, PCurveStruct JacCurve)
{ // Key-pair generation
  // It produces a private key pPrivateKey and computes the public key pPublicKey = pPrivateKey*G, where G is the generator (G and its multiples are passed through pTableGen)
  // Curve, field and table parameters are passed through the curve structure JacCurve
  // JacCurve must be set up in advance using ecc_curve_initialize()
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;  

    if (pTableGen == NULL || pPrivateKey == NULL || pPublicKey == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }  

    Status = random_mod_order(pPrivateKey, JacCurve);
    if (Status != ECCRYPTO_SUCCESS) {
        FP_ZERO(pPrivateKey);
        return Status;
    }

    Status = ECC_KEYGEN_W(pPrivateKey, pTableGen, pPublicKey, JacCurve);
    if (Status != ECCRYPTO_SUCCESS) {
        ECCZERO_WAFF(pPublicKey);
    }
      
    return Status;
}


/***************** ECDH(E) FUNCTIONS FOR WEIERSTRASS a=-3 CURVES ******************/

ECCRYPTO_STATUS ECDH_SECRET_AGREEMENT_W(BASE_ELM pPrivateKey, POINT_WAFF pPublicKey, BASE_ELM pSecretAgreement, PCurveStruct JacCurve)
{ // Secret agreement computation for the ECDH(E) key exchange
  // It computes the shared secret key pSecretAgreement = X(pPrivateKey*pPublicKey), where X() denotes the x-coordinate of an EC point
  // Curve and field parameters are passed through the curve structure JacCurve. JacCurve must be set up in advance using ecc_curve_initialize()
    POINT_WAFF PointAgreement;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (pPrivateKey == NULL || pPublicKey == NULL || pSecretAgreement == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    Status = ECC_MUL_W(pPublicKey, pPrivateKey, PointAgreement, JacCurve);       // Compute secret agreement
    if (Status != ECCRYPTO_SUCCESS) {
        goto exit;
    }

    FP_COPY(PointAgreement->x, pSecretAgreement); 

exit:
    ECCZERO_WAFF(PointAgreement);
    return Status;
}


/****************** ECDSA FUNCTIONS FOR WEIERSTRASS a=-3 CURVES *******************/

ECCRYPTO_STATUS ECDSA_SIGN_W(BASE_ELM pPrivateKey, POINT_WAFF* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, BASE_ELM r, BASE_ELM s, PCurveStruct JacCurve)
{ // Wrapper for the ECDSA signature generation
  // It computes the signature (r,s) of a message m using as inputs a private key pPrivateKey, the generator table pTableGen, and the hash of a message HashedMessage with its byte-length
  // Curve and field parameters are passed through the curve structure JacCurve. JacCurve must be set up in advance using ecc_curve_initialize()
  // The set of valid values for the bitlength of HashedMessage is {256,384,512}
    BASE_ELM RandomNonce;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN; 

    if (pPrivateKey == NULL || pTableGen == NULL || HashedMessage == NULL || RandomNonce == NULL || r == NULL || s == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }   

    Status = random_mod_order(RandomNonce, JacCurve);
    if (Status != ECCRYPTO_SUCCESS) {
        FP_ZERO(RandomNonce);
        return Status;
    }

    return ECDSA_SIGN_INTERNAL_W(pPrivateKey, pTableGen, HashedMessage, SizeHashedMessage, RandomNonce, r, s, JacCurve);
}


ECCRYPTO_STATUS ECDSA_SIGN_INTERNAL_W(BASE_ELM pPrivateKey, POINT_WAFF* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, BASE_ELM RandomNonce, BASE_ELM r, BASE_ELM s, PCurveStruct JacCurve)
{ // Signature generation for ECDSA
  // It computes the signature (r,s) of a message m using as inputs a private key pPrivateKey, the generator table pTableGen, the hash of a message HashedMessage with its byte-length and a random nonce RandomNonce
  // Curve and field parameters are passed through the curve structure JacCurve. JacCurve must be set up in advance using ecc_curve_initialize()
  // The set of valid values for the bitlength of HashedMessage is {256,384,512}
    POINT_WAFF P;
    BASE_ELM DigitPrivateKey;
    dig DigitHashedMessage[MAXWORDS_FIELD];
    unsigned int i, nbits_hashedmessage = SizeHashedMessage*8;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (pPrivateKey == NULL || pTableGen == NULL || HashedMessage == NULL || RandomNonce == NULL || r == NULL || s == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    // Check if the bitlength of the hashed message is in the valid set
    if (nbits_hashedmessage != 256 && nbits_hashedmessage != 384 && nbits_hashedmessage != 512) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    copy((dig*)HashedMessage, DigitHashedMessage, nbits_hashedmessage/ML_WORD);

    // Is private key in [1,r-1]?                
    if ((FP_ISZERO(pPrivateKey) == TRUE) || (MOD_EVAL(pPrivateKey, JacCurve->order) == FALSE)) {
        Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    Status = ECC_MUL_FIXED_W(pTableGen, RandomNonce, P, JacCurve);                 // P = k*G
    if (Status != ECCRYPTO_SUCCESS) {
        goto exit;
    }

    if (!correction_mod_order(P->x, r, JacCurve)) {                                // r_sign = P->x (mod order)
        Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
        goto exit;
    }      
    if (FP_ISZERO(r) == TRUE) {                                                    // if r_sign = 0 then register error and return
        Status = ECCRYPTO_ERROR_INVALID_NONCE_FOR_SIGNING;
        goto exit;
    }

    // Pick the leftmost "rbits" for e
    Status = HashLeftmostExtraction(DigitHashedMessage, nbits_hashedmessage, JacCurve->rbits);
    if (Status != ECCRYPTO_SUCCESS) {
        return Status;
    }
    if (!correction_mod_order(DigitHashedMessage, DigitHashedMessage, JacCurve)) { // e = e (mod order)
        Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
        goto exit;
    }      

    // Conversion to Montgomery representation
    TO_MONTGOMERY_MOD_ORDER(pPrivateKey, DigitPrivateKey, JacCurve);
    TO_MONTGOMERY_MOD_ORDER(RandomNonce, RandomNonce, JacCurve);
    TO_MONTGOMERY_MOD_ORDER(DigitHashedMessage, DigitHashedMessage, JacCurve);
    TO_MONTGOMERY_MOD_ORDER(r, r, JacCurve);

    MONTGOMERY_MUL_MOD_ORDER(DigitPrivateKey, r, s, JacCurve);                     // Mont_s_sign = Mont(d*r_sign (mod order))
    addition_mod_order(DigitHashedMessage, s, s, JacCurve);                        // Mont_s_sign = Mont(e + d*r_sign (mod order))
    MONTGOMERY_INV_MOD_ORDER(RandomNonce, RandomNonce, JacCurve);                  // Mont_kinv   = Mont(k^(-1))
    MONTGOMERY_MUL_MOD_ORDER(s, RandomNonce, s, JacCurve);                         // Mont_s_sign = Mont(k^(-1)*(e + d*r_sign) (mod order))

    // Conversion from Montgomery to standard representation
    FROM_MONTGOMERY_MOD_ORDER(r, r, JacCurve);                                     // r_sign
    FROM_MONTGOMERY_MOD_ORDER(s, s, JacCurve);                                     // s_sign
    if (FP_ISZERO(s) == TRUE) {                                                    // if s_sign = 0 then register error and return
        Status = ECCRYPTO_ERROR_INVALID_NONCE_FOR_SIGNING;
    }

exit:
    ECCZERO_WAFF(P);
    FP_ZERO(DigitPrivateKey);
    FP_ZERO(RandomNonce);
    for (i = 0; i < MAXWORDS_FIELD; i++) {
        ((dig volatile*)DigitHashedMessage)[i] = 0;
    }

    if (Status != ECCRYPTO_SUCCESS) {
        FP_ZERO(r);
        FP_ZERO(s);
    }

    return Status;
}


ECCRYPTO_STATUS ECDSA_VERIFICATION_TABLE_W(POINT_WAFF* pTableVer, PCurveStruct JacCurve)
{ // Computes precomputed table for signature verification in ECDSA
  // It computes table pTableVer containing generator G and several of its multiples: 3*G, 5*G, ..., n*G
  // Curve, field and table parameters are passed through the curve structure JacCurve
  // JacCurve must be set up in advance using ecc_curve_initialize()
    POINT_WAFF P;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (pTableVer == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    ECCSET_W(P, JacCurve);                                    // Set generator
    Status = ECC_PRECOMP_DBLMUL_W(P, pTableVer, JacCurve);    // Compute table

    return Status;
}


ECCRYPTO_STATUS ECDSA_VERIFY_W(POINT_WAFF* pTableVer, POINT_WAFF pPublicKey, unsigned char* HashedMessage, unsigned int SizeHashedMessage, BASE_ELM r, BASE_ELM s, BOOL* valid, PCurveStruct JacCurve)
{ // Signature verification for ECDSA
  // It verifies the validity of the signature (r,s) of a message m using as inputs the generator table pTableVer, a public key pPublicKey and the hash of a message HashedMessage with its byte-length
  // If the signature is valid, then valid = TRUE, otherwise valid = FALSE
  // Curve and field parameters are passed through the curve structure JacCurve. JacCurve must be set up in advance using ecc_curve_initialize()
    POINT_WAFF R;
    BASE_ELM DigitR, DigitS, u1, u2, w;
    dig DigitHashedMessage[MAXWORDS_FIELD];
    unsigned int nbits_hashedmessage = SizeHashedMessage*8;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (valid != NULL) {    // Set signature invalid by default
        *valid = FALSE;        
    }
    if (pTableVer == NULL || pPublicKey == NULL || HashedMessage == NULL || r == NULL || s == NULL || valid == NULL || is_ecc_curve_null(JacCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    // Check if the bitlength of the hashed message is in the valid set
    if (nbits_hashedmessage != 256 && nbits_hashedmessage != 384 && nbits_hashedmessage != 512) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    copy((dig*)HashedMessage, DigitHashedMessage, nbits_hashedmessage/ML_WORD);

    // Is r_sign in [1,r-1]? if not, reject the signature               
    if ((FP_ISZERO(r) == TRUE) || (MOD_EVAL(r, JacCurve->order) == FALSE)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    // Is s_sign in [1,r-1]? if yes, reject the signature               
    if ((FP_ISZERO(s) == TRUE) || (MOD_EVAL(s, JacCurve->order) == FALSE)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    } 

    // Pick the leftmost "rbits" for e
    Status = HashLeftmostExtraction(DigitHashedMessage, nbits_hashedmessage, JacCurve->rbits);
    if (Status != ECCRYPTO_SUCCESS) {
        return Status;
    }
    if (!correction_mod_order(DigitHashedMessage, DigitHashedMessage, JacCurve)){    // e = e (mod order)
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }      
    
    // Conversion to Montgomery representation
    TO_MONTGOMERY_MOD_ORDER(DigitHashedMessage, DigitHashedMessage, JacCurve);
    TO_MONTGOMERY_MOD_ORDER(r, DigitR, JacCurve);
    TO_MONTGOMERY_MOD_ORDER(s, DigitS, JacCurve);
        
    MONTGOMERY_INV_MOD_ORDER(DigitS, w, JacCurve);                            // Mont_w  = Mont(s^(-1) mod order)
    MONTGOMERY_MUL_MOD_ORDER(DigitHashedMessage, w, u1, JacCurve);            // Mont_u1 = Mont(e*w (mod order))
    MONTGOMERY_MUL_MOD_ORDER(DigitR, w, u2, JacCurve);                        // Mont_u2 = Mont(r*w (mod order))

    // Conversion from Montgomery to standard representation
    FROM_MONTGOMERY_MOD_ORDER(u1, u1, JacCurve);                              // u1
    FROM_MONTGOMERY_MOD_ORDER(u2, u2, JacCurve);                              // u2
    FROM_MONTGOMERY_MOD_ORDER(DigitR, DigitR, JacCurve);                      // r_sign
    
    Status = ECC_DBLMUL_W(pTableVer, u1, pPublicKey, u2, R, JacCurve);        // R = u1*G + u2*Q 
    if (Status != ECCRYPTO_SUCCESS) {
        return Status;
    }
    if (ECC_IS_INFINITY_WAFF(R, JacCurve) == TRUE) {                          // If R = inf, then reject the signature
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (!correction_mod_order(R->x, R->x, JacCurve)) {                        // v = R->x (mod order) 
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }        
    *valid = compare_mod_order(DigitR, R->x, JacCurve);                       // if v = r_sign then valid = TRUE, otherwise valid = FALSE 

    return ECCRYPTO_SUCCESS;
}


/***************************************************************************************/
/****************** CRYPTO FUNCTIONS FOR TWISTED EDWARDS a=-1 CURVES *******************/

ECCRYPTO_STATUS ECC_GENERATOR_TABLE_TE(POINT_PRECOMP_EXTAFF_TE* pTableGen, PCurveStruct TedCurve)
{ // Computes precomputed table for the generator
  // This function can be used to speedup scalar multiplications with a fixed-base in ECDHE or ECDSA signing
  // It computes table pTableGen containing generator G and several of its multiples: 3*G, 5*G, ..., n*G 
  // Curve, field and table parameters are passed through the curve structure TedCurve
  // TedCurve must be set up in advance using ecc_curve_initialize()
    POINT_TE P;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (pTableGen == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    ECCSET_TE(P, TedCurve);                                   // Set generator
    Status = ECC_PRECOMP_FIXED_TE(P, pTableGen, TedCurve);    // Compute table

    return Status;
}


ECCRYPTO_STATUS ECC_KEYGEN_TE(BASE_ELM pPrivateKey, POINT_PRECOMP_EXTAFF_TE* pTableGen, POINT_TE pPublicKey, PCurveStruct TedCurve)
{ // Generation of a public key using the private key as input
  // It computes the public key pPublicKey = pPrivateKey*G, where G is the generator (G and its multiples are passed through pTableGen)
  // Curve, field and table parameters are passed through the curve structure TedCurve
  // TedCurve must be set up in advance using ecc_curve_initialize()
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (pPrivateKey == NULL || pTableGen == NULL || pPublicKey == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    Status = ECC_MUL_FIXED_TE(pTableGen, pPrivateKey, pPublicKey, TedCurve);      // Compute public key
    if (Status != ECCRYPTO_SUCCESS) {
        ECCZERO_TE(pPublicKey);
    }

    return Status;
}


ECCRYPTO_STATUS ECC_FULL_KEYGEN_TE(POINT_PRECOMP_EXTAFF_TE* pTableGen, BASE_ELM pPrivateKey, POINT_TE pPublicKey, PCurveStruct TedCurve)
{ // Key-pair generation
  // It produces a private key pPrivateKey and computes the public key pPublicKey = pPrivateKey*G, where G is the generator (G and its multiples are passed through pTableGen)
  // Curve, field and table parameters are passed through the curve structure TedCurve
  // TedCurve must be set up in advance using ecc_curve_initialize()
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;  

    if (pTableGen == NULL || pPrivateKey == NULL || pPublicKey == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }  

    Status = random_mod_order(pPrivateKey, TedCurve);
    if (Status != ECCRYPTO_SUCCESS) {
        FP_ZERO(pPrivateKey);
        return Status;
    }

    Status = ECC_KEYGEN_TE(pPrivateKey, pTableGen, pPublicKey, TedCurve);
    if (Status != ECCRYPTO_SUCCESS) {
        ECCZERO_TE(pPublicKey);
    }

    return Status;
}


/**************** ECDH(E) FUNCTIONS FOR TWISTED EDWARDS a=-1 CURVES ****************/

ECCRYPTO_STATUS ECDH_SECRET_AGREEMENT_TE(BASE_ELM pPrivateKey, POINT_TE pPublicKey, BASE_ELM pSecretAgreement, PCurveStruct TedCurve)
{ // Secret agreement computation for the ECDH(E) key exchange
  // It computes the shared secret key pSecretAgreement = X(pPrivateKey*pPublicKey), where X() denotes the x-coordinate of an EC point
  // Curve and field parameters are passed through the curve structure TedCurve. TedCurve must be set up in advance using ecc_curve_initialize()
    POINT_TE PointAgreement;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (pPrivateKey == NULL || pPublicKey == NULL || pSecretAgreement == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    Status = ECC_MUL_TE(pPublicKey, pPrivateKey, PointAgreement, TedCurve);       // Compute secret agreement
    if (Status != ECCRYPTO_SUCCESS) {
        goto exit;
    }

    FP_COPY(PointAgreement->x, pSecretAgreement); 

exit:
    ECCZERO_TE(PointAgreement);
    return Status;
}


/**************** ECDSA FUNCTIONS FOR TWISTED EDWARDS a=-1 CURVES *****************/

ECCRYPTO_STATUS ECDSA_SIGN_TE(BASE_ELM pPrivateKey, POINT_PRECOMP_EXTAFF_TE* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, BASE_ELM r, BASE_ELM s, PCurveStruct TedCurve)
{ // Wrapper for the ECDSA signature generation
  // It computes the signature (r,s) of a message m using as inputs a private key pPrivateKey, the generator table pTableGen, and the hash of a message HashedMessage with its byte-length
  // Curve and field parameters are passed through the curve structure TedCurve. JacCurve must be set up in advance using ecc_curve_initialize()
  // The set of valid values for the bitlength of HashedMessage is {256,384,512}
    BASE_ELM RandomNonce;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;    

    if (pPrivateKey == NULL || pTableGen == NULL || HashedMessage == NULL || RandomNonce == NULL || r == NULL || s == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    Status = random_mod_order(RandomNonce, TedCurve);
    if (Status != ECCRYPTO_SUCCESS) {
        FP_ZERO(RandomNonce);
        return Status;
    }

    return ECDSA_SIGN_INTERNAL_TE(pPrivateKey, pTableGen, HashedMessage, SizeHashedMessage, RandomNonce, r, s, TedCurve);
}


ECCRYPTO_STATUS ECDSA_SIGN_INTERNAL_TE(BASE_ELM pPrivateKey, POINT_PRECOMP_EXTAFF_TE* pTableGen, unsigned char* HashedMessage, unsigned int SizeHashedMessage, BASE_ELM RandomNonce, BASE_ELM r, BASE_ELM s, PCurveStruct TedCurve)
{ // Signature generation for ECDSA
  // It computes the signature (r,s) of a message m using as inputs a private key pPrivateKey, the generator table pTableGen, the hash of a message HashedMessage with its byte-length and a random nonce RandomNonce
  // Curve and field parameters are passed through the curve structure TedCurve. TedCurve must be set up in advance using ecc_curve_initialize()
  // The set of valid values for the bitlength of HashedMessage is {256,384,512}
    POINT_TE P;
    BASE_ELM DigitPrivateKey;
    dig DigitHashedMessage[MAXWORDS_FIELD];
    unsigned int i, nbits_hashedmessage = SizeHashedMessage*8;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (pPrivateKey == NULL || pTableGen == NULL || HashedMessage == NULL || RandomNonce == NULL || r == NULL || s == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    // Check if the bitlength of the hashed message is in the valid set
    if (nbits_hashedmessage != 256 && nbits_hashedmessage != 384 && nbits_hashedmessage != 512) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    copy((dig*)HashedMessage, DigitHashedMessage, nbits_hashedmessage/ML_WORD);

    // Is private key in [1,r-1]?                
    if ((FP_ISZERO(pPrivateKey) == TRUE) || (MOD_EVAL(pPrivateKey, TedCurve->order) == FALSE)) {
        Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    Status = ECC_MUL_FIXED_TE(pTableGen, RandomNonce, P, TedCurve);                // P = k*G
    if (Status != ECCRYPTO_SUCCESS) {
        goto exit;
    }

    if (!correction_mod_order(P->x, r, TedCurve)) {                                // r_sign = P->x (mod order)
        Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
        goto exit;
    }      
    if (FP_ISZERO(r) == TRUE) {                                                    // if r_sign = 0 then register error and return
        Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
        goto exit;
    } 

    // Pick the leftmost "rbits" for e
    Status = HashLeftmostExtraction(DigitHashedMessage, nbits_hashedmessage, TedCurve->rbits);
    if (Status != ECCRYPTO_SUCCESS) {
        return Status;
    }
    if (!correction_mod_order(DigitHashedMessage, DigitHashedMessage, TedCurve)) { // e = e (mod order)
        Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
        goto exit;
    }      

    // Conversion to Montgomery representation
    TO_MONTGOMERY_MOD_ORDER(pPrivateKey, DigitPrivateKey, TedCurve);
    TO_MONTGOMERY_MOD_ORDER(RandomNonce, RandomNonce, TedCurve);
    TO_MONTGOMERY_MOD_ORDER(DigitHashedMessage, DigitHashedMessage, TedCurve);
    TO_MONTGOMERY_MOD_ORDER(r, r, TedCurve);

    MONTGOMERY_MUL_MOD_ORDER(DigitPrivateKey, r, s, TedCurve);                     // Mont_s_sign = Mont(d*r_sign (mod order))
    addition_mod_order(DigitHashedMessage, s, s, TedCurve);                        // Mont_s_sign = Mont(e + d*r_sign (mod order))
    MONTGOMERY_INV_MOD_ORDER(RandomNonce, RandomNonce, TedCurve);                  // Mont_kinv   = Mont(k^(-1))
    MONTGOMERY_MUL_MOD_ORDER(s, RandomNonce, s, TedCurve);                         // Mont_s_sign = Mont(k^(-1)*(e + d*r_sign) (mod order))

    // Conversion from Montgomery to standard representation
    FROM_MONTGOMERY_MOD_ORDER(r, r, TedCurve);                                     // r_sign
    FROM_MONTGOMERY_MOD_ORDER(s, s, TedCurve);                                     // s_sign
    if (FP_ISZERO(s) == TRUE) {                                                    // if s_sign = 0 then register error and return
        Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
        goto exit;
    }

exit:
    ECCZERO_TE(P);
    FP_ZERO(DigitPrivateKey);
    FP_ZERO(RandomNonce);
    for (i = 0; i < MAXWORDS_FIELD; i++) {
        ((dig volatile*)DigitHashedMessage)[i] = 0;
    }

    if (Status != ECCRYPTO_SUCCESS) {
        FP_ZERO(r);
        FP_ZERO(s);
    }
    
    return Status;
}


ECCRYPTO_STATUS ECDSA_VERIFICATION_TABLE_TE(POINT_PRECOMP_EXTAFF_TE* pTableVer, PCurveStruct TedCurve)
{ // Computes precomputed table for signature verification in ECDSA
  // It computes table pTableVer containing generator G and several of its multiples: 3*G, 5*G, ..., n*G
  // Curve, field and table parameters are passed through the curve structure TedCurve
  // TedCurve must be set up in advance using ecc_curve_initialize()
    POINT_TE P;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

    if (pTableVer == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }

    ECCSET_TE(P, TedCurve);                                    // Set generator
    Status = ECC_PRECOMP_DBLMUL_TE(P, pTableVer, TedCurve);    // Compute table

    return Status;
}


ECCRYPTO_STATUS ECDSA_VERIFY_TE(POINT_PRECOMP_EXTAFF_TE* pTableVer, POINT_TE pPublicKey, unsigned char* HashedMessage, unsigned int SizeHashedMessage, BASE_ELM r, BASE_ELM s, BOOL* valid, PCurveStruct TedCurve)
{ // Signature verification for ECDSA
  // It verifies the validity of the signature (r,s) of a message m using as inputs the generator table pTableVer, a public key pPublicKey and the hash of a message HashedMessage with its byte-length
  // If the signature is valid, then valid = TRUE, otherwise valid = FALSE
  // Curve and field parameters are passed through the curve structure TedCurve. TedCurve must be set up in advance using ecc_curve_initialize()
    POINT_TE R;
    BASE_ELM DigitR, DigitS, u1, u2, w;
    dig DigitHashedMessage[MAXWORDS_FIELD];
    unsigned int nbits_hashedmessage = SizeHashedMessage*8;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
    
    if (valid != NULL) {    // Set signature invalid by default
        *valid = FALSE;
    }
    if (pTableVer == NULL || pPublicKey == NULL || HashedMessage == NULL || r == NULL || s == NULL || valid == NULL || is_ecc_curve_null(TedCurve)) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    // Check if the bitlength of the hashed message is in the valid set
    if (nbits_hashedmessage != 256 && nbits_hashedmessage != 384 && nbits_hashedmessage != 512) {
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }
    
    copy((dig*)HashedMessage, DigitHashedMessage, nbits_hashedmessage/ML_WORD);

    // Is r_sign in [1,r-1]? if not, reject the signature               
    if ((FP_ISZERO(r) == TRUE) || (MOD_EVAL(r, TedCurve->order) == FALSE)) {
        return ECCRYPTO_SUCCESS;
    }
    // Is s_sign in [1,r-1]? if yes, reject the signature               
    if ((FP_ISZERO(s) == TRUE) || (MOD_EVAL(s, TedCurve->order) == FALSE)) {
        return ECCRYPTO_SUCCESS;
    } 

    // Pick the leftmost "rbits" for e
    Status = HashLeftmostExtraction(DigitHashedMessage, nbits_hashedmessage, TedCurve->rbits);
    if (Status != ECCRYPTO_SUCCESS) {
        return Status;
    }
    if (!correction_mod_order(DigitHashedMessage, DigitHashedMessage, TedCurve)) {    // e = e (mod order)
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }      
    
    // Conversion to Montgomery representation
    TO_MONTGOMERY_MOD_ORDER(DigitHashedMessage, DigitHashedMessage, TedCurve);
    TO_MONTGOMERY_MOD_ORDER(r, DigitR, TedCurve);
    TO_MONTGOMERY_MOD_ORDER(s, DigitS, TedCurve);
        
    MONTGOMERY_INV_MOD_ORDER(DigitS, w, TedCurve);                            // Mont_w  = Mont(s^(-1) mod order)
    MONTGOMERY_MUL_MOD_ORDER(DigitHashedMessage, w, u1, TedCurve);            // Mont_u1 = Mont(e*w (mod order))
    MONTGOMERY_MUL_MOD_ORDER(DigitR, w, u2, TedCurve);                        // Mont_u2 = Mont(r*w (mod order))

    // Conversion from Montgomery to standard representation
    FROM_MONTGOMERY_MOD_ORDER(u1, u1, TedCurve);                              // u1
    FROM_MONTGOMERY_MOD_ORDER(u2, u2, TedCurve);                              // u2
    FROM_MONTGOMERY_MOD_ORDER(DigitR, DigitR, TedCurve);                      // r_sign
    
    addition_mod_order(u1, u1, u1, TedCurve);                                 
    addition_mod_order(u1, u1, u1, TedCurve);                                 // u1 = 4*u1

    Status = ECC_DBLMUL_TE(pTableVer, u1, pPublicKey, u2, R, TedCurve);       // R = u1*G + u2*Q 
    if (Status != ECCRYPTO_SUCCESS) {
        return Status;
    }
    if (ECC_IS_NEUTRAL_AFF_TE(R, TedCurve) == TRUE) {                         // If R = inf, then reject the signature
        return ECCRYPTO_SUCCESS;
    }

    if (!correction_mod_order(R->x, R->x, TedCurve)) {                        // v = R->x (mod order)  
        return ECCRYPTO_ERROR_INVALID_PARAMETER;
    }       
    *valid = compare_mod_order(DigitR, R->x, TedCurve);                       // if v = r_sign then valid = TRUE, otherwise valid = FALSE 
    
    return ECCRYPTO_SUCCESS;
}