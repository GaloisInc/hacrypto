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
* Abstract: definitions of 256-bit functions for curves numsp256d1 and numsp256t1
*
* This software is based on the article by Joppe Bos, Craig Costello, 
* Patrick Longa and Michael Naehrig, "Selecting elliptic curves for
* cryptography: an efficiency and security analysis", preprint available
* at http://eprint.iacr.org/2014/130.
******************************************************************************/  

#include "msr_ecclib.h"


#ifdef ECCURVES_256

// Definition of 256-bit field elements and elements in Z_r
#define BASE_ELM                dig256
#define BASE_ELM_NBYTES         sizeof(dig256)

// Definition of point representation types, 256-bit     
#define POINT_WAFF              point_numsp256d1    
#define POINT_WJAC              point_jac_numsp256d1
#define POINT_PRECOMP_WCHU      point_chu_precomp_numsp256d1 
#define POINT_TE                point_numsp256t1   
#define POINT_EXT_TE            point_extproj_numsp256t1   
#define POINT_PRECOMP_EXT_TE    point_extproj_precomp_numsp256t1
#define POINT_PRECOMP_EXTAFF_TE point_extaff_precomp_numsp256t1         

// Definition of field operations with p = 2^256-189
#define FP_COPY                 fpcopy256 
#define FP_ZERO                 fpzero256  
#define FP_ISZERO               fp_iszero256    
#define FP_ADD                  fpadd256   
#define FP_SUB                  fpsub256     
#define FP_NEG                  fpneg256         
#define MOD_EVAL                mod_eval256     
#define FP_DIV2                 fpdiv2_256       
#define FP_MULC                 fpmulc256     
#define FP_SQR                  fpsqr256      
#define FP_MUL                  fpmul256
#define FP_INV                  fpinv256                                       

// Selection of low-level field implementations with p = 2^256-189
#if (USE_ASM == TRUE) && (TARGET_GENERIC == FALSE)  
    #define FP_ZERO_LOW         fpzero256_a  
    #define FP_ADD_LOW          fpadd256_a       
    #define FP_SUB_LOW          fpsub256_a     
    #define FP_NEG_LOW          fpneg256_a       
    #define FP_DIV2_LOW         fpdiv2_256_a  
    #define FP_MULC_LOW         fpmul256_a     
    #define FP_SQR_LOW          fpsqr256_a        
    #define FP_MUL_LOW          fpmul256_a  
#else
    #define FP_ZERO_LOW         fpzero256_c
    #define FP_ADD_LOW          fpadd256_c
    #define FP_SUB_LOW          fpsub256_c
    #define FP_NEG_LOW          fpneg256_c
    #define FP_DIV2_LOW         fpdiv2_256_c
    #define FP_MULC_LOW         fpmul256_c
    #define FP_SQR_LOW          fpsqr256_c
    #define FP_MUL_LOW          fpmul256_c
#endif
#define FP_INV_LOW              fpinv256_fixedchain       

// Definition of Montgomery operations
#if (TARGET_GENERIC == TRUE || TARGET != TARGET_AMD64)
    #define MONTGOMERY_MUL              Montgomery_multiply
#else
    #define MONTGOMERY_MUL              Montgomery_multiply256 
#endif
#define MONTGOMERY_MUL_MOD_ORDER        Montgomery_multiply_mod_order256
#define MONTGOMERY_INV_MOD_ORDER        Montgomery_inversion_mod_order256 
#define MONTGOMERY_INV                  Montgomery_inversion256 
#define TO_MONTGOMERY_MOD_ORDER         toMontgomery_mod_order256 
#define TO_MONTGOMERY                   toMontgomery256 
#define FROM_MONTGOMERY_MOD_ORDER       fromMontgomery_mod_order256 
#define FROM_MONTGOMERY                 fromMontgomery256 

// Definition of point operations with p = 2^256-189
#define ECCSET_W                        eccset_numsp256d1
#define ECCCOPY_W                       ecccopy_numsp256d1
#define ECCCOPY_WJAC                    ecccopy_jac_numsp256d1
#define ECCCOPY_WCHU                    ecccopy_chu_numsp256d1
#define ECCCONVERT_AFF_TO_JAC_W         eccconvert_aff_to_jac_numsp256d1
#define ECCZERO_WAFF                    ecczero_numsp256d1
#define ECCZERO_WJAC                    ecczero_jac_numsp256d1
#define ECCZERO_WCHU                    ecczero_chu_numsp256d1
#define ECC_IS_INFINITY_WAFF            ecc_is_infinity_numsp256d1
#define ECC_IS_INFINITY_WJAC            ecc_is_infinity_jac_numsp256d1
#define ECCNORM_W                       eccnorm_numsp256d1
#define ECCDOUBLE_WJAC                  eccdouble_jac_numsp256d1
#define ECCDOUBLE_INTERNAL_WJAC         eccdouble_jac_internal_numsp256d1
#define ECCMADD_CONDITIONALS_WJAC       eccadd_mixed_jac_conditionals_numsp256d1
#define ECCUADD_WJAC                    eccadd_jac_numsp256d1
#define ECCUADD_NO_INIT_WJAC            eccadd_jac_no_init_numsp256d1
#define ECCUMADD_WJAC                   eccadd_mixed_jac_numsp256d1
#define ECCDOUBLEADD_WJAC               eccdoubleadd_jac_numsp256d1
#define ECCDOUBLEADD_CONDITIONALS_WJAC  eccdoubleadd_jac_conditionals_numsp256d1
#define ECCADD_PRECOMP_WJAC             eccadd_jac_precomp_numsp256d1
#define ECC_PRECOMP_WJAC                ecc_precomp_jac_numsp256d1
#define ECC_MUL_W                       ecc_scalar_mul_numsp256d1
#define LUT_WCHU                        lut_chu_numsp256d1
#define ECC_PRECOMP_FIXED_W             ecc_precomp_fixed_numsp256d1
#define ECC_PRECOMP_FIXED_INTERNAL_W    ecc_precomp_fixed_internal_numsp256d1
#define ECC_MUL_FIXED_W                 ecc_scalar_mul_fixed_numsp256d1
#define ECC_MUL_FIXED_INTERNAL_W        ecc_scalar_mul_fixed_internal_numsp256d1
#define LUT_WAFF                        lut_aff_numsp256d1
#define ECC_PRECOMP_DBLMUL_W            ecc_precomp_dblmul_numsp256d1
#define ECC_PRECOMP_DBLMUL_INTERNAL_W   ecc_precomp_dblmul_internal_numsp256d1
#define ECC_ALLOCATE_PRECOMP_W          ecc_allocate_precomp_numsp256d1
#define ECC_DBLMUL_W                    ecc_double_scalar_mul_numsp256d1
#define ECC_DBLMUL_INTERNAL_W           ecc_double_scalar_mul_internal_numsp256d1
#if (USE_ASM == TRUE) && (TARGET_GENERIC == FALSE)
    #define COMPLETE_EVAL               complete_eval_numsp256d1_a
    #define COMPLETE_SELECT             complete_select_numsp256d1_a
    #define COMPLETE_LUT4               complete_lut4_numsp256d1_a
    #define COMPLETE_LUT5               complete_lut5_numsp256d1_a
#else
    #define COMPLETE_EVAL               complete_eval_numsp256d1
    #define COMPLETE_SELECT             complete_select_numsp256d1
    #define COMPLETE_LUT                complete_lut_numsp256d1
    #define COMPLETE_LUT4(table, index, P)  \
                                        COMPLETE_LUT(table, index, P, 4)         
    #define COMPLETE_LUT5(table, index, P)  \
                                        COMPLETE_LUT(table, index, P, 5)
#endif
#define ECC_GENERATOR_TABLE_W           ecc_generator_table_numsp256d1
#define ECC_KEYGEN_W                    ecc_keygen_numsp256d1
#define ECC_FULL_KEYGEN_W               ecc_full_keygen_numsp256d1
#define ECDH_SECRET_AGREEMENT_W         ecdh_secret_agreement_numsp256d1
#define ECDSA_SIGN_W                    ecdsa_sign_numsp256d1
#define ECDSA_SIGN_INTERNAL_W           ecdsa_sign_internal_numsp256d1
#define ECDSA_VERIFICATION_TABLE_W      ecdsa_verification_table_numsp256d1
#define ECDSA_VERIFY_W                  ecdsa_verify_numsp256d1

#define ECCSET_TE                       eccset_numsp256t1
#define ECCCOPY_EXT_TE                  ecccopy_extproj_numsp256t1
#define ECCCOPY_EXT2_TE                 ecccopy_extproj2_numsp256t1
#define ECCCOPY_EXTAFF_TE               ecccopy_extaff_numsp256t1
#define ECCCONVERT_AFF_TO_EXTPROJ_TE    eccconvert_aff_to_extproj_numsp256t1
#define ECCCONVERT_R1_TO_R2             eccconvert_extproj_to_extproj_precomp_numsp256t1
#define ECCZERO_TE                      ecczero_numsp256t1
#define ECCZERO_EXT_TE                  ecczero_extproj_numsp256t1
#define ECCZERO_PRECOMP_EXT_TE          ecczero_extproj_precomp_numsp256t1
#define ECCZERO_PRECOMP_EXTAFF_TE       ecczero_extaff_precomp_numsp256t1
#define ECC_IS_NEUTRAL_AFF_TE           ecc_is_neutral_numsp256t1
#define ECC_IS_NEUTRAL_EXT_TE           ecc_is_neutral_extproj_numsp256t1
#define ECC_VALIDATION_TE               ecc_validation_numsp256t1
#define ECC_CLEARING_TE                 ecc_clearing_numsp256t1
#define CONVERSION_TO_ODD               conversion_to_odd_numsp256
#define OUTPUT_CORRECTION               output_correction_numsp256
#define ECCNORM_TE                      eccnorm_numsp256t1
#define ECCDOUBLE_EXT_TE                eccdouble_extproj_numsp256t1
#define ECCDOUBLE_EXT_INTERNAL_TE       eccdouble_extproj_internal_numsp256t1
#define ECCUADD_EXT_TE                  eccadd_extproj_numsp256t1
#define ECCUADD_EXT_INTERNAL_TE         eccadd_extproj_internal_numsp256t1
#define ECCUADD_EXT_CORE_TE             eccadd_extproj_core_numsp256t1
#define ECCUMADD_EXT_TE                 eccadd_mixed_extproj_numsp256t1
#define ECCUMADD_EXT_INTERNAL_TE        eccadd_mixed_extproj_internal_numsp256t1
#define ECCADD_TE_PRECOMP               eccadd_extproj_precomp_numsp256t1
#define ECC_PRECOMP_EXT_TE              ecc_precomp_extproj_numsp256t1
#define ECC_MUL_TE                      ecc_scalar_mul_numsp256t1
#define LUT_EXT_TE                      lut_extproj_numsp256t1
#define ECC_MUL_FIXED_TE                ecc_scalar_mul_fixed_numsp256t1
#define ECC_MUL_FIXED_INTERNAL_TE       ecc_scalar_mul_fixed_internal_numsp256t1
#define LUT_EXTAFF_TE                   lut_extaff_numsp256t1
#define ECC_PRECOMP_FIXED_TE            ecc_precomp_fixed_numsp256t1
#define ECC_PRECOMP_FIXED_INTERNAL_TE   ecc_precomp_fixed_internal_numsp256t1
#define ECC_PRECOMP_DBLMUL_TE           ecc_precomp_dblmul_numsp256t1
#define ECC_PRECOMP_DBLMUL_INTERNAL_TE  ecc_precomp_dblmul_internal_numsp256t1
#define ECC_ALLOCATE_PRECOMP_TE         ecc_allocate_precomp_numsp256t1
#define ECC_DBLMUL_TE                   ecc_double_scalar_mul_numsp256t1
#define ECC_DBLMUL_INTERNAL_TE          ecc_double_scalar_mul_internal_numsp256t1
#define ECC_GENERATOR_TABLE_TE          ecc_generator_table_numsp256t1
#define ECC_KEYGEN_TE                   ecc_keygen_numsp256t1
#define ECC_FULL_KEYGEN_TE              ecc_full_keygen_numsp256t1
#define ECDH_SECRET_AGREEMENT_TE        ecdh_secret_agreement_numsp256t1
#define ECDSA_SIGN_TE                   ecdsa_sign_numsp256t1
#define ECDSA_SIGN_INTERNAL_TE          ecdsa_sign_internal_numsp256t1
#define ECDSA_VERIFICATION_TABLE_TE     ecdsa_verification_table_numsp256t1
#define ECDSA_VERIFY_TE                 ecdsa_verify_numsp256t1

#include "fp_template.c"
#include "mont_template.c"
#include "ecc_template.c"
#include "ecc_crypto.c"

#endif


