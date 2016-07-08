/****************************************************************************************
* LatticeCrypto: an efficient post-quantum Ring-Learning With Errors cryptography library
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: main header file
*
*****************************************************************************************/  

#ifndef __LatticeCrypto_H__
#define __LatticeCrypto_H__


// For C++
#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


// Definition of operating system

#define OS_WIN       1
#define OS_LINUX     2

#if defined(__WINDOWS__)        // Microsoft Windows OS
    #define OS_TARGET OS_WIN
#elif defined(__LINUX__)        // Linux OS
    #define OS_TARGET OS_LINUX 
#else
    #error -- "Unsupported OS"
#endif


// Definition of compiler

#define COMPILER_VC      1
#define COMPILER_GCC     2
#define COMPILER_CLANG   3

#if defined(_MSC_VER)           // Microsoft Visual C compiler
    #define COMPILER COMPILER_VC
#elif defined(__GNUC__)         // GNU GCC compiler
    #define COMPILER COMPILER_GCC   
#elif defined(__clang__)        // Clang compiler
    #define COMPILER COMPILER_CLANG   
#else
    #error -- "Unsupported COMPILER"
#endif


// Definition of the targeted architecture and basic data types
    
#define TARGET_AMD64        1
#define TARGET_x86          2
#define TARGET_ARM          3

#if defined(_AMD64_)
    #define TARGET TARGET_AMD64
    #define RADIX           64
    typedef uint64_t        digit_t;        // Unsigned 64-bit digit
    typedef int64_t         sdigit_t;       // Signed 64-bit digit   
#elif defined(_X86_)
    #define TARGET TARGET_x86
    #define RADIX           32
    typedef uint32_t        digit_t;        // Unsigned 32-bit digit
    typedef int32_t         sdigit_t;       // Signed 32-bit digit
#elif defined(_ARM_)
    #define TARGET TARGET_ARM
    #define RADIX           32
    typedef uint32_t        digit_t;        // Unsigned 32-bit digit
    typedef int32_t         sdigit_t;       // Signed 32-bit digit
#else
    #error -- "Unsupported ARCHITECTURE"
#endif


// Instruction support

#define NO_SIMD_SUPPORT 0
#define AVX_SUPPORT     1
#define AVX2_SUPPORT    2

#if defined(_AVX2_)
    #define SIMD_SUPPORT AVX2_SUPPORT       // AVX2 support selection 
#elif defined(_AVX_)
    #define SIMD_SUPPORT AVX_SUPPORT        // AVX support selection 
#else
    #define SIMD_SUPPORT NO_SIMD_SUPPORT
#endif

#if defined(_ASM_)                          // Assembly support selection
    #define ASM_SUPPORT
#endif

#if defined(_GENERIC_)                      // Selection of generic, portable implementation
    #define GENERIC_IMPLEMENTATION
#endif


// Unsupported configurations
                         
#if defined(ASM_SUPPORT) && (OS_TARGET == OS_WIN)
    #error -- "Assembly is not supported on this platform"
#endif        

#if defined(ASM_SUPPORT) && defined(GENERIC_IMPLEMENTATION)
    #error -- "Unsupported configuration"
#endif        

#if (SIMD_SUPPORT != NO_SIMD_SUPPORT) && defined(GENERIC_IMPLEMENTATION)
    #error -- "Unsupported configuration"
#endif

#if (TARGET != TARGET_AMD64) && !defined(GENERIC_IMPLEMENTATION)
    #error -- "Unsupported configuration"
#endif

#if (OS_TARGET == OS_LINUX) && defined(ASM_SUPPORT) && (SIMD_SUPPORT != AVX2_SUPPORT)
    #error -- "Unsupported configuration"
#endif


// Definitions of the error-handling type and error codes

typedef enum {
    CRYPTO_SUCCESS,                          // 0x00
    CRYPTO_ERROR,                            // 0x01
    CRYPTO_ERROR_DURING_TEST,                // 0x02
    CRYPTO_ERROR_UNKNOWN,                    // 0x03
    CRYPTO_ERROR_NOT_IMPLEMENTED,            // 0x04
    CRYPTO_ERROR_NO_MEMORY,                  // 0x05
    CRYPTO_ERROR_INVALID_PARAMETER,          // 0x06
    CRYPTO_ERROR_SHARED_KEY,                 // 0x07
    CRYPTO_ERROR_TOO_MANY_ITERATIONS,        // 0x08
    CRYPTO_ERROR_END_OF_LIST
} CRYPTO_STATUS;

#define CRYPTO_STATUS_TYPE_SIZE (CRYPTO_ERROR_END_OF_LIST)       


// Definitions of the error messages
// NOTE: they must match the error codes above

#define CRYPTO_MSG_SUCCESS                                "CRYPTO_SUCCESS"
#define CRYPTO_MSG_ERROR                                  "CRYPTO_ERROR"
#define CRYPTO_MSG_ERROR_DURING_TEST                      "CRYPTO_ERROR_DURING_TEST"
#define CRYPTO_MSG_ERROR_UNKNOWN                          "CRYPTO_ERROR_UNKNOWN"
#define CRYPTO_MSG_ERROR_NOT_IMPLEMENTED                  "CRYPTO_ERROR_NOT_IMPLEMENTED"
#define CRYPTO_MSG_ERROR_NO_MEMORY                        "CRYPTO_ERROR_NO_MEMORY"
#define CRYPTO_MSG_ERROR_INVALID_PARAMETER                "CRYPTO_ERROR_INVALID_PARAMETER"
#define CRYPTO_MSG_ERROR_SHARED_KEY                       "CRYPTO_ERROR_SHARED_KEY"
#define CRYPTO_MSG_ERROR_TOO_MANY_ITERATIONS              "CRYPTO_ERROR_TOO_MANY_ITERATIONS"                                                            


// Definition of type "RandomBytes" to implement callback function outputting "nbytes" of random values to "random_array"
typedef CRYPTO_STATUS (*RandomBytes)(unsigned int nbytes, unsigned char* random_array);                                                   

// Definition of type "ExtendableOutput" to implement callback function outputting 32-bit "array_ndigits" of values to "extended_array"
typedef CRYPTO_STATUS (*ExtendableOutput)(const unsigned char* seed, unsigned int seed_nbytes, unsigned int array_ndigits, uint32_t* extended_array);                                                  

// Definition of type "StreamOutput" to implement callback function outputting 32-bit "array_ndigits" of values to "stream_array"
typedef CRYPTO_STATUS (*StreamOutput)(const unsigned char* seed, unsigned int seed_nbytes, unsigned char* nonce, unsigned int nonce_nbytes, unsigned int array_nbytes, unsigned char* stream_array);


// Basic key-exchange constants  
#define PKA_BYTES           1824      // Alice's public key size 
#define PKB_BYTES           2048      // Bob's public key size 
#define SHAREDKEY_BYTES     32        // Shared key size 


// This data struct is initialized during setup with user-provided functions
typedef struct
{
    RandomBytes      RandomBytesFunction;               // Function providing random bytes
    ExtendableOutput ExtendableOutputFunction;          // Extendable output function
    StreamOutput     StreamOutputFunction;              // Stream cipher function
} LatticeCryptoStruct, *PLatticeCryptoStruct;


/******************** Function prototypes *******************/
/*********************** Auxiliary API **********************/ 

// Clear digits from memory. "nwords" indicates the number of digits to be zeroed.
extern void clear_words(void* mem, digit_t nwords);

// Output "nbytes" of random values.
// It makes requests of random values to RandomBytesFunction. If successful, the output is given in "random_array".
// The caller is responsible for providing the "RandomBytesFunction" function passing random value as octets.
CRYPTO_STATUS random_bytes(unsigned int nbytes, unsigned char* random_array, RandomBytes RandomBytesFunction);

// Output "array_ndigits" of values in [0, q-1] using an extendable-output function and a seed of size "seed_nbytes".   
// It makes requests of values to ExtendableOutputFunction. If successful, the output is given in "extended_array".
// The caller is responsible for providing the "ExtendableOutputFunction" function passing values as 32-bit digits. 
CRYPTO_STATUS extended_output(const unsigned char* seed, unsigned int seed_nbytes, unsigned int array_ndigits, uint32_t* extended_array, ExtendableOutput ExtendableOutputFunction);

// Output "array_nbytes" of values using a stream cipher, a seed of size "seed_nbytes" and a nonce of size "nonce_nbytes".  
// It makes requests of values to StreamOutputFunction. If successful, the output is given in "stream_array".
// The caller is responsible for providing the "StreamOutputFunction" function passing values as octets.  
CRYPTO_STATUS stream_output(const unsigned char* seed, unsigned int seed_nbytes, unsigned char* nonce, unsigned int nonce_nbytes, unsigned int array_nbytes, unsigned char* stream_array, StreamOutput StreamOutputFunction);

// Dynamic allocation of memory for LatticeCrypto structure. It should be called before initialization with LatticeCrypto_initialize(). Returns NULL on error.
PLatticeCryptoStruct LatticeCrypto_allocate(void); 

// Initialize structure pLatticeCrypto with user-provided functions: RandomBytesFunction, ExtendableOutputFunction and StreamOutputFunction.
CRYPTO_STATUS LatticeCrypto_initialize(PLatticeCryptoStruct pLatticeCrypto, RandomBytes RandomBytesFunction, ExtendableOutput ExtendableOutputFunction, StreamOutput StreamOutputFunction);

// Output error/success message for a given CRYPTO_STATUS
const char* LatticeCrypto_get_error_message(CRYPTO_STATUS Status);

/*********************** Key exchange API ***********************/ 

// Alice's key generation 
// It produces a private key SecretKeyA and computes the public key PublicKeyA.
// Outputs: the private key SecretKeyA that consists of a 32-bit signed 1024-element array (4096 bytes in total)
//          the public key PublicKeyA that occupies 1824 bytes
// pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
CRYPTO_STATUS KeyGeneration_A(int32_t* SecretKeyA, unsigned char* PublicKeyA, PLatticeCryptoStruct pLatticeCrypto);

// Bob's key generation and shared secret computation
// It produces a private key and computes the public key PublicKeyB. In combination with Alice's public key PublicKeyA, it computes 
// the shared secret SharedSecretB.
// Input:   Alice's public key PublicKeyA that consists of 1824 bytes
// Outputs: the public key PublicKeyB that occupies 2048 bytes.
//          the 256-bit shared secret SharedSecretB.
// pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
CRYPTO_STATUS SecretAgreement_B(unsigned char* PublicKeyA, unsigned char* SharedSecretB, unsigned char* PublicKeyB, PLatticeCryptoStruct pLatticeCrypto);

// Alice's shared secret computation 
// It computes the shared secret SharedSecretA using Bob's public key PublicKeyB and Alice's private key SecretKeyA.
// Inputs: Bob's public key PublicKeyB that consists of 2048 bytes
//         the private key SecretKeyA that consists of a 32-bit signed 1024-element array (4096 bytes in total)
// Output: the 256-bit shared secret SharedSecretA.
// pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
CRYPTO_STATUS SecretAgreement_A(unsigned char* PublicKeyB, int32_t* SecretKeyA, unsigned char* SharedSecretA);


#ifdef __cplusplus
}
#endif


#endif
