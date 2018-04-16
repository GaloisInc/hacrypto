/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: configuration file
*********************************************************************************************/

#ifndef _CONFIG_H_
#define _CONFIG_H_


// Definition of operating system

#define OS_LINUX     1

#define LINUX 1
#if defined(LINUX)            // Linux
    #define OS_TARGET OS_LINUX
#else
    #error -- "Unsupported OS"
#endif


#if defined(LINUX)
    #define ALIGN_HEADER(N)
    #define ALIGN_FOOTER(N) __attribute__((aligned(N)))
#endif


#define _OPTIMIZED_FAST_ 1
// Selecting implementation: optimized_fast
#if defined(_OPTIMIZED_FAST_)    // "Optimized_fast" implementation requires support for AVX2 and AES_NI instructions
    #define USE_AVX2
    #define AES_ENABLE_NI
#else
    #error -- unsupported implementation
#endif


// Defining method for generating matrix A
#define _AES128_FOR_A_ 1
#if (_AES128_FOR_A_)
    #define USE_AES128_FOR_A
#elif defined(_CSHAKE128_FOR_A_)
    #define USE_CSHAKE128_FOR_A
#else
    ##error -- missing method for generating matrix A
#endif


// Selecting use of OpenSSL's AES functions
#define _USE_OPENSSL_ 1
#if defined(_USE_OPENSSL_)
    #define USE_OPENSSL
#endif


// Macro to avoid compiler warnings when detecting unreferenced parameters
#define UNREFERENCED_PARAMETER(PAR) ((void)(PAR))


#endif
