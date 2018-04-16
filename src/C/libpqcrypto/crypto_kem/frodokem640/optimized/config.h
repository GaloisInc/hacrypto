/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: configuration file
*********************************************************************************************/

#ifndef _CONFIG_H_
#define _CONFIG_H_


// Defining method for generating matrix A
#define _AES128_FOR_A_ 1
#if (_AES128_FOR_A_)
    #define USE_AES128_FOR_A
#elif defined(_CSHAKE128_FOR_A_)
    #define USE_CSHAKE128_FOR_A
#else
    ##error -- missing method for generating matrix A
#endif


#define _USE_OPENSSL_ 1
// Selecting use of OpenSSL's AES functions
#if defined(_USE_OPENSSL_)
    #define USE_OPENSSL
#endif


// Macro to avoid compiler warnings when detecting unreferenced parameters
#define UNREFERENCED_PARAMETER(PAR) ((void)(PAR))


#endif
