/****************************************************************************************
* LatticeCrypto: an efficient post-quantum Ring-Learning With Errors cryptography library
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: wrappers for user-provided functions
*
*****************************************************************************************/


#include "LatticeCrypto_priv.h"


CRYPTO_STATUS random_bytes(unsigned int nbytes, unsigned char* random_array, RandomBytes RandomBytesFunction)
{ // Output "nbytes" of random values.
  // It makes requests of random values to RandomBytesFunction. If successful, the output is given in "random_array".
  // The caller is responsible for providing the "RandomBytesFunction" function passing random values as octets.

    if (random_array == NULL || RandomBytesFunction == NULL || nbytes == 0) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }    
    
    return (RandomBytesFunction)(nbytes, random_array);
}


CRYPTO_STATUS extended_output(const unsigned char* seed, unsigned int seed_nbytes, unsigned int array_ndigits, uint32_t* extended_array, ExtendableOutput ExtendableOutputFunction)
{ // Output "array_ndigits" of values in [0, q-1] using an extendable-output function and a seed of size "seed_nbytes".
  // It makes requests of values to ExtendableOutputFunction. If successful, the output is given in "extended_array".
  // The caller is responsible for providing the "ExtendableOutputFunction" function passing values as 32-bit digits.

    if (seed == NULL || extended_array == NULL || ExtendableOutputFunction == NULL || seed_nbytes == 0 || array_ndigits == 0) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }    
    
    return (ExtendableOutputFunction)(seed, seed_nbytes, array_ndigits, extended_array);
}


CRYPTO_STATUS stream_output(const unsigned char* seed, unsigned int seed_nbytes, unsigned char* nonce, unsigned int nonce_nbytes, unsigned int array_nbytes, unsigned char* stream_array, StreamOutput StreamOutputFunction)
{ // Output "array_nbytes" of values using a stream cipher, a seed of size "seed_nbytes" and a nonce of size "nonce_nbytes".  
  // It makes requests of values to StreamOutputFunction. If successful, the output is given in "stream_array".
  // The caller is responsible for providing the "StreamOutputFunction" function passing values as octets.

    if (seed == NULL || stream_array == NULL || StreamOutputFunction == NULL || seed_nbytes == 0 || nonce_nbytes == 0 || array_nbytes == 0) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }    
    
    return (StreamOutputFunction)(seed, seed_nbytes, nonce, nonce_nbytes, array_nbytes, stream_array);
}