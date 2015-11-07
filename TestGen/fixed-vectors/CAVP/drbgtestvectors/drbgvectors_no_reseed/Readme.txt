There are two sets of NIST SP 800-90A DRBG example files included in this zip
file.  All values in this zip file are for Prediction Resistance NOT ENABLED,
NO RESEED function, and the DRBG returned bits are four (4) output blocks long.

The files contain sample files for all supported SHA, HMAC, AES, TDES, Elliptic
Curves for each mechanism, including SHA-512/224 and SHA-512/256 as defined in
FIPS 180-4.

1. The response (.rsp) files contain properly formatted CAVS response files.

2. The intermediate value (.txt) files for the tests contain intermediate
   values.  The DRBG tests consist of the following four operations:
   i. Instantiate
   ii. Generate Random Bits
   iii. Generate Random Bits
   iv. Uninstantiate
   The response files contain all inputs for Instantiate and both calls
   to Generate and the Random Bits (i.e., ReturnedBits) returned from the second
   call to Generate.  The intermediate value (.txt) files also show the value
   of the working state after each call to Instantiate and Generate.
   These values are indented by one tab space and are preceded by a line
   indicating the DRBG function just performed:
   ** INSTANTIATE,
   ** GENERATE (FIRST CALL)
   or ** GENERATE (SECOND CALL).
   
The working state values printed out for the different DRBG mechanisms are:
1. Hash_DRBG - working state consists of 'V' (variable) 'C' (constant) and reseed_counter
2. HMAC_DRBG - working state consists of 'V' and 'Key'.
3. CTR_DRBG - working state consists of 'V' and 'Key'.
4. Dual_EC_DRBG - the secret value of the working state is 's'.  Other elements
   of the working state, such as the curve domain parameters and points P and
   Q, are not secret.

Refer to NIST SP 800-90A (January 2012) for more on the DRBG mechanisms and their working state
variables:

http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf