There are two sets of RNG example files:

1. The response (.rsp) files contain properly formatted CAVS response files.

2. The intermediate value (.txt) files for the Monte Carlo tests contain
   values for the first five (5) of the 10,000 iterations.  The values are
   as follows:
   a. For ANSI931 RNG (TDES, AES), the values of DT, V and R returned by the
      RNG are given.  R holds the random bits generated, and V is the updated
	  input used for the next call to the RNG.  DT is incremented by one each
	  time the RNG is called.
	 
   b. For ANSI962 RNG, the values of X and XKey returned by the RNG are given.
      X holds the random bits generated, and XKey is the updated seed-key.

   c. For FIPS186 RNG, the values of X and XKey (or K and KKey) returned by the
      RNG are given.  X (K) holds the random bits generated, and XKey (KKey) is
	  the updated seed-key.  See Appendix 3 of FIPS 186-2 for details.
