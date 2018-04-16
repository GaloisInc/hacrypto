This folder contains the c-code of our implementation of Rainbow(GF(16),32,32,32) optimized for amd64.

The folder contains the following files.
api.h				            -- API for eBracs
blas.c				          -- Basic Linear algebra Library (BLAS)
blas_config.h		      	-- Configure file for BLAS.
blas.h				          -- .H and inline funcitons for BLAS
gf16.h				          -- Library for arightmetic of GF(16)
hash_len_config.h		    -- Configure file for the length of HASH funciton used
hash_utils.c			      -- Library for HASH functions (adaptor for OpenSSL)
hash_utils.h	      		-- Library for HASH functions
mpkc_config.h			      -- Configure for MQ functions
mpkc.h			          	-- Library for MQ functions
prng_utils.c		      	-- Library for pseude random generator(PRNG)
prng_utils.h			      -- Library for PRNG
rainbow_16.c		       	-- Core functions for rainbow over GF(16)
rainbow_16.h			      -- Core functions for rainbow over GF(16)
rainbow_config.h		    -- Configure files for parameters of rainbow_16
rng.c				            -- PRNG from the example of NIST
rng.h				            -- PRNG form the example of NIST
sign.c				          -- Wrapper for reduce API to core funcitons of rainbow_16