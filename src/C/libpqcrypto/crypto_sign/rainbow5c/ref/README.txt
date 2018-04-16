This folder contains the c-code of our Reference implementation of Rainbow(GF(256),92,48,48).

The folder contains the following files.

api.h				              -- API for eBracs
blas.c				            -- Basic Linear algebra Library (BLAS)
blas_config.h			        -- Configures file for BLAS.
blas.h				            -- .H and inline funcitons for BLAS
gf16.h				            -- Library for arithmetic of GF(16)
hash_len_config.h	       	-- Configures file for the length of HASH funciton used
hash_utils.c			        -- Library for HASH functions (adaptor for OpenSSL)
hash_utils.h			        -- Library for HASH functions
mpkc.h				            -- Library for MQ functions
prng_utils.c			        -- Library for pseudo random number generator(PRNG)
prng_utils.h			        -- Library for PRNG
rainbow.c			            -- Core functions for rainbow over GF(256)
rainbow.h			            -- Core functions for rainbow over GF(256)
rainbow_config.h		      -- Configures files for the parameters of rainbow
rng.c			              	-- PRNG from the example of NIST
rng.h				              -- PRNG from the example of NIST
sign.c				            -- Wrapper to reduce API to the core functions of rainbow