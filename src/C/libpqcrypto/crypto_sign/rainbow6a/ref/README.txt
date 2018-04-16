This folder contains the c-code of our Reference implementation of Rainbow(GF(16),76,64,64)
This folder contains the files

api.h			           	-- API for eBracs
blas.c			         	-- Basic Linear algebra Library (BLAS)
blas_config.h			    -- Configures file for BLAS.
blas.h				        -- .H and inline functions for BLAS
gf16.h				        -- Library for arithmetic of GF(16)
hash_len_config.h		  -- Configures file for the length of HASH funciton used
hash_utils.c		    	-- Library for HASH functions (adaptor for OpenSSL)
hash_utils.h			    -- Library for HASH functions
mpkc_config.h	 		    -- Configures for MQ functions
mpkc.h				        -- Library for MQ functions
prng_utils.c			    -- Library for pseudo random number generator(PRNG)
prng_utils.h			    -- Library for PRNG
rainbow_16.c			    -- Core functions for rainbow over GF(16)
rainbow_16.h			    -- Core functions for rainbow over GF(16)
rainbow_config.h		  -- Configures files for parameters of rainbow_16
rng.c				          -- PRNG from the example of NIST
rng.h				          -- PRNG form the example of NIST
sign.c				        -- Wrapper to reduce the API to the core functions of rainbow_16