This folder contains the c-code of our implementation of Rainbow(GF(256),84,56,56) optimized for avx2 vector instructions.

The folder contains the following files.
api.h				                    -- API for eBracs
blas_avx2.h			                -- BLAS, for AVX2 instruction set.
blas.c		                   		-- Basic Linear algebra Library (BLAS)
blas_config.h			              -- Configure file for BLAS
blas.h				                  -- .H and inline functions for BLAS
blas_sse.h		                	-- BLAS, for SSE instruction set.
gf16_avx2.h			                -- Library for arithmetic of GF(16), AVX2 instruciton set.
gf16.c			                   	-- Library for arithmetic of GF(16)
gf16.h				                  -- Library for arithmetic of GF(16)
gf16_sse.h			                -- Library for arithmetic of GF(16), SSE instruction set.
gf16_tabs.h			                -- Tables for Library of arithmetic of GF(16)
hash_len_config.h		            -- Configures file for the length of HASH funciton used
hash_utils.c			              -- Library for HASH functions (adaptor for OpenSSL)
hash_utils.h			              -- Library for HASH functions
mpkc_avx2.h	  		              -- Library of MQ functions (AVX2)
mpkc.h				                  -- Library for MQ functions
prng_utils.c		               	-- Library for pseudo random number generator(PRNG)
prng_utils.h			              -- Library for PRNG
rainbow.c			                  -- Core functions for rainbow 
rainbow.h			                  -- Core functions for rainbow 
rainbow_config.h		            -- Configures files for parameters of rainbow
rng.c				                    -- PRNG from the example of NIST
rng.h	                          -- PRNG form the example of NIST
sign.c				                  -- Wrapper to reduce API to the core functions of rainbow