This folder contains the c-code of our implementation of Rainbow(GF(31),84,56,56) optimized for axv2 vector instructions.

The folder contains the following files.
api.h			                   	-- API for eBracs
blas_avx2.h		         	      -- BLAS, for AVX2 instruction set.
blas.c				                -- Basic Linear algebra Library (BLAS)
blas_config.h			            -- Configure file for BLAS
blas.h				                -- .H and inline funcitons for BLAS
gf31_convert.c			          -- Data Convertor for byte stream and gf(31)
gf31_convert.h			          -- Data Convertor for byte stream and gf(31)
gf31.h				                -- Library for arithmetic of GF(31)
gf31_sse.h			              -- Library for arithmetic of GF(16), SSE instruciton set.
gf31_table.c			            -- Tables for Library of arithmetic of GF(31)
gf31_table.h			            -- Tables for Library of arithmetic of GF(31)
hash_len_config.h		          -- Configures file for the length of HASH function used
hash_utils.c			            -- Library for HASH functions (adaptor for OpenSSL)
hash_utils.h			            -- Library for HASH functions
mpkc_avx2.h			              -- Library for MQ functions, AVX2 instruction set.
mpkc.h				                -- Library for MQ functions
prng_utils.c			            -- Library for pseudo random number generator(PRNG)
prng_utils.h			            -- Library for PRNG
rainbow.c			                -- Core functions for rainbow
rainbow.h			                -- Core functions for rainbow
rainbow_config.h		          -- Configures files for parameters of rainbow_16
rng.c		                  		-- PRNG from the example of NIST
rng.h				                  -- PRNG from the example of NIST
sign.c		                 		-- Wrapper to reduce API to the core functions of rainbow