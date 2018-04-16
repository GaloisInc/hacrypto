This folder contains the c-code of our implementation of Rainbow(GF(16),56,48,48) optimized for axv2 vector instructions.

The folder contains the following files.
api.h			                   	-- API for eBracs
blas_avx2.h		         	      -- BLAS, for AVX2 instruction set.
blas.c				                -- Basic Linear algebra Library (BLAS)
blas_config.h			            -- Configure file for BLAS
blas.h				                -- .H and inline funcitons for BLAS
blas_sse.h			              -- BLAS, for SSE instruction set.
gf16_avx2.h		              	-- Library for arithmetic of GF(16), AVX2 instruction set.
gf16.c				                -- Library for arithmetic of GF(16)
gf16.h				                -- Library for arithmetic of GF(16)
gf16_sse.h			              -- Library for arithmetic of GF(16), SSE instruction set.
gf16_tabs.h			              -- Tables for Library of arithmetic of GF(16)
hash_len_config.h		          -- Configures file for the length of HASH funciton used
hash_utils.c			            -- Library for HASH functions (adaptor for OpenSSL)
hash_utils.h			            -- Library for HASH functions
mpkc_avx2.c			              -- Library for MQ functions, AVX2 instruction set.
mpkc_avx2.h			              -- Library for MQ functions, AVX2 instruciton set.
mpkc.c				                -- Library for MQ functions
mpkc_config.h	             		-- Configures file for Library of MQ functions
mpkc.h				                -- Library for MQ functions
prng_utils.c			            -- Library for pseudo random number generator(PRNG)
prng_utils.h			            -- Library for PRNG
rainbow_16323232_core_avx2.c	-- AVX2 specialized core functions for rainbow gf16,32,32,32
rainbow_16323232_core_avx2.h	-- AVX2 specialized core functions for rainbow gf16,32,32,32
rainbow_16.c			            -- Core functions for rainbow over GF(16)
rainbow_16.h			            -- Core functions for rainbow over GF(16)
rainbow_config.h		          -- Configures files for parameters of rainbow_16
rng.c		                  		-- PRNG from the example of NIST
rng.h				                  -- PRNG from the example of NIST
sign.c		                 		-- Wrapper to reduce API to the core functions of rainbow_16