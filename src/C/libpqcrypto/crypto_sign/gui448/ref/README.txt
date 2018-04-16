This folder gontains the c-code of our reference implementation of Gui(GF(2),448,513,32,28,2).

The folder contains the following files.
api.h			           	-- API for eBracs
blas.c			          -- Basic Linear algebra Library (BLAS)
blas_config.h			    -- Configure file for BLAS.
blas.h			         	-- Basic Linear algebra Library (BLAS)
gf16.c				        -- Library for arightmetic of GF(16)
gf16.h				        -- Library for arightmetic of GF(16)
gf16_tabs.h		      	-- Tables for Library for arightmetic of GF(16)
gfext_config.h		   	-- Configure file for Library for Extended Field
gfext.h			          -- Library for Extended Field
gfext_poly_gf2.c		  -- Find Unique root for polynomials over Extended Field for gf2
gfext_poly_gf2.h		  -- Find Unique root for polynomials over Extended Field for gf2
gui.c				          -- Core components for gui.
gui_config.h			    -- Configure file for gui.
gui.h				          -- Core components for gui.
gui_sig.c			        -- The signature system from gui.
gui_sig.h			        -- The signature system from gui.
hash_len_config.h		  -- Configure file for the length of HASH funciton used
hash_utils.c			    -- Library for HASH functions (adaptor for OpenSSL)
hash_utils.h			    -- Library for HASH functions
mpkc_config.h			    -- Configure for MQ functions
mpkc.h				        -- Library for MQ functions
prng_utils.c		     	-- Library for pseude random generator(PRNG)
prng_utils.h		     	-- Library for pseude random generator(PRNG)
rng.c			          	-- PRNG from the example of NIST
rng.h				          -- PRNG from the example of NIST
sign.c			         	-- Wrapper for reduce API to signature system for gui.