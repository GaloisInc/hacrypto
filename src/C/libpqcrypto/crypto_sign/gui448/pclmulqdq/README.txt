This folder contains the c-code of our implementation of Gui(GF(2),448,513,32,28,2) using the PCLMULQDQ instruction set.

The folder contains the following files.
api.h				          -- API for eBracs
bitmat_prod_sse.h	  	-- Matrix production over GF(2) for field isomorphism. SSE instruciton set. 
blas.c			          -- Basic Linear algebra Library (BLAS)
blas_config.h		    	-- Configure file for BLAS.
blas.h			          -- Basic Linear algebra Library (BLAS)
gf16.c		          	-- Library for arithmetic of GF(16)
gf16.h			          -- Library for arithmetic of GF(16)
gf16_tabs.h			      -- Tables for Library for arithmetic of GF(16)
gfext_aesni.h			    -- Library for Extended Field. AESNI(pclmulqdq) instruction set.
gfext_config.h		    -- Configure file for Library for Extended Field
gfext.h			          -- Library for Extended Field
gfext_iso_184.c		    -- Tables for field isomorphism for GF(2^184) to GF(256^24)
gfext_iso_240.c		    -- Tables for field isomorphism for GF(2^240) to GF(256^30)
gfext_iso_312.c		    -- Tables for field isomorphism for GF(2^312) to GF(256^39)
gfext_iso_448.c		    -- Tables for field isomorphism for GF(2^448) to GF(256^56)
gfext_poly_gf2.c		  -- Find Unique root for polynomials over Extended Field for gf2
gfext_poly_gf2.h		  -- Find Unique root for polynomials over Extended Field for gf2
gui.c				          -- Core components for gui.
gui_config.h			    -- Configure file for gui.
gui.h				          -- Core components for gui.
gui_sig.c			        -- The signature system of gui.
gui_sig.h			        -- The signature system from gui.
hash_len_config.h		  -- Configure file for the length of HASH funciton used
hash_utils.c			    -- Library for HASH functions (adaptor for OpenSSL)
hash_utils.h			    -- Library for HASH functions (adaptor for OpenSSL)
mpkc_config.h			    -- Configure for MQ functions
mpkc.h			          -- Library for MQ functions
prng_utils.c			    -- Library for pseudo random number generator(PRNG)
prng_utils.h			    -- Library for pseudo random number generator(PRNG)
rng.c				          -- PRNG from the example of NIST
rng.h				          -- PRNG from the example of NIST
sign.c			          -- Wrapper to reduce the API to the signature system for gui