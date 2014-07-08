all: callsha framac_val_compare

framac_val_compare: 
	frama-c -val *.c hashes.h -main compare_vst_NSS -print -slevel 3000 -machdep x86_64 > frama_c_run.log	
callsha:
	gcc callsha.c sha_vst.c sha_nss.c lib.c -L/usr/local/lib -L. -lsodium
