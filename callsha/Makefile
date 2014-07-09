all: callsha framac_val_compare

framac_val_compare: 
	frama-c -val callsha.c lib.c sha_nss.c sha_vst.c framac_entry.c hashes.h /share/frama-c/builtin.c -main compare_vst_NSS_3 -print -slevel 3000 -machdep x86_64 > frama_c_run.log	
callsha:
	gcc callsha.c sha_vst.c sha_nss.c lib.c -L/usr/local/lib -L. -lsodium
