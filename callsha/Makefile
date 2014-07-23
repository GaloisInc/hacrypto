CC=gcc
OFILES= callsha.o sha_vst.o sha_nss.o lib.o

all: lib 

frama-c : framac_val_compare

framac_val_compare: 
	frama-c -val callsha.c lib.c sha_nss.c sha_vst.c framac_entry.c hashes.h /share/frama-c/builtin.c -main compare_vst_NSS_3 -print -slevel 3000 -machdep x86_64 > frama_c_run.log	

callsha:
	$(CC) callsha.c sha_vst.c sha_nss.c lib.c -L/usr/local/lib -L. -lsodium
	

lib : $(OFILES) 
	ar rcs test_sha.a $(OFILES)

%.o: %.c 
	$(CC) -c -o $@ $< 
	
