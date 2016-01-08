####  Makefile provided for compilation of MSR ECCLib using the GNU GCC compiler on x64 CPUs  ####
####  See the accompanying README file for instructions.                                      ####

CC=gcc
CFLAGS=-c -O3 -D _AMD64_ -D __LINUX__ -D _AVX_ -D TARGET_GENERIC=0 -D USE_ASM=1
LDFLAGS=
OBJECTS=curves.o ecc256.o ecc384.o ecc512.o fp.o extras.o fp256_x64_a.o fp384_x64_a.o fp512_x64_a.o ecc_additional.o
OBJECTS_CRYPTO_TESTS=$(OBJECTS) crypto_tests.o 
OBJECTS_ECC_TESTS=$(OBJECTS) ecc_tests.o
OBJECTS_FP_TESTS=$(OBJECTS) fp_tests.o
OBJECTS_SAMPLE_TESTS=$(OBJECTS) sample.o
OBJECTS_ALL=$(OBJECTS) crypto_tests.o ecc_tests.o fp_tests.o sample.o

crypto_tests: $(OBJECTS_CRYPTO_TESTS)
	$(CC) -o crypto_tests $(OBJECTS_CRYPTO_TESTS)

ecc_tests: $(OBJECTS_ECC_TESTS)
	$(CC) -o ecc_tests $(OBJECTS_ECC_TESTS)

fp_tests: $(OBJECTS_FP_TESTS)
	$(CC) -o fp_tests $(OBJECTS_FP_TESTS)

sample: $(OBJECTS_SAMPLE_TESTS)
	$(CC) -o sample $(OBJECTS_SAMPLE_TESTS)

curves.o: MSR_ECClib/curves.c MSR_ECClib/msr_ecclib.h
	$(CC) $(CFLAGS) MSR_ECClib/curves.c

ecc256.o: MSR_ECClib/ecc256.c MSR_ECClib/ecc_template.c MSR_ECClib/fp_template.c MSR_ECClib/ecc_crypto.c MSR_ECClib/msr_ecclib.h
	$(CC) $(CFLAGS) MSR_ECClib/ecc256.c

ecc384.o: MSR_ECClib/ecc384.c MSR_ECClib/ecc_template.c MSR_ECClib/fp_template.c MSR_ECClib/ecc_crypto.c MSR_ECClib/msr_ecclib.h
	$(CC) $(CFLAGS) MSR_ECClib/ecc384.c

ecc512.o: MSR_ECClib/ecc512.c MSR_ECClib/ecc_template.c MSR_ECClib/fp_template.c MSR_ECClib/ecc_crypto.c MSR_ECClib/msr_ecclib.h
	$(CC) $(CFLAGS) MSR_ECClib/ecc512.c

fp.o: MSR_ECClib/fp.c MSR_ECClib/msr_ecclib_priv.h MSR_ECClib/msr_ecclib.h 
	$(CC) $(CFLAGS) MSR_ECClib/fp.c

ecc_additional.o: MSR_ECClib/ecc_additional.c MSR_ECClib/msr_ecclib_priv.h MSR_ECClib/msr_ecclib.h 
	$(CC) $(CFLAGS) -mavx MSR_ECClib/ecc_additional.c

fp256_x64_a.o: MSR_ECClib/AMD64/fp256_x64_a.S MSR_ECClib/AMD64/fp_x64.h
	$(CC) $(CFLAGS) MSR_ECClib/AMD64/fp256_x64_a.S

fp384_x64_a.o: MSR_ECClib/AMD64/fp384_x64_a.S MSR_ECClib/AMD64/fp_x64.h
	$(CC) $(CFLAGS) MSR_ECClib/AMD64/fp384_x64_a.S

fp512_x64_a.o: MSR_ECClib/AMD64/fp512_x64_a.S MSR_ECClib/AMD64/fp_x64.h
	$(CC) $(CFLAGS) MSR_ECClib/AMD64/fp512_x64_a.S

extras.o: Tests/extras.c Tests/tests.h MSR_ECClib/msr_ecclib.h
	$(CC) $(CFLAGS) -I MSR_ECClib Tests/extras.c

crypto_tests.o: Tests/crypto_tests.c MSR_ECClib/msr_ecclib.h MSR_ECClib/msr_ecclib_priv.h Tests/tests.h
	$(CC) $(CFLAGS) -I MSR_ECClib Tests/crypto_tests.c

ecc_tests.o: Tests/ecc_tests.c MSR_ECClib/msr_ecclib.h MSR_ECClib/msr_ecclib_priv.h Tests/tests.h
	$(CC) $(CFLAGS) -I MSR_ECClib Tests/ecc_tests.c

fp_tests.o: Tests/fp_tests.c MSR_ECClib/msr_ecclib.h Tests/tests.h
	$(CC) $(CFLAGS) -I MSR_ECClib Tests/fp_tests.c

sample.o: Sample/sample.c MSR_ECClib/msr_ecclib.h Tests/tests.h
	$(CC) $(CFLAGS) -I MSR_ECClib Sample/sample.c

.PHONY: clean

clean:
	rm crypto_tests ecc_tests fp_tests sample $(OBJECTS_ALL)

