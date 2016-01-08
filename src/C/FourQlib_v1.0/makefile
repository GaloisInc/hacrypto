####  Makefile for compilation using the GNU GCC compiler  ####

OPT=-O3     # Optimization option by default

ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
endif

ADDITIONAL_SETTINGS=
ifeq "$(SET)" "EXTENDED"
    ADDITIONAL_SETTINGS=-fwrapv -fomit-frame-pointer -march=native
endif

ifeq "$(ASM)" "TRUE"
    USE_ASM=-D _ASM_
endif

ifeq "$(GENERIC)" "TRUE"
    USE_GENERIC=-D _GENERIC_
endif

ifeq "$(AVX2)" "TRUE"
    USE_AVX2=-D _AVX2_
    SIMD=-mavx2
else ifeq "$(AVX)" "TRUE"
    USE_AVX=-D _AVX_
    SIMD=-mavx
endif

ifeq "$(ARCH)" "ARM"
    ARM_SETTING=-lrt
endif

ifeq "$(USE_ENDO)" "TRUE"
    USE_ENDOMORPHISMS=-D USE_ENDO
endif

CC=gcc
CFLAGS=-c $(OPT) $(ADDITIONAL_SETTINGS) $(SIMD) -D $(ARCHITECTURE) -D __LINUX__ $(USE_AVX) $(USE_AVX2) $(USE_ASM) $(USE_GENERIC) $(USE_ENDOMORPHISMS)
LDFLAGS=
ifneq "$(GENERIC)" "TRUE"
ifeq "$(AVX2)" "TRUE"
    ASM_OBJECTS=fp2_1271_AVX2.o
else
    ASM_OBJECTS=fp2_1271.o
endif 
endif
OBJECTS=FourQ.o eccp2.o eccp2_no_endo.o eccp2_core.o $(ASM_OBJECTS)
OBJECTS_ECC_TEST=ecc_tests.o test_extras.o $(OBJECTS) 
OBJECTS_ALL=$(OBJECTS) $(OBJECTS_ECC_TEST)

ecc_test: $(OBJECTS_ECC_TEST)
	$(CC) -o ecc_test $(OBJECTS_ECC_TEST) $(ARM_SETTING)

FourQ.o: FourQ.c FourQ.h
	$(CC) $(CFLAGS) FourQ.c

eccp2_core.o: eccp2_core.c FourQ.h AMD64/fp_x64.h
	$(CC) $(CFLAGS) eccp2_core.c

eccp2.o: eccp2.c FourQ.h
	$(CC) $(CFLAGS) eccp2.c

eccp2_no_endo.o: eccp2_no_endo.c FourQ.h
	$(CC) $(CFLAGS) eccp2_no_endo.c
    
ifeq "$(AVX2)" "TRUE"
    fp2_1271_AVX2.o: AMD64/fp2_1271_AVX2.S
	    $(CC) $(CFLAGS) AMD64/fp2_1271_AVX2.S
else
    fp2_1271.o: AMD64/fp2_1271.S
	    $(CC) $(CFLAGS) AMD64/fp2_1271.S
endif

test_extras.o: test_extras.c FourQ.h
	$(CC) $(CFLAGS) test_extras.c

ecc_tests.o: ecc_tests.c FourQ.h
	$(CC) $(CFLAGS) ecc_tests.c

.PHONY: clean

clean:
	rm ecc_test fp2_1271.o fp2_1271_AVX2.o $(OBJECTS_ALL)

