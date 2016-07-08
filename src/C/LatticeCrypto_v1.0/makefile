####  Makefile for compilation on Linux  ####

OPT=-O3     # Optimization option by default

ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

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
endif

ifeq "$(ARCH)" "ARM"
    ARM_SETTING=-lrt
endif

cc=$(COMPILER)
CFLAGS=-c $(OPT) $(ADDITIONAL_SETTINGS) $(SIMD) -D $(ARCHITECTURE) -D __LINUX__ $(USE_AVX2) $(USE_ASM) $(USE_GENERIC)
LDFLAGS=
ifeq "$(GENERIC)" "TRUE"
    OTHER_OBJECTS=ntt.o
else
ifeq "$(ASM)" "TRUE"
    OTHER_OBJECTS=ntt_x64.o consts.o
    ASM_OBJECTS=ntt_x64_asm.o error_asm.o
endif 
endif
OBJECTS=kex.o random.o ntt_constants.o $(ASM_OBJECTS) $(OTHER_OBJECTS)
OBJECTS_TEST=tests.o test_extras.o $(OBJECTS)
OBJECTS_ALL=$(OBJECTS) $(OBJECTS_TEST)

test: $(OBJECTS_TEST)
	$(CC) -o test $(OBJECTS_TEST) $(ARM_SETTING)

kex.o: kex.c LatticeCrypto_priv.h
	$(CC) $(CFLAGS) kex.c

random.o: random.c LatticeCrypto_priv.h
	$(CC) $(CFLAGS) random.c

ntt_constants.o: ntt_constants.c LatticeCrypto_priv.h
	$(CC) $(CFLAGS) ntt_constants.c
    
ifeq "$(GENERIC)" "TRUE"
    ntt.o: generic/ntt.c LatticeCrypto_priv.h
	    $(CC) $(CFLAGS) generic/ntt.c 
else   
ifeq "$(ASM)" "TRUE"
    ntt_x64.o: AMD64/ntt_x64.c
	    $(CC) $(CFLAGS) AMD64/ntt_x64.c
    ntt_x64_asm.o: AMD64/ntt_x64_asm.S
	    $(CC) $(CFLAGS) AMD64/ntt_x64_asm.S
    error_asm.o: AMD64/error_asm.S
	    $(CC) $(CFLAGS) AMD64/error_asm.S
    consts.o: AMD64/consts.c
	    $(CC) $(CFLAGS) AMD64/consts.c
endif
endif

test_extras.o: tests/test_extras.c tests/test_extras.h LatticeCrypto_priv.h
	$(CC) $(CFLAGS) tests/test_extras.c

tests.o: tests/tests.c LatticeCrypto_priv.h
	$(CC) $(CFLAGS) tests/tests.c

.PHONY: clean

clean:
	rm -f test ntt.o ntt_x64.o ntt_x64_asm.o error_asm.o consts.o $(OBJECTS_ALL)

