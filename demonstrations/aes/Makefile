include Makefile.local

all: clean saw cryptol cryptol-gen

cryptol: cryptol-typecheck cryptol-validate

cryptol-typecheck:
	cryptol -c ":quit" aes.cry
	cryptol -c ":quit" AESTBox.cry

cryptol-validate:
	cryptol -c ":check prop_tests" aes.cry
	cryptol -c ":set tests=10000" \
		-c ":check AESTests" \
		-c ":check sboxUnsboxInverse" \
		-c ":check keyExpansionInjective"\
		-c ":check encDecInverse" \
		AESTBox.cry

# If you have a fat maching and patience, run the proofs!
cryptol-verify:
	cryptol -c ":prove prop_tests" aes.cry
	cryptol -c ":prove AESTests" \
		-c ":prove sboxUnsboxInverse" \
		-c ":prove keyExpansionInjective" \
		-c ":prove encDecInverse" \
		AESTBox.cry

compile-c:
	$(CLANG) -c -emit-llvm -o aes.bc aes.c
	$(LLVMDIS) -o aes.ll aes.bc
	$(CLANG) -o aes aes.c

saw: compile-c
	saw aes.saw

# svcspgen and cryptol-gen are not in any public release of Cryptol.
# The artifacts resulting from these build rules are included in this
# repository for demonstration purposes.

# System Verilog generation from original AES specification.
sv-gen:
#	$(AT_GALOIS)
	rm -fR gen/aes-svcsp
	mkdir -p gen/aes-svcsp
	svcspgen -c aes.config
	mv SVCSP* AESEncrypt* gen/aes-svcsp/

# LLVM generation
cryptol-gen: cryptol-gen-original cryptol-gen-tbox

# LLVM generation from original AES specification.
cryptol-gen-original:
	rm -fR gen/aes-llvm/
	cryptol-gen aes.gen
	cd gen/aes-llvm/ && $(MAKE)

# LLVM generation from the TBox version of the AES specification.
cryptol-gen-tbox:
	rm -fR gen/aes-tbox-llvm/
	cryptol-gen AESTBox.gen
	cd gen/aes-tbox-llvm/ && $(MAKE)

clean:
	rm -fR *.bc gen aes *.sv *.sv.json *.ll
