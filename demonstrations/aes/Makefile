include Makefile.local

# All build rules are documented and include typical wall clock times
# to run on a modern MacBook Pro.

all: clean saw cryptol cryptol-gen

cryptol: cryptol-typecheck cryptol-validate

# Typecheck all specifications (1 second).
cryptol-typecheck:
	cryptol -c ":quit" aes.cry
	cryptol -c ":quit" AESTBox.cry

# Validate all specifications by executing 1,000 random tests 
# (100 seconds).
cryptol-validate:
	cryptol -c ":check prop_tests" aes.cry
	cryptol -c ":set tests=1000" \
		-c ":check AESTests" \
		-c ":check sboxUnsboxInverse" \
		-c ":check keyExpansionInjective"\
		-c ":check encDecInverse" \
		AESTBox.cry

# Formally verify all properties.  If you have a fat maching and
# patience, run the proofs! (x hours)
cryptol-verify:
	cryptol -c ":prove prop_tests" aes.cry
	cryptol -c ":prove AESTests" \
		-c ":prove sboxUnsboxInverse" \
		-c ":prove keyExpansionInjective" \
		-c ":prove encDecInverse" \
		AESTBox.cry

# Compile the synthesized C implementation of encrypt.
compile-c:
	$(CLANG) -c -emit-llvm -o aes.bc aes.c
	$(LLVMDIS) -o aes.ll aes.bc
	$(CLANG) -o aes aes.c

# Formally verify that the synthesized version of encrypt is correct
# (x minutes).
saw: compile-c
	saw aes.saw

# Synthesis

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
