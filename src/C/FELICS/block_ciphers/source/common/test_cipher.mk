#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
#
# This file is part of FELICS.
#
# FELICS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# FELICS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

#
# Call this makefile from a cipher source directory or build directory to build 
#	... the given cipher:
#	make -f ./../../../common/test_cipher.mk [help|pc|avr|msp|arm|pc-scenario1|
#		avr-scenario1|msp-scenario1|arm-scenario1|pc-scenario2|avr-scenario2|
#		msp-scenario2|arm-scenario2|cipher|scenario1|scenario2|test-cipher|
#		test-scenario1|test-scenario2|upload-cipher|upload-scenario1|
#		upload-scenario2|clean|cleanall]
#
# 	Examples: 
#		From cipher source directory or build directory:
#			make -f ./../../../common/Makefile clean
#			make -f ./../../../common/Makefile cipher
#			make -f ./../../../common/Makefile test-cipher
#			make -f ./../../../common/Makefile clean
#			make -f ./../../../common/Makefile scenario1
#			make -f ./../../../common/Makefile test-scenario1
#		
#		From cipher source directory:
#			make clean
#			make cipher
# 			make test-cipher
#			make clean
# 			make scenario1
# 			make test-scenario1
#


CIPHER_MAKEFILE=./../../../common/cipher.mk
BUILD_DIR = ./../build

OPTIONS=COMPILER_OPTIONS='-O3'


.PHONY: help pc avr msp arm pc-scenario1 avr-scenario1 msp-scenario1 \
	arm-scenario1 pc-scenario2 avr-scenario2 msp-scenario2 arm-scenario2 \
	cipher scenario1 scenario2 test-cipher test-scenario1 test-scenario2 \
	upload-cipher upload-scenario1 upload-scenario2 clean cleanall


help:
	@echo ""
	@echo -n "Call this makefile from a cipher source directory or build "
	@echo 		"directory to build the given cipher:"
	@echo -n "	make -f ./../source/Makefile [help|pc|avr|msp|arm|pc-scenario1|"
	@echo -n 		"avr-scenario1|msp-scenario1|arm-scenario1|pc-scenario2|"
	@echo -n 		"avr-scenario2|msp-scenario2|arm-scenario2|cipher|"
	@echo -n 		"scenario1|scenario2|test-cipher|test-scenario1|"
	@echo -n		"test-scenario2|upload-cipher|upload-scenario1|"
	@echo -n		"upload-scenario2|clean|cleanall]"
	@echo ""
	@echo ""
	@echo "	Examples: "
	@echo "		From cipher source directory or build directory:"
	@echo "			make -f ./../source/Makefile clean"
	@echo "			make -f ./../source/Makefile cipher"
	@echo "			make -f ./../source/Makefile test-cipher"
	@echo "			make -f ./../source/Makefile clean"
	@echo "			make -f ./../source/Makefile scenario1"
	@echo "			make -f ./../source/Makefile test-scenario1"
	@echo ""
	@echo "		From cipher source directory:"
	@echo "			make clean"
	@echo "			make cipher"
	@echo "			make test-cipher"
	@echo "			make clean"
	@echo "			make scenario1"
	@echo "			make test-scenario1"
	@echo ""



# Build cipher for PC in Release mode
pc:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS)

# Build cipher for AVR in Release mode
avr:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=AVR 

# Build cipher for MSP in Release mode
msp:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=MSP

# Build cipher for ARM in Release mode
arm:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=ARM


# Build scenario1 for PC in Release mode
pc-scenario1:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=PC SCENARIO=1

# Build scenario1 for AVR in Release mode
avr-scenario1:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=AVR SCENARIO=1

# Build scenario1 for MSP in Release mode
msp-scenario1:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=MSP SCENARIO=1

# Build scenario1 for ARM in Release mode
arm-scenario1:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=ARM SCENARIO=1


# Build scenario2 for PC in Release mode
pc-scenario2:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=PC SCENARIO=2

# Build scenario2 for AVR in Release mode
avr-scenario2:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=AVR SCENARIO=2

# Build scenario2 for MSP in Release mode
msp-scenario2:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=MSP SCENARIO=2

# Build scenario2 for ARM in Release mode
arm-scenario2:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) ARCHITECTURE=ARM SCENARIO=2



# Build cipher for PC in Debug mode
cipher:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) DEBUG=7 SCENARIO=0

# Build scenario1 for PC in Debug mode
scenario1:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) DEBUG=7 SCENARIO=1

# Build scenario2 for PC in Debug mode
scenario2:
	make -f $(CIPHER_MAKEFILE) $(OPTIONS) DEBUG=7 SCENARIO=2



# Test cipher. Use only after cipher
test-cipher:
	$(BUILD_DIR)/cipher.elf

# Test scenario 1. Use only after scenario1
test-scenario1:
	$(BUILD_DIR)/scenario1.elf

# Test scenario 2. Use only after scenario2
test-scenario2:
	$(BUILD_DIR)/scenario2.elf



# Upload ARM binary to the board. Use only after arm
upload-cipher:
	make -f $(CIPHER_MAKEFILE) ARCHITECTURE=ARM upload-cipher

# Upload ARM binary to the board. Use only after arm-scenario1
upload-scenario1:
	make -f $(CIPHER_MAKEFILE) ARCHITECTURE=ARM upload-scenario1

# Upload ARM binary to the board. Use only after arm-scenario2
upload-scenario2:
	make -f $(CIPHER_MAKEFILE) ARCHITECTURE=ARM upload-scenario2



# Run the ARM program on the board. Use only after upload-cipher, 
# 	upload-scenario1 or upload-scenario2
run:
	make -f $(CIPHER_MAKEFILE) ARCHITECTURE=ARM run



# Clean build directory
clean:
	make -f $(CIPHER_MAKEFILE) clean



# Clean all temporary files
cleanall:
	make -f $(CIPHER_MAKEFILE) cleanall
