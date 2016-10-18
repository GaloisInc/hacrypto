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
# Call this makefile to build all ciphers:
#	make [ARCHITECTURE=[AVR|MSP|ARM|PC]] [DEBUG=[0|1|3|7]] [all|clean|cleanall]
#
#	Examples:
#		make
#		make ARCHITECTURE=PC DEBUG=1
#		make clean
#


CIPHERDIR = ./ciphers
#EXAMPLECIPHER = ./ciphers/CipherName_BlockSizeInBits_KeySizeInBits_v01

ALLCIPHERS = $(wildcard $(CIPHERDIR)/*)
CIPHERS = $(filter-out $(EXAMPLECIPHER), $(ALLCIPHERS))
DIRS = $(addsuffix /build/, $(CIPHERS))

CIPHERMAKEFILE = ./../../../common/cipher.mk


DELIMITER = ==========


.PHONY : all clean cleanall


all:
	@echo $(DELIMITER) Begin building all ciphers - $@ $(DELIMITER)
	$(foreach dir, $(DIRS), make -C $(dir) -f $(CIPHERMAKEFILE) $@ &&) true
	@echo $(DELIMITER) End building all ciphers - $@ $(DELIMITER)


clean:
	@echo $(DELIMITER) Begin cleaning all ciphers - $@ $(DELIMITER)
	rm -f *~
	$(foreach dir, $(DIRS), make -C $(dir) -f $(CIPHERMAKEFILE) $@ &&) true
	@echo $(DELIMITER) End cleaning all ciphers - $@ $(DELIMITER)


cleanall:
	@echo $(DELIMITER) Begin cleaning all ciphers - $@ $(DELIMITER)
	rm -f *~
	$(foreach dir, $(DIRS), make -C $(dir) -f $(CIPHERMAKEFILE) $@ &&) true
	@echo $(DELIMITER) End cleaning all ciphers - $@ $(DELIMITER)
