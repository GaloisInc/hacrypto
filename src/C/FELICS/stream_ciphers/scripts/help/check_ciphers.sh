#!/bin/bash

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


# Display help information
function display_help()
{
	echo ""
	echo " Call this script to check if the ciphers implementations are compliant with the framework"
	echo " 	./check_ciphers.sh [{-h|--help}] [--version] [{-v|--verbosity}=[0|1|2]] [{-a|--architectures}=['PC AVR MSP ARM']] [{-s|--scenarios}=['0 1']] [{-c|--ciphers}=['Cipher1 Cipher2 ...']] [{-co|--compiler_options}='...']"
	echo ""
	echo "	Options:"
	echo "		-h, --help"
	echo "			Display help information"
	echo "		--version"
	echo "			Display version information"
	echo "		-v, --verbosity"
	echo "			Specifies the verbosity level to use"
	echo "				0 - display only not compliant ciphers"
	echo "				1 - display all ciphers"
	echo "				2 - display all ciphers with details"
	echo "				Default: 0"
	echo "		-a, --architectures"
	echo "			Specifies for which archiectures to check the ciphers for compliance"
	echo "				List of values: 'PC AVR MSP ARM'"
	echo "				Default: all architectures"
	echo "		-s, --scenarios"
	echo "			Specifies for which scenarios to check the ciphers for compliance"
	echo "				List of values: '0 1'"
	echo "				Default: all scenarios"
	echo "		-c, --ciphers"
	echo "			Specifies which ciphers to be checked for compliance"
	echo "				List of values: 'CipherName_StateSizeInBits_KeySizeInBits_IVSizeInBits_v01 ...'"
	echo "				Default: all ciphers"
	echo "		-co,--compiler_options"
	echo "			Specifies the compiler options"
	echo "				List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'"
	echo "				Default: all compiler options"
	echo ""
	echo "	Examples:"
	echo "		./check_ciphers.sh -f=0"
	echo "		./check_ciphers.sh --verbosity=1"
	echo "		./check_ciphers.sh -a='PC AVR' --scenarios=\"0 1\""
	echo ""

	exit
}
