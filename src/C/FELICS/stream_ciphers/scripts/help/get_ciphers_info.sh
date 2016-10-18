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
	echo " Call this script to get the ciphers iplementation information"
	echo " 	./get_ciphers_info.sh [{-h|--help}] [--version] [{-f|--format}=[0|1|2|3|4|5]] [{-c|--ciphers}=['Cipher1 Cipher2 ...']]"
	echo ""
	echo "	Options:"
	echo "		-h, --help"
	echo "			Display help information"
	echo "		--version"
	echo "			Display version information"
	echo "		-f, --format"
	echo "			Specifies which output format to use"
	echo "				0 - use all output formats below"
	echo "				1 - raw table"
	echo "				2 - MediaWiki table"
	echo "				3 - XML table"
	echo "				4 - LaTeX table"
	echo "				5 - CSV table"
	echo "				Default: 0"
	echo "		-c, --ciphers"
	echo "			Specifies for which ciphers to get the implementation information"
	echo "				List of values: 'CipherName_StateSizeInBits_KeySizeInBits_IVSizeInBits_v01 ...'"
	echo "				Default: all ciphers"
	echo ""
	echo "	Examples:"
	echo "		./get_ciphers_info.sh"
	echo "		./get_ciphers_info.sh --format=1"
	echo "		./get_ciphers_info.sh -f=2"
	echo ""

	exit
}
