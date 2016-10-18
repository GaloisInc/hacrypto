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
	echo " Call this script to get the results"
	echo " 	./collect_ciphers_metrics.sh [{-h|--help}] [--version] [{-f|--format}=[0|1|2|3|4|5]] [{-a|--architectures}=['PC AVR MSP ARM']] [{-s|--scenarios}=['0 1 2']] [{-c|--ciphers}=['Cipher1 Cipher2 ...']] [{-p|--prefix}='...'] [{-co|--compiler_options}='...'] [{-i|incremental}=[0|1]]"
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
	echo "		-a, --architectures"
	echo "			Specifies for which archiectures to get the results"
	echo "				List of values: 'PC AVR MSP ARM'"
	echo "				Default: all architectures"
	echo "		-s, --scenarios"
	echo "			Specifies for which scenarios to get the results"
	echo "				List of values: '0 1 2'"
	echo "				Default: all scenarios"
	echo "		-c, --ciphers"
	echo "			Specifies for which ciphers to get the results"
	echo "				List of values: 'CipherName_BlockSizeInBits_KeySizeInBits_v01 ...'"
	echo "				Default: all ciphers"
	echo "		-p, --prefix"
	echo "			Specifies the results file prefix"
	echo "				Default: current date in 'YYYY_mm_dd' format"
	echo "		-co,--compiler_options"
	echo "			Specifies the compiler options"
	echo "				List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'"
	echo "				Default: all compiler options"
	echo "		-i, --incremental"
	echo "			Specifies if script should use an incremntal strategy (collect results just for new and modified implementations since the last run)"
	echo "				0 - do not use incrmental strategy"
	echo "				1 - use incremental strategy"
	echo "				Default: 1"
	echo ""
	echo "	Examples:"
	echo "		./get_results.sh -f=0"
	echo "		./get_results.sh --format=1"
	echo "		./get_results.sh -a='PC AVR' --scenarios=\"1 2\""
	echo ""

	exit
}
