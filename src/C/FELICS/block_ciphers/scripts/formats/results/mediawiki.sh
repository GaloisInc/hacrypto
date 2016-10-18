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

#
# Functions to generate MediaWiki data table
#


# Add MediaWiki table header
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the architecture
function add_mediawiki_table_header()
{	
	local output_file=$1
	local scenario=$2
	local architecture=$3


	# Clear output
	echo -n "" > $output_file

	case $scenario in
		$SCRIPT_SCENARIO_0)
			# Table title & header
			printf "{| class=\"wikitable sortable\" style=\"margin: auto;\"" >> $output_file
			printf "\n" >> $output_file
			printf "|+ Architecture: $architecture; Scenario: $scenario" >> $output_file
			printf "\n" >> $output_file
			printf "|-" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"3\" rowspan=\"2\" | Cipher Info" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"3\" rowspan=\"2\" | Implementation Info" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"5\" rowspan=\"2\" | Code Size" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"10\" | RAM" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"4\" rowspan=\"2\" | Execution Time" >> $output_file
			printf "\n" >> $output_file
			printf "|-" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"4\" | Stack" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"6\" | Data" >> $output_file
			printf "\n" >> $output_file
			printf "|-" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Cipher" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Block Size (bits)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Key Size (bits)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Version" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Language" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Options" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | EKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | DKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | D (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | EKS+E+DKS+D (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | EKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | DKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | D (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | EKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | DKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | D (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Common (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Total (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | EKS (cycles)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (cycles)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | DKS (cycles)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | D (cycles)" >> $output_file
			printf "\n" >> $output_file
			;;
		$SCRIPT_SCENARIO_1)
			# Table title & header
			printf "{| class=\"wikitable sortable\" style=\"margin: auto;\"" >> $output_file
			printf "\n" >> $output_file
			printf "|+ Architecture: $architecture; Scenario: $scenario" >> $output_file
			printf "\n" >> $output_file
			printf "|-" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"3\" rowspan=\"2\" | Cipher Info" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"3\" rowspan=\"2\" | Implementation Info" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"5\" rowspan=\"2\" | Code Size" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"10\" | RAM" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"4\" rowspan=\"2\" | Execution Time" >> $output_file
			printf "\n" >> $output_file
			printf "|-" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"4\" | Stack" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"6\" | Data" >> $output_file
			printf "\n" >> $output_file
			printf "|-" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Cipher" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Block Size (bits)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Key Size (bits)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Version" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Language" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Options" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | EKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | DKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | D (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | EKS+E+DKS+D (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | EKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | DKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | D (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | EKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | DKS (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | D (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Common (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Total (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | EKS (cycles)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (cycles)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | DKS (cycles)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | D (cycles)" >> $output_file
			printf "\n" >> $output_file
			;;
		$SCRIPT_SCENARIO_2)
			# Table title & header
			printf "{| class=\"wikitable sortable\" style=\"margin: auto;\"" >> $output_file
			printf "\n" >> $output_file
			printf "|+ Architecture: $architecture; Scenario: $scenario" >> $output_file
			printf "\n" >> $output_file
			printf "|-" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"3\" rowspan=\"2\" | Cipher Info" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"3\" rowspan=\"2\" | Implementation Info" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" rowspan=\"2\" | Code Size" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" colspan=\"2\" | RAM" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" rowspan=\"2\" | Execution Time" >> $output_file
			printf "\n" >> $output_file
			printf "|-" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Stack" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Data" >> $output_file
			printf "\n" >> $output_file
			printf "|-" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Cipher" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Block Size (bits)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Key Size (bits)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Version" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Language" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Options" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | Data (bytes)" >> $output_file
			printf "\n" >> $output_file
			printf "! scope=\"col\" | E (cycles)" >> $output_file
			printf "\n" >> $output_file
			;;
	esac
}


# Add MediaWiki table row
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the cipher name
#	$4 - the cipher block size
#	$5 - the cipher key size
#	$6 - the cipher implementation version
#	$7 - the cipher implementation language
#	$8 - the cipher implementation compiler options
#	$9 ... - cipher metrics values
function add_mediawiki_table_row()
{
	local output_file=$1
	local scenario=$2
	local cipher_name=$3
	local cipher_block_size=$4
	local cipher_key_size=$5
	local cipher_implementation_version=$6
	local cipher_implementation_language=$7
	local cipher_implementation_compiler_options=$8
	local cipher_metrics_values=( ${@:9} )


	printf "|-" >> $output_file
	printf "\n" >> $output_file
	printf "! $cipher_name" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_block_size" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_key_size" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_implementation_version" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_implementation_language" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_implementation_compiler_options" >> $output_file
	printf "\n" >> $output_file


	for value in ${cipher_metrics_values[@]}
	do
		printf "| %s" $value >> $output_file
		printf "\n" >> $output_file
	done
}


# Add MediaWiki table footer
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
function add_mediawiki_table_footer()
{
	local output_file=$1
	local scenario=$2

	
	printf "|}" >> $output_file
}
