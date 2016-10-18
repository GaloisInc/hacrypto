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
# Functions to generate CSV data table
#


# Add CSV table header
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the architecture
function add_csv_table_header()
{
	local output_file=$1
	local scenario=$2
	local architecture=$3
	

	# Clear output
	echo -n "" > $output_file

	case $scenario in
		$SCRIPT_SCENARIO_0)
			# First header row
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Cipher Info" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Implementation Info" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Code Size" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "RAM" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Execution Time" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "\n" >> $output_file


			# Second header row
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Stack" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Data" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "\n" >> $output_file


			# Third header row
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Cipher" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "State Size (bits)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Key Size (bits)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "IV (bits)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Version" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Language" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Options" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "S (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "E (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "S + E (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "S (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "E (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "S (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "E (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Common (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Total (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "S (cycles)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "E (cycles)" >> $output_file

			printf "\n" >> $output_file
			;;
		$SCRIPT_SCENARIO_1)
			# First header row
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Cipher Info" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Implementation Info" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Code Size" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "RAM" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Execution Time" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "\n" >> $output_file


			# Second header row
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Stack" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Data" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER$CSV_TEXT_DELIMITER" >> $output_file

			printf "\n" >> $output_file


			# Third header row
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Cipher" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "State Size (bits)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Key Size (bits)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "IV (bits)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Version" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Language" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Options" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "S (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "E (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "S + E (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "S (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "E (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "S (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "E (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Common (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Total (bytes)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "S (cycles)" >> $output_file

			printf "$CSV_FIELD_DELIMITER" >> $output_file
			printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "E (cycles)" >> $output_file

			printf "\n" >> $output_file
			;;
	esac
}


# Add CVS table row
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the cipher name
#	$4 - the cipher state size
#	$5 - the cipher key size
#	$6 - the cipher IV size
#	$7 - the cipher implementation version
#	$8 - the cipher implementation language
#	$9 - the cipher implementation compiler options
#	$10 ... - cipher metrics values
function add_csv_table_row()
{
	local output_file=$1
	local scenario=$2
	local cipher_name=$3
	local cipher_state_size=$4
	local cipher_key_size=$5
	local cipher_iv_size=$6
	local cipher_implementation_version=$7
	local cipher_implementation_language=$8
	local cipher_implementation_compiler_options=$9
	local cipher_metrics_values=( ${@:10} )


	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "$cipher_name" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $cipher_state_size >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $cipher_key_size >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $cipher_iv_size >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $cipher_implementation_version >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $cipher_implementation_language >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_EQUAL_DELIMITER$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "$cipher_implementation_compiler_options" >> $output_file

	
	for value in ${cipher_metrics_values[@]}
	do
		printf "$CSV_FIELD_DELIMITER" >> $output_file
		printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" $value >> $output_file
	done
	printf "\n" >> $output_file
}


# Add CSV table footer
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
function add_csv_table_footer()
{
	local output_file=$1
	local scenario=$2
	

	case $scenario in
		$SCRIPT_SCENARIO_0)
			;;
		$SCRIPT_SCENARIO_1)
			;;
	esac
}
