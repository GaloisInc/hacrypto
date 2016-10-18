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
function add_csv_table_header()
{
	local output_file=$1
	

	# Clear output
	echo -n "" > $output_file

	
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Cipher" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Block Size (bits)" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Key Size (bits)" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file	
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Implementation Version" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Implementation Info" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "Implementation Authors" >> $output_file

	printf "\n" >> $output_file
}


# Add CSV table row
# Parameters:
# 	$1 - the output file
# 	$2 - the cipher name
# 	$3 - the cipher block size
# 	$4 - the cipher key size
# 	$5 - the cipher implementation version
# 	$6 - the cipher implementation info
# 	$7 - the cipher implementation authors
function add_csv_table_row()
{
	local output_file=$1
	local cipher_name=$2
	local cipher_block_size=$3
	local cipher_key_size=$4
	local cipher_implementation_version=$5
	local cipher_implementation_info=$6
	local cipher_implementation_authors=$7


	cipher_implementation_info=${cipher_implementation_info//\"/\"\"}


	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "$cipher_name" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "$cipher_block_size" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "$cipher_key_size" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "$cipher_implementation_version" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "$cipher_implementation_info" >> $output_file

	printf "$CSV_FIELD_DELIMITER" >> $output_file
	printf "$CSV_TEXT_DELIMITER%s$CSV_TEXT_DELIMITER" "$cipher_implementation_authors" >> $output_file
	
	printf "\n" >> $output_file
}


# Add CSV table footer
# Parameters:
# 	$1 - the output file
function add_csv_table_footer()
{
	local output_file=$1
}
