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
function add_mediawiki_table_header()
{	
	local output_file=$1


	# Clear output
	echo -n "" > $output_file


	# Table title & header
	printf "{| class=\"wikitable sortable\" style=\"margin: auto;\"" >> $output_file
	printf "\n" >> $output_file
	printf "|+ Stream Ciphers Implementation Info" >> $output_file
	printf "\n" >> $output_file
	printf "|-" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Cipher" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | State Size (bits)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Key Size (bits)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | IV Size (bits)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Implementation Version" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Implementation Info" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Implementation Authors" >> $output_file
	printf "\n" >> $output_file
}


# Add MediaWiki table row
# Parameters:
# 	$1 - the output file
# 	$2 - the cipher name
# 	$3 - the cipher state size
# 	$4 - the cipher key size
# 	$5 - the cipher IV size
# 	$6 - the cipher implementation version
# 	$7 - the cipher implementation info
# 	$8 - the cipher implementation authors
function add_mediawiki_table_row()
{
	local output_file=$1
	local cipher_name=$2
	local cipher_state_size=$3
	local cipher_key_size=$4
	local cipher_iv_size=$5
	local cipher_implementation_version=$6
	local cipher_implementation_info=$7
	local cipher_implementation_authors=$8


	printf "|-" >> $output_file
	printf "\n" >> $output_file
	printf "! $cipher_name" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_state_size" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_key_size" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_iv_size" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_implementation_version" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_implementation_info" >> $output_file
	printf "\n" >> $output_file
	printf "| $cipher_implementation_authors" >> $output_file
	printf "\n" >> $output_file
}


# Add MediaWiki table footer
# Parameters:
# 	$1 - the output file
function add_mediawiki_table_footer()
{
	local output_file=$1

	
	printf "|}" >> $output_file
}
