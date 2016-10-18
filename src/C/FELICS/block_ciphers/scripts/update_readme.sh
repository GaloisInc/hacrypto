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
# Call this script to update README file in each cipher folder source 
#	... implementation
#	./update_readme.sh
#


# The ciphers path
CIPHERS_PATH=../source/ciphers

# The README file path
README_FILE_PATH=../source/ciphers/CipherName_BlockSizeInBits_KeySizeInBits_v01/source/README


# Get current script path
script_path=$(dirname $0)


# Get the files matching the pattern
directories=$(ls -d $script_path/$CIPHERS_PATH/*)


source_file_path=$script_path/$README_FILE_PATH
for directory in $directories
do
	destination_file_path=$directory/source/README

	if [ $destination_file_path != $source_file_path ] ; then
		echo "Copy $source_file_path to $destination_file_path ..."	
		cp -f $source_file_path $destination_file_path
	fi
done
