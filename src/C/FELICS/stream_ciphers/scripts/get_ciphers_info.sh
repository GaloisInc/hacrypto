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
# Call this script to get the ciphers iplementation information
# 	./get_ciphers_info.sh [{-h|--help}] [--version] [{-f|--format}=[0|1|2|3|4|5]] [{-c|--ciphers}=['Cipher1 Cipher2 ...']]
#
#	Options:
#		-h, --help
#			Display help information
#		-f, --format
#			Specifies which output format to use
#				0 - use all output formats below
#				1 - raw table
#				2 - MediaWiki table
#				3 - XML table
#				4 - LaTeX table
#				5 - CSV table
#				Default: 0
#		-c, --ciphers
#			Specifies for which ciphers to get the implementation information
#				List of values: 'CipherName_StateSizeInBits_KeySizeInBits_IVSizeInBits_v01 ...'
#				Default: all ciphers
#
#	Examples:
#		./get_ciphers_info.sh
#		./get_ciphers_info.sh --format=1
#		./get_ciphers_info.sh -f=2
#


# Get current script path
script_path=$(dirname $0)

# Include constants files
source $script_path/constants/constants.sh
source $script_path/constants/get_ciphers_info.sh

# Include help file
source $script_path/help/get_ciphers_info.sh

# Include validation functions
source $script_path/common/validate.sh

# Include version file
source $script_path/common/version.sh


# Default values
SCRIPT_FORMAT=$SCRIPT_FORMAT_0


# Parse script arguments
for i in "$@"
do
	case $i in
		-h|--help)
			display_help
			shift
			;;
		--version)
			display_version
			shift
			;;
		-f=*|--format=*)
			SCRIPT_FORMAT="${i#*=}"
			shift
			;;
		-c=*|--ciphers=*)
			SCRIPT_USER_CIPHERS="${i#*=}"
			shift
			;;

		*)
			# Unknown option
			;;
	esac
done


echo "Script settings:"
echo -e "\t SCRIPT_FORMAT \t = $SCRIPT_FORMAT"


# Validate format
validate_format $SCRIPT_FORMAT


# Include output format
case $SCRIPT_FORMAT in
	$SCRIPT_FORMAT_0)
		source $script_path/formats/info/raw.sh
		source $script_path/formats/info/mediawiki.sh
		source $script_path/formats/info/xml.sh
		source $script_path/formats/info/latex.sh
		source $script_path/formats/info/csv.sh
		;;
	$SCRIPT_FORMAT_1)
		source $script_path/formats/info/raw.sh
		;;
	$SCRIPT_FORMAT_2)
		source $script_path/formats/info/mediawiki.sh
		;;
	$SCRIPT_FORMAT_3)
		source $script_path/formats/info/xml.sh
		;;
	$SCRIPT_FORMAT_4)
		source $script_path/formats/info/latex.sh
		;;
	$SCRIPT_FORMAT_5)
		source $script_path/formats/info/csv.sh
		;;
	*)
		# Unknown format
		echo "Unknown format!"
		exit
		;;
esac


# Change current directory to script source path directory
if [ '.' != $script_path ] ; then
	cd $script_path
fi


# Set the current working directory
current_directory=$(pwd)
echo "Begin get ciphers info - $current_directory"


# Change current working directory
cd $current_directory/$CIPHERS_PATH
echo "Changed working directory: $(pwd)"
echo ""


# Get the number of directories
directories_number=$(find . -maxdepth 1 -type d | wc -l)

if [ 0 -eq $directories_number ] ; then
	echo "There is no directory here: '$(pwd)'!"
	echo "Exit!"
	exit
fi

# Get the files matching the pattern
ciphers_directories=$(ls -d *)


# If user ciphers are not set, use all ciphers
if [ -n "$SCRIPT_USER_CIPHERS" ]; then
	declare -a directories
	for cipher in $SCRIPT_USER_CIPHERS
	do
		cipher_found=$FALSE
		for cipher_directory in $ciphers_directories
		do
			if [ $cipher == $cipher_directory ] ; then
				directories+=($cipher_directory)
				cipher_found=$TRUE
				break
			fi
		done
		if [ $FALSE == $cipher_found ] ; then
			echo "Unknown cipher '$cipher'!"
			exit
		fi
	done
	build=$SCRIPT_BUILD_ENABLED
else
	directories=$ciphers_directories
fi


script_raw_output=$current_directory/$SCRIPT_OUTPUT_PATH$INFO_OUTPUT_FILE_NAME$SCRIPT_RAW_OUTPUT_EXTENSION
script_mediawiki_output=$current_directory/$SCRIPT_OUTPUT_PATH$INFO_OUTPUT_FILE_NAME$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
script_xml_output=$current_directory/$SCRIPT_OUTPUT_PATH$INFO_OUTPUT_FILE_NAME$SCRIPT_XML_OUTPUT_EXTENSION
script_latex_output=$current_directory/$SCRIPT_OUTPUT_PATH$INFO_OUTPUT_FILE_NAME$SCRIPT_LATEX_OUTPUT_EXTENSION
script_csv_output=$current_directory/$SCRIPT_OUTPUT_PATH$INFO_OUTPUT_FILE_NAME$SCRIPT_CSV_OUTPUT_EXTENSION


# Add table header
case $SCRIPT_FORMAT in
	$SCRIPT_FORMAT_0)
		add_raw_table_header $script_raw_output $scenario $architecture
		add_mediawiki_table_header $script_mediawiki_output $scenario $architecture
		add_xml_table_header $script_xml_output $scenario $architecture
		add_latex_table_header $script_latex_output $scenario $architecture
		add_csv_table_header $script_csv_output $scenario $architecture
		;;
	$SCRIPT_FORMAT_1)
		add_raw_table_header $script_raw_output $scenario $architecture
		;;
	$SCRIPT_FORMAT_2)
		add_mediawiki_table_header $script_mediawiki_output $scenario $architecture
		;;
	$SCRIPT_FORMAT_3)
		add_xml_table_header $script_xml_output $scenario $architecture
		;;
	$SCRIPT_FORMAT_4)
		add_latex_table_header $script_latex_output $scenario $architecture
		;;
	$SCRIPT_FORMAT_5)
		add_csv_table_header $script_csv_output $scenario $architecture
		;;
esac


for directory in ${directories[@]}
do
	cd $directory/build

	
	# Get the cipher name
	cipher_directory_name=$(basename -- "$(dirname -- "$(pwd)")")

	cipher_name=$(echo $cipher_directory_name| cut -d $DIRECTORY_NAME_SEPARATOR -f 1)
	cipher_state_size=$(echo $cipher_directory_name | cut -d $DIRECTORY_NAME_SEPARATOR -f 2)
	cipher_key_size=$(echo $cipher_directory_name | cut -d $DIRECTORY_NAME_SEPARATOR -f 3)
	cipher_iv_size=$(echo $cipher_directory_name | cut -d $DIRECTORY_NAME_SEPARATOR -f 4)
	cipher_implementation_version=$(echo $cipher_directory_name| cut -d $DIRECTORY_NAME_SEPARATOR -f 5)
	cipher_implementation_version=${cipher_implementation_version:1:${#cipher_implementation_version}-1}

	cipher_implementation_info=$(cat $IMPLEMENTATION_INFO_FILE | grep $IMPLEMENTATION_DESCRIPTION$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2)
	cipher_implementation_authors=$(cat $IMPLEMENTATION_INFO_FILE | grep $IMPLEMENTATION_AUTHORS$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2)
	

	if [ $EXAMPLE_CIPHER_NAME == $cipher_name ] ; then
		cd ./../../
		continue
	fi


	echo "Run for cipher '$cipher_name':"
	echo -e "\t STATE_SIZE = $cipher_state_size"
	echo -e "\t KEY_SIZE = $cipher_key_size"
	echo -e "\t IV_SIZE = $cipher_iv_size"
	echo -e "\t IMPLEMENTATION_VERSION = $cipher_implementation_version"
	echo ""


	# Add table row
	case $SCRIPT_FORMAT in
		$SCRIPT_FORMAT_0)
			add_raw_table_row $script_raw_output "$cipher_name" "$cipher_state_size" "$cipher_key_size" "$cipher_iv_size" "$cipher_implementation_version" "$cipher_implementation_info" "$cipher_implementation_authors"
			add_mediawiki_table_row $script_mediawiki_output "$cipher_name" "$cipher_state_size" "$cipher_key_size" "$cipher_iv_size" "$cipher_implementation_version" "$cipher_implementation_info" "$cipher_implementation_authors"
			add_xml_table_row $script_xml_output "$cipher_name" "$cipher_state_size" "$cipher_key_size" "$cipher_iv_size" "$cipher_implementation_version" "$cipher_implementation_info" "$cipher_implementation_authors"
			add_latex_table_row $script_latex_output "$cipher_name" "$cipher_state_size" "$cipher_key_size" "$cipher_iv_size" "$cipher_implementation_version" "$cipher_implementation_info" "$cipher_implementation_authors"
			add_csv_table_row $script_csv_output "$cipher_name" "$cipher_state_size" "$cipher_key_size" "$cipher_iv_size" "$cipher_implementation_version" "$cipher_implementation_info" "$cipher_implementation_authors"
			;;
		$SCRIPT_FORMAT_1)
			add_raw_table_row $script_raw_output "$cipher_name" "$cipher_state_size" "$cipher_key_size" "$cipher_iv_size" "$cipher_implementation_version" "$cipher_implementation_info" "$cipher_implementation_authors"
			;;
		$SCRIPT_FORMAT_2)
			add_mediawiki_table_row $script_mediawiki_output "$cipher_name" "$cipher_state_size" "$cipher_key_size" "$cipher_iv_size" "$cipher_implementation_version" "$cipher_implementation_info" "$cipher_implementation_authors"
			;;
		$SCRIPT_FORMAT_3)
			add_xml_table_row $script_xml_output "$cipher_name" "$cipher_state_size" "$cipher_key_size" "$cipher_iv_size" "$cipher_implementation_version" "$cipher_implementation_info" "$cipher_implementation_authors"
			;;
		$SCRIPT_FORMAT_4)
			add_latex_table_row $script_latex_output "$cipher_name" "$cipher_state_size" "$cipher_key_size" "$cipher_iv_size" "$cipher_implementation_version" "$cipher_implementation_info" "$cipher_implementation_authors"
			;;
		$SCRIPT_FORMAT_5)
			add_csv_table_row $script_csv_output "$cipher_name" "$cipher_state_size" "$cipher_key_size" "$cipher_iv_size" "$cipher_implementation_version" "$cipher_implementation_info" "$cipher_implementation_authors"
			;;
	esac


	cd ./../../
done


# Add table footer
case $SCRIPT_FORMAT in
	$SCRIPT_FORMAT_0)
		add_raw_table_footer $script_raw_output
		add_mediawiki_table_footer $script_mediawiki_output
		add_xml_table_footer $script_xml_output
		add_latex_table_footer $script_latex_output
		add_csv_table_footer $script_csv_output
		;;
	$SCRIPT_FORMAT_1)
		add_raw_table_footer $script_raw_output
		;;
	$SCRIPT_FORMAT_2)
		add_mediawiki_table_footer $script_mediawiki_output
		;;
	$SCRIPT_FORMAT_3)
		add_xml_table_footer $script_xml_output
		;;
	$SCRIPT_FORMAT_4)
		add_latex_table_footer $script_latex_output
		;;
	$SCRIPT_FORMAT_5)
		add_csv_table_footer $script_csv_output
		;;
esac


# Change current working directory
cd $current_directory
echo "End get ciphers info - $(pwd)"
