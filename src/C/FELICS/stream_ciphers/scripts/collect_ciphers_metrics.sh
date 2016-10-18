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
# Call this script to collect the ciphers metrics
# 	./collect_ciphers_metrics.sh [{-h|--help}] [{-h|--help}] [{-f|--format}=[0|1|2|3|4|5]] [{-a|--architectures}=['PC AVR MSP ARM']] [{-s|--scenarios}=['0 1']] [{-c|--ciphers}=['Cipher1 Cipher2 ...']] [{-co|--compiler_options}='...']
#
#	Options:
#		-h, --help
#			Display help information
#		--version
#			Display version information
#		-f, --format
#			Specifies which output format to use
#				0 - use all output formats below
#				1 - raw table
#				2 - MediaWiki table
#				3 - XML table
#				4 - LaTeX table
#				5 - CSV table
#				Default: 0
#		-a, --architectures
#			Specifies for which archiectures to collect ciphers metrics
#				List of values: 'PC AVR MSP ARM'
#				Default: all architectures
#		-s, --scenarios
#			Specifies for which scenarios to collect ciphers metrics
#				List of values: '0 1'
#				Default: all scenarios
#		-c, --ciphers
#			Specifies for which ciphers to collect the metrics
#				List of values: 'CipherName_StateSizeInBits_KeySizeInBits_IVSizeInBits_v01 ...'
#				Default: all ciphers
#		-co,--compiler_options
#			Specifies the compiler options
#				List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'
#				Default: all compiler options
#
#	Examples:
#		./collect_ciphers_metrics.sh -f=0
#		./collect_ciphers_metrics.sh --format=1
#		./collect_ciphers_metrics.sh -a='PC AVR' --scenarios="0 1"
#


# Get current script path
script_path=$(dirname $0)

# Include constants files
source $script_path/constants/constants.sh
source $script_path/constants/collect_ciphers_metrics.sh

# Include help file
source $script_path/help/collect_ciphers_metrics.sh

# Include validation functions
source $script_path/common/validate.sh

# Include check status function
source $script_path/common/check_status.sh

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
		-a=*|--architectures=*)
			SCRIPT_USER_ARCHITECTURES="${i#*=}"
			shift
			;;
		-s=*|--scenarios=*)
			SCRIPT_USER_SCENARIOS="${i#*=}"
			shift
			;;
		-c=*|--ciphers=*)
			SCRIPT_USER_CIPHERS="${i#*=}"
			shift
			;;
		-co=*|--compiler_options=*)
			SCRIPT_USER_COMPILER_OPTIONS="${i#*=}"
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
		source $script_path/formats/results/raw.sh
		source $script_path/formats/results/mediawiki.sh
		source $script_path/formats/results/xml.sh
		source $script_path/formats/results/latex.sh
		source $script_path/formats/results/csv.sh
		;;
	$SCRIPT_FORMAT_1)
		source $script_path/formats/results/raw.sh
		;;
	$SCRIPT_FORMAT_2)
		source $script_path/formats/results/mediawiki.sh
		;;
	$SCRIPT_FORMAT_3)
		source $script_path/formats/results/xml.sh
		;;
	$SCRIPT_FORMAT_4)
		source $script_path/formats/results/latex.sh
		;;
	$SCRIPT_FORMAT_5)
		source $script_path/formats/results/csv.sh
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
echo "Begin collect ciphers metrics - $current_directory"


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


# Build all ciphers once
build=$SCRIPT_BUILD_DISABLED

# If user architectures are not set, use all architectures
if [ -n "$SCRIPT_USER_ARCHITECTURES" ]; then
	architectures=$SCRIPT_USER_ARCHITECTURES
	build=$SCRIPT_BUILD_ENABLED
else
	architectures=(${SCRIPT_ARCHITECTURES[@]}) 
fi

# If user scenarios are not set, use all scenarios
if [ -n "$SCRIPT_USER_SCENARIOS" ]; then
	scenarios=$SCRIPT_USER_SCENARIOS
	build=$SCRIPT_BUILD_ENABLED
else
	scenarios=(${SCRIPT_SCENARIOS[@]}) 
fi

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

# If user compiler options are not set, use all compiler options
if [ -n "$SCRIPT_USER_COMPILER_OPTIONS" ]; then
	user_compiler_options="${SCRIPT_USER_COMPILER_OPTIONS[@]}"
	compiler_options=()

	OLD_IFS=$IFS
	IFS=";"
	for user_compiler_option in ${user_compiler_options[@]}
	do
		compiler_option=$(echo -e "${user_compiler_option}" | sed -e 's/^[[:space:]]*//')
		compiler_options+=("$compiler_option")
	done
	IFS=$OLD_IFS
else
	compiler_options=("${SCRIPT_COMPILER_OPTIONS[@]}")
fi


# Validate architectures
for architecture in $architectures
do
	validate_architecture $architecture
done

# Validate scenarios
for scenario in $scenarios
do
	validate_scenario $scenario
done


for architecture in ${architectures[@]}
do
	echo -e "\t\t\t ---> Architecture: $architecture"
	
	for scenario in ${scenarios[@]}
	do
		echo -e "\t\t\t\t ---> Scenario: $scenario"

		script_raw_output=$current_directory/$SCRIPT_OUTPUT_PATH$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_RAW_OUTPUT_EXTENSION
		script_mediawiki_output=$current_directory/$SCRIPT_OUTPUT_PATH$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
		script_xml_output=$current_directory/$SCRIPT_OUTPUT_PATH$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_XML_OUTPUT_EXTENSION
		script_latex_output=$current_directory/$SCRIPT_OUTPUT_PATH$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_LATEX_OUTPUT_EXTENSION
		script_csv_output=$current_directory/$SCRIPT_OUTPUT_PATH$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_CSV_OUTPUT_EXTENSION

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

			cipher_name=$(echo $cipher_directory_name | cut -d $DIRECTORY_NAME_SEPARATOR -f 1)
			cipher_state_size=$(echo $cipher_directory_name | cut -d $DIRECTORY_NAME_SEPARATOR -f 2)
			cipher_key_size=$(echo $cipher_directory_name | cut -d $DIRECTORY_NAME_SEPARATOR -f 3)
			cipher_iv_size=$(echo $cipher_directory_name | cut -d $DIRECTORY_NAME_SEPARATOR -f 4)
			cipher_implementation_version=$(echo $cipher_directory_name | cut -d $DIRECTORY_NAME_SEPARATOR -f 5)
			cipher_implementation_version=${cipher_implementation_version:1:${#cipher_implementation_version}-1}

			if [ $EXAMPLE_CIPHER_NAME == $cipher_name ] ; then
				cd ./../../
				continue
			fi


			cipher_implementation_language=$(cat $IMPLEMENTATION_INFO_FILE | grep $IMPLEMENTATION_TYPE$architecture$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')

			# Convert to uppercase
			cipher_implementation_language=${cipher_implementation_language^^}

			if [ $IMPLEMENTATION_ASM != "$cipher_implementation_language" ] && [ $IMPLEMENTATION_C_ASM != "$cipher_implementation_language" ] ; then
				cipher_implementation_language=$IMPLEMENTATION_C
			fi


			for compiler_option in "${compiler_options[@]}"		
			do
				echo -e "\t\t\t\t\t ---> Cipher: $directory"

				echo "Run for cipher '$cipher_name':"
				echo -e "\t STATE_SIZE = $cipher_state_size"
				echo -e "\t KEY_SIZE = $cipher_key_size"
				echo -e "\t IV_SIZE = $cipher_iv_size"
				echo -e "\t IMPLEMENTATION_VERSION = $cipher_implementation_version"
				echo -e "\t ARCHITECTURE = $architecture"			
				echo -e "\t SCENARIO = $scenario"
				echo -e "\t COMPILER_OPTIONS = $compiler_option"
				echo ""


				compiler_option_name=${compiler_option// /_}

				check_cipher_output_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CHECK_CIPHER_OUTPUT_FILE
				check_cipher_error_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CHECK_CIPHER_ERROR_FILE

				# Remove log file
				rm -f $check_cipher_output_file

				# Clear error file
				echo "" > $check_cipher_error_file

				# Check cipher
				timeout $CHECK_CIPHER_TIMEOUT ./../../../../scripts/cipher/check_cipher.sh -s=$scenario -a=$architecture -c=$cipher_directory_name "-co=$compiler_option" -m=$CIPHER_SCRIPT_MODE -o=$check_cipher_output_file 2> $check_cipher_error_file
				if [ ! -f $check_cipher_output_file ] ; then
					continue
				fi
				if [ -f $check_cipher_error_file ] ; then
					check_cipher_errors=$(cat $check_cipher_error_file)
				fi
				if [ "" != "$check_cipher_errors" ] ; then
					continue
				fi

				check_cipher_result=$(cat $check_cipher_output_file)
				if [ $FALSE -eq $check_cipher_result ] ; then
					continue
				fi

				cipher_code_size_output_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_CODE_SIZE_OUTPUT_FILE
				cipher_ram_output_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_RAM_OUTPUT_FILE
				cipher_execution_time_output_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_EXECUTION_TIME_OUTPUT_FILE

				cipher_code_size_error_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_CODE_SIZE_ERROR_FILE
				cipher_ram_error_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_RAM_ERROR_FILE
				cipher_execution_time_error_file=$architecture$SCENARIO_NAME_PART$scenario$COMPILER_OPTIONS_NAME_PART$compiler_option_name$FILE_NAME_SEPARATOR$CIPHER_EXECUTION_TIME_ERROR_FILE

				# Remove log files
				rm -f $cipher_code_size_output_file
				rm -f $cipher_ram_output_file
				rm -f $cipher_execution_time_output_file

				# Clear error files
				echo "" > $cipher_code_size_error_file
				echo "" > $cipher_ram_error_file
				echo "" > $cipher_execution_time_error_file

				# Code size
				timeout $CIPHER_CODE_SIZE_TIMEOUT ./../../../../scripts/cipher/cipher_code_size.sh "-s=$scenario" "-a=$architecture" "-m=$CIPHER_SCRIPT_MODE" "-co=$compiler_option" -o=$cipher_code_size_output_file 2> $cipher_code_size_error_file
				if [ ! -f $cipher_code_size_output_file ] ; then
					continue
				fi
				if [ -f $cipher_code_size_error_file ] ; then
					cipher_code_size_errors=$(cat $cipher_code_size_error_file)
				fi
				if [ "" != "$cipher_code_size_errors" ] ; then
					continue
				fi


				# RAM
				timeout $CIPHER_RAM_TIMEOUT ./../../../../scripts/cipher/cipher_ram.sh "-s=$scenario" "-a=$architecture" "-m=$CIPHER_SCRIPT_MODE" "-co=$compiler_option" -o=$cipher_ram_output_file 2> $cipher_ram_error_file
				if [ ! -f $cipher_ram_output_file ] ; then
					continue
				fi
				if [ -f $cipher_ram_error_file ] ; then
					cipher_ram_errors=$(cat $cipher_ram_error_file)
				fi
				if [ "" != "$cipher_ram_errors" ] ; then
					continue
				fi


				# Execution time
				timeout $CIPHER_EXECUTION_TIME_TIMEOUT ./../../../../scripts/cipher/cipher_execution_time.sh "-s=$scenario" "-a=$architecture" "-m=$CIPHER_SCRIPT_MODE" "-co=$compiler_option" -o=$cipher_execution_time_output_file 2> $cipher_execution_time_error_file
				if [ ! -f $cipher_execution_time_output_file ] ; then
					continue
				fi
				if [ -f $cipher_execution_time_error_file ] ; then
					cipher_execution_time_errors=$(cat $cipher_execution_time_error_file)
				fi
				if [ "" != "$cipher_execution_time_errors" ] ; then
					continue
				fi


				values=( $(cat $cipher_code_size_output_file) $(cat $cipher_ram_output_file)  $(cat $cipher_execution_time_output_file) )

				# Add table row
				case $SCRIPT_FORMAT in
					$SCRIPT_FORMAT_0)
						add_raw_table_row $script_raw_output $scenario $cipher_name $cipher_state_size $cipher_key_size $cipher_iv_size $cipher_implementation_version $cipher_implementation_language "$compiler_option" ${values[@]}
						add_mediawiki_table_row $script_mediawiki_output $scenario $cipher_name $cipher_state_size $cipher_key_size $cipher_iv_size $cipher_implementation_version $cipher_implementation_language "$compiler_option" ${values[@]}
						add_xml_table_row $script_xml_output $scenario $cipher_name $cipher_state_size $cipher_key_size $cipher_iv_size $cipher_implementation_version $cipher_implementation_language "$compiler_option" ${values[@]}
						add_latex_table_row $script_latex_output $scenario $cipher_name $cipher_state_size $cipher_key_size $cipher_iv_size $cipher_implementation_version $cipher_implementation_language "$compiler_option" ${values[@]}
						add_csv_table_row $script_csv_output $scenario $cipher_name $cipher_state_size $cipher_key_size $cipher_iv_size $cipher_implementation_version $cipher_implementation_language "$compiler_option" ${values[@]}
						;;
					$SCRIPT_FORMAT_1)
						add_raw_table_row $script_raw_output $scenario $cipher_name $cipher_state_size $cipher_key_size $cipher_iv_size $cipher_implementation_version $cipher_implementation_language "$compiler_option" ${values[@]}
						;;
					$SCRIPT_FORMAT_2)
						add_mediawiki_table_row $script_mediawiki_output $scenario $cipher_name $cipher_state_size $cipher_key_size $cipher_iv_size $cipher_implementation_version $cipher_implementation_language "$compiler_option" ${values[@]}
						;;
					$SCRIPT_FORMAT_3)
						add_xml_table_row $script_xml_output $scenario $cipher_name $cipher_state_size $cipher_key_size $cipher_iv_size $cipher_implementation_version $cipher_implementation_language "$compiler_option" ${values[@]}
						;;
					$SCRIPT_FORMAT_4)
						add_latex_table_row $script_latex_output $scenario $cipher_name $cipher_state_size $cipher_key_size $cipher_iv_size $cipher_implementation_version $cipher_implementation_language "$compiler_option" ${values[@]}
						;;
					$SCRIPT_FORMAT_5)
						add_csv_table_row $script_csv_output $scenario $cipher_name $cipher_state_size $cipher_key_size $cipher_iv_size $cipher_implementation_version $cipher_implementation_language "$compiler_option" ${values[@]}
						;;
				esac


				if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
					# Remove generated files
					rm -f $check_cipher_output_file
					rm -f $cipher_code_size_output_file
					rm -f $cipher_ram_output_file
					rm -f $cipher_execution_time_output_file

					rm -f $check_cipher_error_file
					rm -f $cipher_code_size_error_file
					rm -f $cipher_ram_error_file
					rm -f $cipher_execution_time_error_file
				fi
			done


			cd ./../../
		done

		# Add table footer
		case $SCRIPT_FORMAT in
			$SCRIPT_FORMAT_0)
				add_raw_table_footer $script_raw_output $scenario
				add_mediawiki_table_footer $script_mediawiki_output $scenario
				add_xml_table_footer $script_xml_output $scenario
				add_latex_table_footer $script_latex_output $scenario
				add_csv_table_footer $script_csv_output $scenario
				;;
			$SCRIPT_FORMAT_1)
				add_raw_table_footer $script_raw_output $scenario
				;;
			$SCRIPT_FORMAT_2)
				add_mediawiki_table_footer $script_mediawiki_output $scenario
				;;
			$SCRIPT_FORMAT_3)
				add_xml_table_footer $script_xml_output $scenario
				;;
			$SCRIPT_FORMAT_4)
				add_latex_table_footer $script_latex_output $scenario
				;;
			$SCRIPT_FORMAT_5)
				add_csv_table_footer $script_csv_output $scenario
				;;
		esac

	done
done


# Change current working directory
cd $current_directory
echo "End collect ciphers metrics - $(pwd)"
