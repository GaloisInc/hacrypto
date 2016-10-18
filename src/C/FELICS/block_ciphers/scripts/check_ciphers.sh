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
# Call this script to check if the ciphers implementations are compliant with the framework
# 	./check_ciphers.sh [{-h|--help}] [--version] [{-v|--verbosity}=[0|1|2]] [{-a|--architectures}=['PC AVR MSP ARM']] [{-s|--scenarios}=['0 1 2']] [{-c|--ciphers}=['Cipher1 Cipher2 ...']] [{-co|--compiler_options}='...']
#
#	Options:
#		-h, --help
#			Display help information
#		--version
#			Display version information
#		-v, --verbosity
#			Specifies the verbosity level to use
#				0 - display only not compliant ciphers
#				1 - display all ciphers
#				2 - display all ciphers with details
#				Default: 0
#		-a, --architectures
#			Specifies for which archiectures to check the ciphers for compliance
#				List of values: 'PC AVR MSP ARM'
#				Default: all architectures
#		-s, --scenarios
#			Specifies for which scenarios to check the ciphers for compliance
#				List of values: '0 1 2'
#				Default: all scenarios
#		-c, --ciphers
#			Specifies which ciphers to be checked for compliance
#				List of values: 'CipherName_BlockSizeInBits_KeySizeInBits_v01 ...'
#				Default: all ciphers
#		-co,--compiler_options
#			Specifies the compiler options
#				List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'
#				Default: all compiler options
#
#	Examples:
#		./check_ciphers.sh -f=0
#		./check_ciphers.sh --verbosity=1
#		./check_ciphers.sh -a='PC AVR' --scenarios="1 2"
#


# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/config/config.sh

# Include constants files
source $script_path/constants/constants.sh
source $script_path/constants/check_ciphers.sh

# Include help file
source $script_path/help/check_ciphers.sh

# Include validation functions
source $script_path/common/validate.sh

# Include version file
source $script_path/common/version.sh


# Default values
SCRIPT_VERBOSITY=$SCRIPT_VERBOSITY_0


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
		-v=*|--verbosity=*)
			SCRIPT_VERBOSITY="${i#*=}"
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
echo -e "\t SCRIPT_VERBOSITY \t\t = $SCRIPT_VERBOSITY"


# Validate inputs
validate_verbosity $SCRIPT_VERBOSITY


# Change current directory to script source path directory
if [ '.' != $script_path ] ; then
	cd $script_path
fi


# Set the current working directory
current_directory=$(pwd)
echo "Begin check ciphers - $current_directory"


# Change current working directory
cd $current_directory/$CIPHERS_PATH
echo "Changed working directory: $(pwd)"
echo ""


# Get the number of directories
directories_number=$(find . -maxdepth 1 -type d | wc -l)

if [ $directories_number -eq 0 ] ; then
	echo "There is no directory here: '$(pwd)'!"
	echo "Exit!"
	exit
fi

# Get the files matching the pattern
ciphers_directories=$(ls -d *)


# If user architectures are not set, use all architectures
if [ -n "$SCRIPT_USER_ARCHITECTURES" ]; then
	architectures=$SCRIPT_USER_ARCHITECTURES
else
	architectures=(${SCRIPT_ARCHITECTURES[@]})
fi

# If user scenarios are not set, use all scenarios
if [ -n "$SCRIPT_USER_SCENARIOS" ]; then
	scenarios=$SCRIPT_USER_SCENARIOS
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


compliant_test_cases=0
checked_test_cases=0

compliant_cipher_implementation_architecture_scenarios=0
checked_cipher_implementation_architecture_scenarios=0

for directory in ${directories[@]}
do
	cd $directory/build


	# Get the cipher name, block size, key size and implementation version from directory name
	cipher_name=$(echo $directory| cut -d $DIRECTORY_NAME_SEPARATOR -f 1)
	cipher_block_size=$(echo $directory | cut -d $DIRECTORY_NAME_SEPARATOR -f 2)
	cipher_key_size=$(echo $directory | cut -d $DIRECTORY_NAME_SEPARATOR -f 3)
	cipher_implementation_version=$(echo $directory| cut -d $DIRECTORY_NAME_SEPARATOR -f 4)
		

	if [ $SCRIPT_VERBOSITY_2 -eq $SCRIPT_VERBOSITY ] ; then
		echo ""
		echo "Run for cipher '$cipher_name':"
		echo -e "\t BLOCK_SIZE = $cipher_block_size"
		echo -e "\t KEY_SIZE = $cipher_key_size"
		echo -e "\t IMPLEMENTATION_VERSION = $cipher_implementation_version"
		echo ""
	fi


	# Assume that the cipher is compliant
	compliant=$TRUE


	if [ $TRUE -eq $compliant ] ; then
		for architecture in ${architectures[@]}
		do
			if [ $SCRIPT_VERBOSITY_2 -eq $SCRIPT_VERBOSITY ] ; then
				echo -e "\t ---> Architecture: $architecture"
			fi

			for scenario in ${scenarios[@]}
			do
				if [ $SCRIPT_VERBOSITY_2 -eq $SCRIPT_VERBOSITY ] ; then
					echo -e "\t\t ---> Scenario: $scenario"
				fi

				# Assume that the cipher implementation is not compliant with the architecture and scenario
				compliant_cipher_implementation_architecture_scenario=$FALSE

				for compiler_option in "${compiler_options[@]}"
				do
					if [ $SCRIPT_VERBOSITY_2 -eq $SCRIPT_VERBOSITY ] ; then
						echo -e "\t\t\t ---> Compiler options: $compiler_option"
					fi


					check_cipher_output_file=$architecture$SCENARIO_NAME_PART$scenario$FILE_NAME_SEPARATOR$CHECK_CIPHER_OUTPUT_FILE
					check_cipher_details_output_file=$architecture$SCENARIO_NAME_PART$scenario$FILE_NAME_SEPARATOR$CHECK_CIPHER_DETAILS_OUTPUT_FILE
					check_cipher_error_file=$architecture$SCENARIO_NAME_PART$scenario$FILE_NAME_SEPARATOR$CHECK_CIPHER_ERROR_FILE

					# Remove log files
					rm -f $check_cipher_output_file
					rm -f rm -f $check_cipher_details_output_file

					# Clear error file
					echo "" > $check_cipher_error_file

					# Check cipher
					timeout $CHECK_CIPHER_TIMEOUT ./../../../../scripts/cipher/check_cipher.sh -m=$CIPHER_SCRIPT_MODE -s=$scenario -a=$architecture -c=$directory -co="$compiler_option" -o=$check_cipher_output_file > $check_cipher_details_output_file 2> $check_cipher_error_file

					if [ ! -f $check_cipher_output_file ] ; then
						compliant=$FALSE
					else
						if [ -f $check_cipher_error_file ] ; then
							check_cipher_errors=$(cat $check_cipher_error_file)
						fi

						if [ "" != "$check_cipher_errors" ] ; then
							comliant=$FALSE
						fi

						compliant=$(cat $check_cipher_output_file)
					fi

					#if [ $SCRIPT_VERBOSITY_2 -eq $SCRIPT_VERBOSITY ] ; then
					#	echo "$(cat $check_cipher_details_output_file)"
					#fi
					

					if [ $FALSE -eq $compliant ] ; then
							echo "$(tput setab 1)$directory$(tput sgr 0) $(tput setaf 1)NOT OK!$(tput sgr 0)"
					else
						if [ $SCRIPT_VERBOSITY_0 -ne $SCRIPT_VERBOSITY ] ; then
							echo "$(tput setab 2)$directory$(tput sgr 0) $(tput setaf 2)OK!$(tput sgr 0)"
						fi
					fi


					if [ $TRUE -eq $compliant ] ; then
						compliant_cipher_implementation_architecture_scenario=$TRUE
					fi

					
					checked_test_cases=$(($checked_test_cases + 1))
					if [ $TRUE -eq $compliant ] ; then
						compliant_test_cases=$(($compliant_test_cases + 1))
					fi

					if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
						# Remove generated files
						rm -f check_cipher_output_file
						rm -f check_cipher_details_output_file
						rm -f check_cipher_error_file
					fi
				done

				checked_cipher_implementation_architecture_scenarios=$(($checked_cipher_implementation_architecture_scenarios + 1))
				if [ $TRUE -eq $compliant_cipher_implementation_architecture_scenario ] ; then
					compliant_cipher_implementation_architecture_scenarios=$(($compliant_cipher_implementation_architecture_scenarios + 1))
				fi

				if [ $FALSE -eq $compliant_cipher_implementation_architecture_scenario ] ; then
					echo "$(tput setab 1)$directory - architecture: $architecture; scenario: $scenario - $(tput sgr 0) $(tput setaf 1)NOT OK!$(tput sgr 0)"
				else
					if [ $SCRIPT_VERBOSITY_0 -ne $SCRIPT_VERBOSITY ] ; then
						echo "$(tput setab 2)$directory - architecture $architecture; scenario: $scenario - $(tput sgr 0) $(tput setaf 2)OK!$(tput sgr 0)"
					fi
				fi
			done
		done
	fi

	
	cd ./../../
done


echo ""
echo "Result"
echo -e "\t Checked test cases: $checked_test_cases"
echo -e "\t Compliant test cases: $compliant_test_cases"
echo -e "\t Not compliant test cases: $(($checked_test_cases - $compliant_test_cases))"
echo ""
echo -e "\t Checked (cipher, architecture, scenario) pairs: $checked_cipher_implementation_architecture_scenarios"
echo -e "\t Compliant (cipher, architecture, scenario) pairs: $compliant_cipher_implementation_architecture_scenarios"
echo -e "\t Not compliant (cipher, architecture, scenario) pairs: $(($checked_cipher_implementation_architecture_scenarios - $compliant_cipher_implementation_architecture_scenarios))"


# Change current working directory
cd $current_directory
echo "End check ciphers - $(pwd)"
