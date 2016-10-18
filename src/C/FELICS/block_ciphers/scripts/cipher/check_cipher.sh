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
# Call this script to check if the cipher implementation is compliant with the framework
# 	./check_cipher.sh [{-h|--help}] [--version] [{-m|--mode}=[0|1]] [{-s|--scenario}=[0|1|2]] [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-t|--target}=[...]] [{-o|--output}=[...]] [{-co|--compiler_options}='...']
#
#	To call from a cipher build folder use:
#		./../../../../scripts/cipher/check_cipher.sh [options]
#
#	Options:
#		-h, --help
#			Display help information
#		--version
#			Display version information
#		-m, --mode
#			Specifies which output mode to use
#				0 - raw table for given cipher
#				1 - raw data for given cipher
#				Default: 0
#		-s, --scenario
#			Specifies which scenario is used
#				0 - cipher scenario
#				1 - scenario 1
#				2 - scenario 2
#				Default: 0
#		-a, --architecture
#			Specifies which architecture is used
#				PC - binary files are build for PC
#				AVR - binary files are build for AVR device
#				MSP - binary file are build for MSP device
#				ARM - binary files are build for ARM device
#				Default: PC
#		-t, --target
#			Specifies which is the target path. The relative path is computed from the directory where script was called
#				Default: .
#		-o, --output
#			Specifies where to output the results. The relative path is computed from the directory where script was called
#				Default: /dev/tty
#		-co,--compiler_options
#			Specifies the compiler options
#				List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'
#				Default: -O3
#
#	Examples:
#		./../../../../scripts/cipher/check_cipher.sh -m=0
#		./../../../../scripts/cipher/check_cipher.sh --mode=1 --architecture=MSP
#  		./../../../../scripts/cipher/check_cipher.sh -o=results.txt
#		./check_cipher.sh -t=./../../source/ciphers/CipherName_BlockSizeInBits_KeySizeInBits_v01/build
#


# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/../config/config.sh

# Include constants files
source $script_path/../constants/constants.sh
source $script_path/../constants/cipher/check_cipher.sh

# Include help file
source $script_path/../help/cipher/check_cipher.sh

# Include validation functions
source $script_path/../common/validate.sh

# Include version file
source $script_path/../common/version.sh


# Default values
SCRIPT_MODE=$SCRIPT_MODE_0
SCRIPT_SCENARIO=$SCRIPT_SCENARIO_0
SCRIPT_ARCHITECTURE=$SCRIPT_ARCHITECTURE_PC
SCRIPT_TARGET=$DEFAULT_SCRIPT_TARGET
SCRIPT_OUTPUT=$DEFAULT_SCRIPT_OUTPUT
SCRIPT_COMPILER_OPTIONS=$SCRIPT_COMPILER_OPTION_OPTIMIZE_3


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
		-m=*|--mode=*)
			SCRIPT_MODE="${i#*=}"
			shift
			;;
		-s=*|--scenario=*)
			SCRIPT_SCENARIO="${i#*=}"
			shift
			;;
		-a=*|--architecture=*)
			SCRIPT_ARCHITECTURE="${i#*=}"
			shift
			;;
		-t=*|--target=*)
			if [[ "${i#*=}" ]] ; then
				SCRIPT_TARGET="${i#*=}"
			fi
			shift
			;;
		-o=*|--output=*)
			if [[ "${i#*=}" ]] ; then
				SCRIPT_OUTPUT="${i#*=}"
			fi
			shift
			;;
		-co=*|--compiler_options=*)
			SCRIPT_COMPILER_OPTIONS="${i#*=}"
			shift
			;;
		*)
			# Unknown option
			;;
	esac
done


echo "Script settings:"
echo -e "\t SCRIPT_MODE \t\t\t = $SCRIPT_MODE"
echo -e "\t SCRIPT_SCENARIO \t\t = $SCRIPT_SCENARIO"
echo -e "\t SCRIPT_ARCHITECTURE \t\t = $SCRIPT_ARCHITECTURE"
echo -e "\t SCRIPT_TARGET \t\t\t = $SCRIPT_TARGET"
echo -e "\t SCRIPT_OUTPUT \t\t\t = $SCRIPT_OUTPUT"
echo -e "\t SCRIPT_COMPILER_OPTIONS \t = $SCRIPT_COMPILER_OPTIONS"


# Validate inputs
validate_mode $SCRIPT_MODE
validate_scenario $SCRIPT_SCENARIO
validate_architecture $SCRIPT_ARCHITECTURE


# Set the current working directory
current_directory=$(pwd)
echo "Begin check cipher - $current_directory"


# Change relative script output path
if [[ $SCRIPT_OUTPUT != /* ]] ; then
	SCRIPT_OUTPUT=$current_directory/$SCRIPT_OUTPUT
fi


# Change current working directory
cd $SCRIPT_TARGET
echo "Changed working directory: $(pwd)"


# Assume that the cipher is compliant
compliant=$TRUE

# Clean
make -f $CIPHER_MAKEFILE $MAKE_CLEAN_TARGET &> $MAKE_FILE_LOG
if [ $SUCCESS_EXIT_CODE -ne $? ]; then
	compliant=$FALSE
	if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
		echo "Error! For error details please read the log file: '$(pwd)/$MAKE_FILE_LOG'"
	fi
fi

# Build
make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE SCENARIO=$SCRIPT_SCENARIO COMPILER_OPTIONS="$SCRIPT_COMPILER_OPTIONS" &>> $MAKE_FILE_LOG
if [ $SUCCESS_EXIT_CODE -ne $? ]; then
	compliant=$FALSE
	if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
		echo "Error! For error details please read the log file: '$(pwd)/$MAKE_FILE_LOG'"
	fi
fi


if [ $TRUE == $compliant ] && [ $SCRIPT_SCENARIO_0 == $SCRIPT_SCENARIO ] ; then
	# Clean
	make -f $CIPHER_MAKEFILE $MAKE_CLEAN_TARGET &>> $MAKE_FILE_LOG
	if [ $SUCCESS_EXIT_CODE -ne $? ]; then
		compliant=$FALSE
		if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
			echo "Error! For error details please read the log file: '$(pwd)/$MAKE_FILE_LOG'"
		fi
	fi

	# Build
	make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE SCENARIO=$SCRIPT_SCENARIO COMPILER_OPTIONS="$SCRIPT_COMPILER_OPTIONS" DEBUG=7 &>> $MAKE_FILE_LOG
	if [ $SUCCESS_EXIT_CODE -ne $? ]; then
		compliant=$FALSE
		if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
			echo "Error! For error details please read the log file: '$(pwd)/$MAKE_FILE_LOG'"
		fi
	fi

	case $SCRIPT_ARCHITECTURE in
		$SCRIPT_ARCHITECTURE_PC)
			# Run
			if [ -f $CIPHER_ELF_FILE ] ; then
				./$CIPHER_ELF_FILE > $RESULT_FILE
				if [ $SUCCESS_EXIT_CODE -ne $? ]; then
					compliant=$FALSE
					if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
						echo "Error! Run the executable to see the error: '$(pwd)/$CIPHER_ELF_FILE'"
					fi	
				fi
			else
				compliant=$FALSE
			fi
			;;

		$SCRIPT_ARCHITECTURE_AVR)
			# Run
			if [ -f $CIPHER_ELF_FILE ] ; then
				$SIMAVR_SIMULATOR -m atmega128 $CIPHER_ELF_FILE &> $RESULT_FILE
				if [ $SUCCESS_EXIT_CODE -ne $? ]; then
					compliant=$FALSE
					if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
						echo "Error! Run the executable to see the error: '$(pwd)/$CIPHER_ELF_FILE'"
					fi	
				fi
			else
				compliant=$FALSE
			fi
			;;

		$SCRIPT_ARCHITECTURE_MSP)
			# Run
			if [ -f $CIPHER_ELF_FILE ] ; then
				$MSPDEBUG_SIMULATOR -n sim < $MSPDEBUG_CHECK_CIPHER_COMMANDS_FILE &> $RESULT_FILE
				if [ $SUCCESS_EXIT_CODE -ne $? ]; then
					compliant=$FALSE
					if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
						echo "Error! Run the executable to see the error: '$(pwd)/$CIPHER_ELF_FILE'"
					fi	
				fi
			else
				compliant=$FALSE
			fi
			;;

		$SCRIPT_ARCHITECTURE_ARM)
			if [ -f $CIPHER_ELF_FILE ] ; then
				# Upload the program to the board
				make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE upload-cipher &>> $MAKE_FILE_LOG

				# Run the program stored in the flash memory of the board
				$ARM_SERIAL_TERMINAL > $RESULT_FILE
			else
				compliant=$FALSE
			fi
			;;
	esac

	# Check run result
	if [ -f $RESULT_FILE ] ; then
		correct_count=$(grep -c "$CORRECT" $RESULT_FILE)
		wrong_count=$(grep -c "$WRONG" $RESULT_FILE)

		if [ $EXPECTED_CORRECT_COUNT -ne $correct_count ] || [ $EXPECTED_WRONG_COUNT -ne $wrong_count ] ; then
			compliant=$FALSE
			if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
				echo "Error! Test vectors do not check!"
				echo "correct = $correct_count, wrong = $wrong_count"
			fi
		else
			if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
				rm -f $MAKE_FILE_LOG
				rm -f $RESULT_FILE
			fi
		fi
	else
		compliant=$FALSE
	fi
fi


if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
	if [ $FALSE -eq $compliant ] ; then
		echo "$(tput setaf 1)NOT OK!$(tput sgr 0)"
	else
		echo "$(tput setaf 2)OK!$(tput sgr 0)"
	fi
else
	echo -n $compliant > $SCRIPT_OUTPUT
fi


# Change current working directory
cd $current_directory
if [ $SCRIPT_MODE_0 -ne $SCRIPT_MODE ] ; then
	echo ""
fi
echo "End check cipher - $(pwd)"
