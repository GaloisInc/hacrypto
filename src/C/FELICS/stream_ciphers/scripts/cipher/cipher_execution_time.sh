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
# Call this script to extract the cipher execution time
# 	./cipher_execution_time.sh [{-h|--help}] [--version] [{-m|--mode}=[0|1]] [{-s|--scenario}=[0|1]] [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-t|--target}=[...]] [{-o|--output}=[...]] [{-b|build}=[0|1]] [{-co|--compiler_options}='...']
#
#	To call from a cipher build folder use:
#		./../../../../scripts/cipher/cipher_execution_time.sh [options]
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
#		-b, --build
#			Specifies if script should build the source files
#				0 - do not build source files
#				1 - build source files
#				Default: 1
#		-co,--compiler_options
#			Specifies the compiler options
#				List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'
#				Default: -O3
#
#	Examples:
#		./../../../../scripts/cipher_execution_time.sh -m=0
#		./../../../../scripts/cipher_execution_time.sh --mode=1 --architecture=MSP
#  		./../../../../scripts/cipher_execution_time.sh -o=results.txt
#		./cipher_execution_time.sh -t=./../../source/ciphers/CipherName_StateSizeInBits_KeySizeInBits_IVSizeInBits_v01/build
#


# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/../config/config.sh

# Include constants files
source $script_path/../constants/constants.sh
source $script_path/../constants/cipher/cipher_execution_time.sh

# Include help file
source $script_path/../help/cipher/cipher_execution_time.sh

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
SCRIPT_BUILD=$SCRIPT_BUILD_ENABLED
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
		-b=*|--build=*)
			SCRIPT_BUILD="${i#*=}"
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
echo -e "\t SCRIPT_BUILD \t\t\t = $SCRIPT_BUILD"
echo -e "\t SCRIPT_COMPILER_OPTIONS \t = $SCRIPT_COMPILER_OPTIONS"


# Validate inputs
validate_mode $SCRIPT_MODE
validate_scenario $SCRIPT_SCENARIO
validate_architecture $SCRIPT_ARCHITECTURE


if [ $SCRIPT_BUILD_ENABLED -eq $SCRIPT_BUILD ] ; then
	$script_path/../common/build.sh -a=$SCRIPT_ARCHITECTURE -s=$SCRIPT_SCENARIO -co="$SCRIPT_COMPILER_OPTIONS" -v=$SCRIPT_VERBOSE_DISABLED
fi


# Simulate the given binary file execution
# Parameters:
# 	$1 - the target binary file or the commands file
#	$2 - the simulator output file
#	$3 - the make log file
#	$4 - the make target
function simulate()
{
	local target_file=$1
	local output_file=$2
	local make_log_file=$3
	local make_target=$4


	case $SCRIPT_ARCHITECTURE in
		$SCRIPT_ARCHITECTURE_PC)
			# Make the program with cycle count functionality activated
			make -f $CIPHER_MAKEFILE $MAKE_CLEAN_TARGET &> $make_log_file
			make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE SCENARIO=$SCRIPT_SCENARIO  MEASURE_CYCLE_COUNT=1 COMPILER_OPTIONS="$SCRIPT_COMPILER_OPTIONS" &> $make_log_file
			
			# Run the program
			$target_file > $output_file
			;;
		$SCRIPT_ARCHITECTURE_AVR)
			$AVRORA_SIMULATOR -arch=avr -mcmu=atmega128 -input=elf -monitors=calls -seconds=5 -colors=false $target_file > $output_file
			;;
		$SCRIPT_ARCHITECTURE_MSP)
			$MSPDEBUG_SIMULATOR -n sim < $target_file &> $output_file
			;;
		$SCRIPT_ARCHITECTURE_ARM)
			# Make the program with cycle count functionality activated & upload it to the board
			make -f $CIPHER_MAKEFILE $MAKE_CLEAN_TARGET &> $make_log_file
			make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE SCENARIO=$SCRIPT_SCENARIO MEASURE_CYCLE_COUNT=1 COMPILER_OPTIONS="$SCRIPT_COMPILER_OPTIONS" &> $make_log_file
			make -f $CIPHER_MAKEFILE ARCHITECTURE=$SCRIPT_ARCHITECTURE $make_target &> $make_log_file

			# Run the program stored in the flash memory of the board
			$ARM_SERIAL_TERMINAL > $output_file
			;;
	esac
}


# Compute the execution time
# Parameters:
# 	$1 - the simulator output file
# 	$2 - the execution time (cycle count) first row identifier
# 	$3 - the execution time (cycle count) second row identifier
function compute_execution_time()
{
	local output_file=$1
	local first_row_identifier=$2
	local second_row_identifier=$3


	case $SCRIPT_ARCHITECTURE in
		$SCRIPT_ARCHITECTURE_PC)
			local cycle_count=$(cat $output_file | grep $first_row_identifier | tr -d '\r' | cut -d ':' -f 2)
			echo $cycle_count
			;;
		$SCRIPT_ARCHITECTURE_AVR)
			local initial_value=$(cat $output_file | grep -e "--(CALL)-> $first_row_identifier" | grep "$first_row_identifier$" | tr -d '\r' | tr -s ' ' | cut -d ' ' -f 3)
			
			local final_value
			if [ -z $second_row_identifier ] ; then
				final_value=$(cat $output_file | grep -e "<-(RET )-- $first_row_identifier" | grep "$first_row_identifier$" | tr -d '\r' | tr -s ' ' | cut -d ' ' -f 3)
			else
				final_value=$(cat $output_file | grep -e "--(CALL)-> $second_row_identifier" | grep "$second_row_identifier$" | tr -d '\r' | tr -s ' ' | cut -d ' ' -f 3)
			fi

			if [ -z $final_value ] ; then
				final_value=$(cat $output_file | grep -e "<-(RET )--" | tail -1 | tr -d '\r' | tr -s ' ' | cut -d ' ' -f 3)
			fi

			local cycle_count=$(($final_value - $initial_value))
			echo $cycle_count
			;;
		$SCRIPT_ARCHITECTURE_MSP)
			local mclk_initial_value=$(cat $output_file | grep "MCLK:" | head -n $first_row_identifier | tail -n 1 | tr -d '\r' | cut -d ':' -f 2)
			local mclk_final_value=$(cat $output_file | grep "MCLK:" | head -n $(($first_row_identifier + 1)) | tail -n 1 | tr -d '\r' | cut -d ':' -f 2)

			local cycle_count=$(($mclk_final_value - $mclk_initial_value))
			echo $cycle_count
			;;
		$SCRIPT_ARCHITECTURE_ARM)
			local cycle_count=$(cat $output_file | grep $first_row_identifier | tr -d '\r' | cut -d ':' -f 2)
			echo $cycle_count
			;;
	esac
}


# Set the current working directory
current_directory=$(pwd)
echo "Begin cipher execution time - $current_directory"


# Change relative script output path
if [[ $SCRIPT_OUTPUT != /* ]] ; then
	SCRIPT_OUTPUT=$current_directory/$SCRIPT_OUTPUT
fi


# Change current working directory
cd $SCRIPT_TARGET
echo "Changed working directory: $(pwd)"


# Get the cipher name
cipher_name=$(basename -- "$(dirname -- "$(pwd)")")


# Set the searched file pattern
case $SCRIPT_SCENARIO in
	$SCRIPT_SCENARIO_0)
		file=$CIPHER_FILE$ELF_FILE_EXTENSION
		;;

	$SCRIPT_SCENARIO_1)
		file=$SCENARIO1_FILE$ELF_FILE_EXTENSION
		;;
esac


# Get the number of files matching the pattern
files_number=$(find . -maxdepth 1 -type f -name "$file" | wc -l)

if [ $files_number -eq 0 ] ; then
	echo "There is no file matching the pattern: '$file' for cipher '$cipher_name'!"
	echo "Exit!"
	exit
fi


s_execution_time=0
e_execution_time=0
total_execution_time=0

# Debug the executable
case $SCRIPT_ARCHITECTURE in
	$SCRIPT_ARCHITECTURE_PC)

		make_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
		pc_output_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$PC_OUTPUT_FILE

		case $SCRIPT_SCENARIO in
			$SCRIPT_SCENARIO_0)
				simulate $PC_CIPHER_FILE $pc_output_file $make_log_file
	
				if [ -f $pc_output_file ] ; then
					s_execution_time=$(compute_execution_time $pc_output_file 'SetupCycleCount')
					e_execution_time=$(compute_execution_time $pc_output_file 'EncryptCycleCount')
				fi
				;;
			$SCRIPT_SCENARIO_1)
				simulate $PC_SCENARIO1_FILE $pc_output_file $make_log_file

				if [ -f $pc_output_file ] ; then
					s_execution_time=$(compute_execution_time $pc_output_file 'SetupCycleCount')
					e_execution_time=$(compute_execution_time $pc_output_file 'EncryptCycleCount')
				fi
				;;
		esac

		if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
			# Remove log files
			rm -f $make_log_file
			rm -f $pc_output_file
		fi
		;;
		
	$SCRIPT_ARCHITECTURE_AVR)

		avr_execution_time_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$AVR_EXECUTION_TIME_LOG_FILE		
		
		case $SCRIPT_SCENARIO in
			$SCRIPT_SCENARIO_0)
				simulate $file $avr_execution_time_log_file

				if [ -f $avr_execution_time_log_file ] ; then
					s_execution_time=$(compute_execution_time $avr_execution_time_log_file 'Setup' 'EndSetup')
					e_execution_time=$(compute_execution_time $avr_execution_time_log_file 'Encrypt' 'EndEncryption')
				fi
				;;
			$SCRIPT_SCENARIO_1)
				simulate $file $avr_execution_time_log_file

				if [ -f $avr_execution_time_log_file ] ; then
					s_execution_time=$(compute_execution_time $avr_execution_time_log_file 'Setup' 'EndSetup')
					e_execution_time=$(compute_execution_time $avr_execution_time_log_file 'Encrypt' 'EndEncryption')
				fi
				;;
		esac
	
		if [ -f $avr_execution_time_log_file ] ; then
			total_execution_time=$(compute_execution_time $avr_execution_time_log_file 'main')
		fi

		if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
			# Remove log file
			rm -f $avr_execution_time_log_file
		fi
		;;

	$SCRIPT_ARCHITECTURE_MSP)

		mspdebug_execution_time_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MSPDEBUG_EXECUTION_TIME_LOG_FILE
		mspdebug_execution_time_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MSPDEBUG_EXECUTION_TIME_SECTIONS_LOG_FILE

		case $SCRIPT_SCENARIO in
			$SCRIPT_SCENARIO_0)
				simulate $MSP_CIPHER_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE $mspdebug_execution_time_log_file
				simulate $MSP_CIPHER_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE $mspdebug_execution_time_sections_log_file

				if [ -f $mspdebug_execution_time_log_file ] ; then
					s_execution_time=$(compute_execution_time $mspdebug_execution_time_sections_log_file 1)
					e_execution_time=$(compute_execution_time $mspdebug_execution_time_sections_log_file 3)
				fi
				;;
			$SCRIPT_SCENARIO_1)
				simulate $MSP_SCENARIO1_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE $mspdebug_execution_time_log_file
				simulate $MSP_SCENARIO1_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE $mspdebug_execution_time_sections_log_file

				if [ -f $mspdebug_execution_time_log_file ] ; then
					s_execution_time=$(compute_execution_time $mspdebug_execution_time_sections_log_file 1)
					e_execution_time=$(compute_execution_time $mspdebug_execution_time_sections_log_file 3)
				fi
				;;
		esac

		if [ -f $mspdebug_execution_time_log_file ] ; then
			total_execution_time=$(compute_execution_time $mspdebug_execution_time_log_file 1)
		fi

		if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
			# Remove log files
			rm -f $mspdebug_execution_time_log_file
			rm -f $mspdebug_execution_time_sections_log_file
		fi
		;;

	$SCRIPT_ARCHITECTURE_ARM)

		make_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
		arm_serial_terminal_output_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$ARM_SERIAL_TERMINAL_OUTPUT_FILE

		case $SCRIPT_SCENARIO in
			$SCRIPT_SCENARIO_0)
				simulate $file $arm_serial_terminal_output_file $make_log_file $UPLOAD_CIPHER
			
				if [ -f $arm_serial_terminal_output_file ] ; then
					s_execution_time=$(compute_execution_time $arm_serial_terminal_output_file 'SetupCycleCount')
					e_execution_time=$(compute_execution_time $arm_serial_terminal_output_file 'EncryptCycleCount')
				fi
				;;
			$SCRIPT_SCENARIO_1)
				simulate $file $arm_serial_terminal_output_file $make_log_file $UPLOAD_SCENARIO1

				if [ -f $arm_serial_terminal_output_file ] ; then
					s_execution_time=$(compute_execution_time $arm_serial_terminal_output_file 'SetupCycleCount')
					e_execution_time=$(compute_execution_time $arm_serial_terminal_output_file 'EncryptCycleCount')
				fi
				;;
		esac
		
		if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
			# Remove log files
			rm -f $make_log_file
			rm -f $arm_serial_terminal_output_file
		fi
		;;
esac


# Dipslay results
if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
	# Clear output
	echo -n "" > $SCRIPT_OUTPUT
	
	# Table header
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
	printf "\n" >> $SCRIPT_OUTPUT
	printf "| %10s | %10s | %10s |\n" "Scenario" "Setup" "Enc." >> $SCRIPT_OUTPUT
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
	printf "\n" >> $SCRIPT_OUTPUT

	# Table line
	printf "| %10s | %10s | %10s |\n" $total_execution_time $s_execution_time $e_execution_time >> $SCRIPT_OUTPUT

	# Table footer
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
	printf "\n" >> $SCRIPT_OUTPUT
else
	case $SCRIPT_SCENARIO in
		$SCRIPT_SCENARIO_0)
			# Display results
			printf "%s %s" $s_execution_time $e_execution_time > $SCRIPT_OUTPUT
			;;
		$SCRIPT_SCENARIO_1)
			# Display results
			printf "%s %s" $s_execution_time $e_execution_time > $SCRIPT_OUTPUT
			;;
	esac
fi


# Change current working directory
cd $current_directory
if [ $SCRIPT_MODE_0 -ne $SCRIPT_MODE ] ; then
	echo ""
fi
echo "End cipher execution time - $(pwd)"
