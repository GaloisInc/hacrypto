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
# Call this script to extract the cipher RAM consumption
# 	./cipher_ram.sh [{-h|--help}] [--version] [{-m|--mode}=[0|1]] [{-s|--scenario}=[0|1|2]] [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-t|--target}=[...]] [{-o|--output}=[...]] [{-b|build}=[0|1]] [{-co|--compiler_options}='...']
#
#	To call from a cipher build folder use:
#		./../../../../scripts/cipher/cipher_ram.sh [options]
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
#		./../../../../scripts/cipher/cipher_ram.sh -m=0
#		./../../../../scripts/cipher/cipher_ram.sh --mode=1 --architecture=MSP
#  		./../../../../scripts/cipher/cipher_ram.sh -o=results.txt
#		./cipher_ram.sh -t=./../../source/ciphers/CipherName_BlockSizeInBits_KeySizeInBits_v01/build
#


# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/../config/config.sh

# Include constants files
source $script_path/../constants/constants.sh
source $script_path/../constants/cipher/cipher_ram.sh

# Include help file
source $script_path/../help/cipher/cipher_ram.sh

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
# 	$1 - the gdb command file
# 	$2 - the gdb target binary file
# 	$3 - the gdb output file
# 	$4 - the simulator output file
# 	$5 - the make log file
function simulate()
{
	local command_file=$1
	local target_file=$2
	local gdb_output_file=$3
	local simulator_output_file=$4
	local make_log_file=$5


	case $SCRIPT_ARCHITECTURE in
		$SCRIPT_ARCHITECTURE_PC)
			$PC_GDB -x $command_file $target_file &> $gdb_output_file &
			;;
		$SCRIPT_ARCHITECTURE_AVR)
			$SIMAVR_SIMULATOR -g -m atmega128 $target_file &> $simulator_output_file &
			$AVR_GDB -x $command_file &> $gdb_output_file
			
			simavr_pid=$(ps aux | grep "$SIMAVR_SIMULATOR -g -m atmega128 $target_file" | grep -v "grep" | tr -s ' ' | cut -d ' ' -f 2)	
			for pid in $simavr_pid
			do
				kill -PIPE $pid
			done
			;;
		$SCRIPT_ARCHITECTURE_MSP)
			$MSPDEBUG_SIMULATOR -n sim "prog $target_file" gdb &> $simulator_output_file &
			$MSP_GDB -x $command_file &> $gdb_output_file
			;;
		$SCRIPT_ARCHITECTURE_ARM)
			# Upload the program to the board
			make -f ./../../../common/cipher.mk ARCHITECTURE=$SCRIPT_ARCHITECTURE $target_file &> $make_log_file

			$JLINK_GDB_SERVER -device cortex-m3 &> $simulator_output_file &
			$ARM_GDB -x $command_file &> $gdb_output_file

			jlink_gdb_server_pid=$(ps aux | grep "JLinkGDBServer" | grep -v "grep" | tr -s ' ' | cut -d ' ' -f 2)
			for pid in $jlink_gdb_server_pid
			do	
				kill -PIPE $pid
			done
			;;
	esac

	# Wait for the debug session to finish
	sleep 1
}


# Compute the stack usage
# Parameters:
# 	$1 - the gdb output file
# 	$2 - the gdb printed variable name
function compute_stack_usage()
{
	local output_file=$1
	local variable_name=$2


	# Get the stack content array
	local stack_content=( $(cat $output_file | nawk '/\$'$variable_name' = {/,/}/' | tr -d '\r' | cut -d '{' -f 2 | cut -d '}' -f 1 | tr -d ',') ) 

	local count=0
	while [ $((${stack_content[$count]})) -eq $((${MEMORY_PATTERN[$(($count % $memory_patern_length))]})) ]
	do
		count=$(($count + 1));
	done

	local used_stack=$(($MEMORY_SIZE - $count))
	
	echo $used_stack
}


# Set the current working directory
current_directory=$(pwd)
echo "Begin cipher RAM - $current_directory"


# Change relative script output path
if [[ $SCRIPT_OUTPUT != /* ]] ; then
	SCRIPT_OUTPUT=$current_directory/$SCRIPT_OUTPUT
fi


# Change current working directory
cd $SCRIPT_TARGET
echo "Changed working directory: $(pwd)"


# Get the state, key, round keys size
block_size=$(cat $CONSTANTS_SOURCE_FILE | grep "$BLOCK_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)
key_size=$(cat $CONSTANTS_SOURCE_FILE | grep "$KEY_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)
round_keys_size=$(cat $CONSTANTS_SOURCE_FILE | grep "$ROUND_KEYS_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)


# Set the searched files pattern
pattern=$ALL_FILES$OBJECT_FILE_EXTENSION 

# Get the number of files matching the pattern
files_number=$(find . -maxdepth 1 -type f -name "$pattern" | wc -l)

if [ 0 -eq $files_number ] ; then
	echo "There is no file matching the pattern: '$pattern' for cipher '$cipher_name'!"
	echo "Exit!"
	exit
fi

# Get the files matching the pattern
files=$(ls $pattern)


# Add scenario *.elf file to the files
case $SCRIPT_SCENARIO in
	$SCRIPT_SCENARIO_0)
		files="$CIPHER_FILE$ELF_FILE_EXTENSION $files"	
		;;

	$SCRIPT_SCENARIO_1)
		files="$SCENARIO1_FILE$ELF_FILE_EXTENSION $files"
		;;

	$SCRIPT_SCENARIO_2)
		files="$SCENARIO2_FILE$ELF_FILE_EXTENSION $files"
		;;
esac


# Set the size command depending on the architecture
case $SCRIPT_ARCHITECTURE in
	$SCRIPT_ARCHITECTURE_PC)
		script_size=$PC_SIZE	
		;;

	$SCRIPT_ARCHITECTURE_AVR)
		script_size=$AVR_SIZE
		;;

	$SCRIPT_ARCHITECTURE_MSP)
		script_size=$MSP_SIZE
		;;

	$SCRIPT_ARCHITECTURE_ARM)
		script_size=$ARM_SIZE
		;;
esac


for file in $files
do
	# Get the section sizes line for current file
	if [ -e $file ] ; then
		size=$($script_size $file | grep $file)
	else
		continue
	fi

	# Get the section data size
	data=$(echo $size | cut -d ' ' -f 2)
	
	# Get the component name (file name without the extension)
	component=${file%$OBJECT_FILE_EXTENSION}
	if [ "$component" == "$file" ] ; then
		component=${file%$ELF_FILE_EXTENSION}
	fi

	declare $component"_data"=$data
done


shared_constants_eks=0
shared_constants_e=0
shared_constants_dks=0
shared_constants_d=0
shared_constants_total=0

# Read and process constants implementation information
declare -a shared_parts
for constants_section in ${CONSTANTS_SECTIONS[@]}
do
	shared_files=$(cat $IMPLEMENTATION_INFO_FILE | grep $constants_section$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 | tr ',' ' ')

	for shared_file in $shared_files
	do
		shared_name=$shared_file"_data"

		shared_value=${!shared_name}
		if [ "" == "$shared_value" ] ; then
			shared_value=0
		fi


		# Test if the shared file RAM was added to the total
		used_part=$FALSE
		for shared_part in ${shared_parts[@]}
		do
			if [ "$shared_part" == "$shared_file" ] ; then
				used_part=$TRUE
				break
			fi
		done

	
		# Add the shared file ROM to total
		if [ $FALSE -eq $used_part ]; then
			shared_constants_total=$(($shared_constants_total + $shared_value))
			shared_parts+=($shared_file) 
		fi
	
	
		case $constants_section in
			$CONSTANTS_SECTION_EKS)
				shared_constants_eks=$(($shared_constants_eks + $shared_value))
				;;
			$CONSTANTS_SECTION_E)
				shared_constants_e=$(($shared_constants_e + $shared_value))
				;;
			$CONSTANTS_SECTION_DKS)
				shared_constants_dks=$(($shared_constants_dks + $shared_value))
				;;
			$CONSTANTS_SECTION_D)
				shared_constants_d=$(($shared_constants_d + $shared_value))
				;;
		esac
	done
done


# Check if encryption key schedule is used
use_encryption_key_schedule=$(cat $IMPLEMENTATION_INFO_FILE | grep $USE_ENCRYPTION_KEY_SCHEDULE$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')

# Convert to lowercase
use_encryption_key_schedule=${use_encryption_key_schedule,,}


# Compute the data RAM
case $SCRIPT_SCENARIO in
	$SCRIPT_SCENARIO_0)
		data_ram_eks=$shared_constants_eks
		data_ram_e=$shared_constants_e
		data_ram_dks=$shared_constants_dks
		data_ram_d=$shared_constants_d

		if [ $USE_KEY_SCHEDULE_NO == "$use_encryption_key_schedule" ] ; then
			# Data RAM common = key + block/state
			data_ram_common=$(($key_size + $block_size))
		else
			# Data RAM common = key + round keys + block/state
			data_ram_common=$(($key_size + $round_keys_size + $block_size))
		fi
		
		data_ram_total=$(($data_ram_common + $shared_constants_total))
		;;
	$SCRIPT_SCENARIO_1)
		data_ram_eks=$shared_constants_eks
		data_ram_e=$shared_constants_e
		data_ram_dks=$shared_constants_dks
		data_ram_d=$shared_constants_d

		data_size=$(cat $SCENARIO1_CONSTANTS_SOURCE_FILE | grep "$RAW_DATA_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)
		if [ $USE_KEY_SCHEDULE_NO == "$use_encryption_key_schedule" ] ; then
			# Data RAM common = key + data/state + IV
			data_ram_common=$(($key_size + $data_size + $block_size))
		else
			# Data RAM common = key + round keys + data/state + IV
			data_ram_common=$(($key_size + $round_keys_size + $data_size + $block_size))
		fi

		data_ram_total=$(($data_ram_common + $shared_constants_total))
		;;
	$SCRIPT_SCENARIO_2)
		data_size=$(cat $SCENARIO2_CONSTANTS_SOURCE_FILE | grep "$RAW_DATA_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)
		# Data RAM = data/state + counter + shared constants
		data_ram_total=$(($data_size + $block_size + $shared_constants_e))
		;;
esac


# Get the memory pattern length
memory_patern_length=$((${#MEMORY_PATTERN[@]}))

# Generate the memory file
memory_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MEMORY_FILE
echo "Generate the memory file: '$memory_file'"
echo -n "" > $memory_file

for ((i=0; i<$MEMORY_SIZE/$memory_patern_length; i++))
do
	echo -ne "$(printf '\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x' ${MEMORY_PATTERN[*]})" >> $memory_file
done


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

	$SCRIPT_SCENARIO_2)
		file=$SCENARIO2_FILE$ELF_FILE_EXTENSION
		;;
esac


# Get the number of files matching the pattern
files_number=$(find . -maxdepth 1 -type f -name "$file" | wc -l)

if [ 0 -eq $files_number ] ; then
	echo "There is no file matching the pattern: '$file' for cipher '$cipher_name'!"
	echo "Exit!"
	exit
fi


gdb_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$GDB_STACK_LOG_FILE
gdb_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$GDB_STACK_SECTIONS_LOG_FILE

# Debug the executable
case $SCRIPT_ARCHITECTURE in
	$SCRIPT_ARCHITECTURE_PC)

		case $SCRIPT_SCENARIO in
			$SCRIPT_SCENARIO_0)
				simulate $PC_CIPHER_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
				simulate $PC_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
				;;
			$SCRIPT_SCENARIO_1)
				simulate $PC_SCENARIO1_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
				simulate $PC_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
				;;
			$SCRIPT_SCENARIO_2)
				simulate $PC_SCENARIO2_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
				simulate $PC_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
				;;
		esac
		;;

	$SCRIPT_ARCHITECTURE_AVR)

		simavr_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$SIMAVR_STACK_LOG_FILE
		simavr_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$SIMAVR_STACK_SECTIONS_LOG_FILE

		case $SCRIPT_SCENARIO in
			$SCRIPT_SCENARIO_0)
				simulate $AVR_CIPHER_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
				simulate $AVR_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file
				;;
			$SCRIPT_SCENARIO_1)
				simulate $AVR_SCENARIO1_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
				simulate $AVR_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file
				;;
			$SCRIPT_SCENARIO_2)
				simulate $AVR_SCENARIO2_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
				simulate $AVR_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file
				;;
		esac

		if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
			# Remove log files
			rm -f $simavr_stack_log_file
			rm -f $simavr_stack_sections_log_file
		fi
		;;
	
	$SCRIPT_ARCHITECTURE_MSP)

		mspdebug_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MSPDEBUG_STACK_LOG_FILE
		mspdebug_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MSPDEBUG_STACK_SECTIONS_LOG_FILE

		case $SCRIPT_SCENARIO in
			$SCRIPT_SCENARIO_0)
				simulate $MSP_CIPHER_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
				simulate $MSP_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
				;;
			$SCRIPT_SCENARIO_1)
				simulate $MSP_SCENARIO1_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
				simulate $MSP_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
				;;
			$SCRIPT_SCENARIO_2)
				simulate $MSP_SCENARIO2_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
				simulate $MSP_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
				;;
		esac

		if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
			# Remove log files
			rm -f $mspdebug_stack_log_file
			rm -f $mspdebug_stack_sections_log_file
		fi
		;;

	$SCRIPT_ARCHITECTURE_ARM)

		make_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
		jlink_gdb_server_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$JLINK_GDB_SERVER_STACK_LOG_FILE
		jlink_gdb_server_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$JLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE

		case $SCRIPT_SCENARIO in
			$SCRIPT_SCENARIO_0)
				simulate $ARM_CIPHER_GDB_STACK_COMMANDS_FILE $UPLOAD_CIPHER $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
				simulate $ARM_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE $UPLOAD_CIPHER $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
				;;
			$SCRIPT_SCENARIO_1)
				simulate $ARM_SCENARIO1_GDB_STACK_COMMANDS_FILE $UPLOAD_SCENARIO1 $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
				simulate $ARM_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $UPLOAD_SCENARIO1 $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
				;;
			$SCRIPT_SCENARIO_2)
				simulate $ARM_SCENARIO2_GDB_STACK_COMMANDS_FILE $UPLOAD_SCENARIO2 $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
				simulate $ARM_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE $UPLOAD_SCENARIO2 $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
				;;
		esac

		if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
			# Remove log files
			rm -f $make_log_file
			rm -f $jlink_gdb_server_stack_log_file
			rm -f $jlink_gdb_server_stack_sections_log_file
		fi
		;;
esac


eks_stack=0
e_stack=0
dks_stack=0
d_stack=0
total_stack=0

if [ -f $gdb_stack_log_file ] ; then
	total_stack=$(compute_stack_usage $gdb_stack_log_file 1)
fi

if [ -f $gdb_stack_sections_log_file ] ; then
	case $SCRIPT_SCENARIO in
		$SCRIPT_SCENARIO_0)
			eks_stack=$(compute_stack_usage $gdb_stack_sections_log_file 1)
			e_stack=$(compute_stack_usage $gdb_stack_sections_log_file 2)
			dks_stack=$(compute_stack_usage $gdb_stack_sections_log_file 3)
			d_stack=$(compute_stack_usage $gdb_stack_sections_log_file 4)
			;;
		$SCRIPT_SCENARIO_1)
			eks_stack=$(compute_stack_usage $gdb_stack_sections_log_file 1)
			e_stack=$(compute_stack_usage $gdb_stack_sections_log_file 2)
			dks_stack=$(compute_stack_usage $gdb_stack_sections_log_file 3)
			d_stack=$(compute_stack_usage $gdb_stack_sections_log_file 4)
			;;
		$SCRIPT_SCENARIO_2)
			e_stack=$(compute_stack_usage $gdb_stack_sections_log_file 1)
			;;
	esac
fi


if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
	# Remove memory and gdb log files
	rm -f $memory_file
	rm -f $gdb_stack_log_file
	rm -f $gdb_stack_sections_log_file
fi


# Check if encryption/decryption key schedule is used
use_encryption_key_schedule=$(cat $IMPLEMENTATION_INFO_FILE | grep $USE_ENCRYPTION_KEY_SCHEDULE$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')
use_decryption_key_schedule=$(cat $IMPLEMENTATION_INFO_FILE | grep $USE_DECRYPTION_KEY_SCHEDULE$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')

# Convert to lowercase
use_encryption_key_schedule=${use_encryption_key_schedule,,}
use_decryption_key_schedule=${use_decryption_key_schedule,,}

if [ $USE_KEY_SCHEDULE_NO == "$use_encryption_key_schedule" ] ; then
	eks_stack=0
fi

if [ $USE_KEY_SCHEDULE_NO == "$use_decryption_key_schedule" ] ; then
	dks_stack=0
fi


# Dipslay results
if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
	# Clear output
	echo -n "" > $SCRIPT_OUTPUT
	
	# Table header
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
	printf "\n" >> $SCRIPT_OUTPUT
	printf "| %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s |\n" "Block Size" "Key Size" "R.K.s Size" "Data RAM" "Scenario" "Enc. K.S." "Enc." "Dec. K.S." "Dec." >> $SCRIPT_OUTPUT
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
	printf "\n" >> $SCRIPT_OUTPUT

	# Table line
	printf "| %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s |\n" $block_size $key_size $round_keys_size $data_ram_total $total_stack $eks_stack $e_stack $dks_stack $d_stack >> $SCRIPT_OUTPUT

	# Table footer
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
	printf "\n" >> $SCRIPT_OUTPUT
else
	case $SCRIPT_SCENARIO in
		$SCRIPT_SCENARIO_0)
			# Display results
			printf "%s %s %s %s %s %s %s %s %s %s" $eks_stack $e_stack $dks_stack $d_stack $data_ram_eks $data_ram_e $data_ram_dks $data_ram_d $data_ram_common $data_ram_total > $SCRIPT_OUTPUT
			;;
		$SCRIPT_SCENARIO_1)
			# Display results
			printf "%s %s %s %s %s %s %s %s %s %s" $eks_stack $e_stack $dks_stack $d_stack $data_ram_eks $data_ram_e $data_ram_dks $data_ram_d $data_ram_common $data_ram_total > $SCRIPT_OUTPUT
			;;
		$SCRIPT_SCENARIO_2)
			# Display results
			printf "%s %s" $e_stack $data_ram_total > $SCRIPT_OUTPUT
			;;
	esac
fi
	

# Change current working directory
cd $current_directory
if [ $SCRIPT_MODE_0 -ne $SCRIPT_MODE ] ; then
	echo ""
fi
echo "End cipher RAM - $(pwd)"
