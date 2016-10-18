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
# Call this script to extract the cipher code size
# 	./cipher_code_size.sh [{-h|--help}] [--version] [{-m|--mode}=[0|1]] [{-s|--scenario}=[0|1|2]] [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-t|--target}=[...]] [{-o|--output}=[...]] [{-b|build}=[0|1]] [{-co|--compiler_options}='...']
#
#	To call from a cipher build folder use:
#		./../../../../scripts/cipher/cipher_code_size.sh [options]
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
#		./../../../../scripts/cipher/cipher_code_size.sh -m=0
#		./../../../../scripts/cipher/cipher_code_size.sh --mode=1 --architecture=MSP
#  		./../../../../scripts/cipher/cipher_code_size.sh -o=results.txt
#		./cipher_code_size.sh -t=./../../source/ciphers/CipherName_BlockSizeInBits_KeySizeInBits_v01/build
#


# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/../config/config.sh

# Include constants files
source $script_path/../constants/constants.sh
source $script_path/../constants/cipher/cipher_code_size.sh

# Include help file
source $script_path/../help/cipher/cipher_code_size.sh

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


# Set the current working directory
current_directory=$(pwd)
echo "Begin cipher code size - $current_directory"


# Change relative script output path
if [[ $SCRIPT_OUTPUT != /* ]] ; then
	SCRIPT_OUTPUT=$current_directory/$SCRIPT_OUTPUT
fi


# Change current working directory
cd $SCRIPT_TARGET
echo "Changed working directory: $(pwd)"


# Get the cipher name
cipher_name=$(basename -- "$(dirname -- "$(pwd)")")


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


if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
	# Clear output
	echo -n "" > $SCRIPT_OUTPUT
	
	# Table header
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
	printf "\n" >> $SCRIPT_OUTPUT
	printf "| %-30s | %10s | %10s | %10s | %10s | %10s |\n" "Component" "ROM" "text" "data" "bss" "dec" >> $SCRIPT_OUTPUT
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
	printf "\n" >> $SCRIPT_OUTPUT
fi


for file in $files
do
	# Get the section sizes line for current file
	if [ -e $file ] ; then
		size=$($script_size $file | grep $file)
	else
		continue
	fi

	# Get the section sizes
	text=$(echo $size | cut -d ' ' -f 1)
	data=$(echo $size | cut -d ' ' -f 2)
	bss=$(echo $size | cut -d ' ' -f 3)
	dec=$(echo $size | cut -d ' ' -f 4)

	# Compute the ROM requirement	
	rom=$(($text + $data))
	

	# Get the component name (file name without the extension)
	component=${file%$OBJECT_FILE_EXTENSION}
	if [ "$component" == "$file" ] ; then
		component=${file%$ELF_FILE_EXTENSION}
	fi
	

	if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
		# Table line
		printf "| %-30s | %10s | %10s | %10s | %10s | %10s |\n" $component $rom $text $data $bss $dec >> $SCRIPT_OUTPUT
	else
		# Set the component section sizes
		declare $component"_text"=$text
		declare $component"_data"=$data
		declare $component"_bss"=$bss
		declare $component"_dec"=$dec

		# Set the component ROM requirement
		declare $component"_rom"=$rom
	fi
done


if [ $SCRIPT_MODE_0 -ne $SCRIPT_MODE ] ; then
	shared_code_eks=0
	shared_code_e=0
	shared_code_dks=0
	shared_code_d=0
	shared_code_total=0

	# Read and process code implementation information
	declare -a shared_parts
	for code_section in ${CODE_SECTIONS[@]}
	do
		shared_files=$(cat $IMPLEMENTATION_INFO_FILE | grep $code_section$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 | tr ',' ' ')

		for shared_file in $shared_files
		do
			shared_name=$shared_file"_rom"

			shared_value=${!shared_name}
			if [ "" == "$shared_value" ] ; then
				shared_value=0
			fi


			# Test if the shared file ROM was added to the total
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
				shared_code_total=$(($shared_code_total + $shared_value))
				shared_parts+=($shared_file) 
			fi
		
		
			case $code_section in
				$CODE_SECTION_EKS)
					shared_code_eks=$(($shared_code_eks + $shared_value))
					;;
				$CODE_SECTION_E)
					shared_code_e=$(($shared_code_e + $shared_value))
					;;
				$CODE_SECTION_DKS)
					shared_code_dks=$(($shared_code_dks + $shared_value))
					;;
				$CODE_SECTION_D)
					shared_code_d=$(($shared_code_d + $shared_value))
					;;
			esac
		done
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
			shared_name=$shared_file"_rom"

			shared_value=${!shared_name}
			if [ "" == "$shared_value" ] ; then
				shared_value=0
			fi


			# Test if the shared file ROM was added to the total
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

	
	# Check if encryption/decryption key schedule is used
	use_encryption_key_schedule=$(cat $IMPLEMENTATION_INFO_FILE | grep $USE_ENCRYPTION_KEY_SCHEDULE$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')
	use_decryption_key_schedule=$(cat $IMPLEMENTATION_INFO_FILE | grep $USE_DECRYPTION_KEY_SCHEDULE$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')

	# Convert to lowercase
	use_encryption_key_schedule=${use_encryption_key_schedule,,}
	use_decryption_key_schedule=${use_decryption_key_schedule,,}

	if [ $USE_KEY_SCHEDULE_NO == "$use_encryption_key_schedule" ] ; then
		encryption_key_schedule_rom=0
	fi

	if [ $USE_KEY_SCHEDULE_NO == "$use_decryption_key_schedule" ] ; then
		decryption_key_schedule_rom=0
	fi

	# Test if decryption key schedule is empty
	case $SCRIPT_ARCHITECTURE in
		$SCRIPT_ARCHITECTURE_PC)
			if [ $EMPTY_DKS_PC -ge $decryption_key_schedule_rom ] ; then
				decryption_key_schedule_rom=0
			fi
			;;
		$SCRIPT_ARCHITECTURE_AVR)
			if [ $EMPTY_DKS_AVR -ge $decryption_key_schedule_rom ] ; then
				decryption_key_schedule_rom=0
			fi
			;;
		$SCRIPT_ARCHITECTURE_MSP)
			if [ $EMPTY_DKS_MSP -ge $decryption_key_schedule_rom ] ; then
				decryption_key_schedule_rom=0
			fi
			;;
		$SCRIPT_ARCHITECTURE_ARM)
			if [ $EMPTY_DKS_ARM -ge $decryption_key_schedule_rom ] ; then
				decryption_key_schedule_rom=0
			fi
			;;
	esac


	# Cipher
	cipher_eks=$(($encryption_key_schedule_rom + $shared_code_eks + $shared_constants_eks))
	cipher_e=$(($encrypt_rom + $shared_code_e + $shared_constants_e))
	cipher_dks=$(($decryption_key_schedule_rom + $shared_code_dks + $shared_constants_dks))
	cipher_d=$(($decrypt_rom + $shared_code_d + $shared_constants_d))
	cipher_total=$(($encryption_key_schedule_rom + $encrypt_rom + $decryption_key_schedule_rom + $decrypt_rom + $shared_code_total + $shared_constants_total))

	#Scenarios
	case $SCRIPT_SCENARIO in
		$SCRIPT_SCENARIO_1)
			# Scenario 1
			scenario1_eks=$cipher_eks
			scenario1_e=$(($encrypt_scenario1_rom + $cipher_e))
			scenario1_dks=$cipher_dks
			scenario1_d=$(($decrypt_scenario1_rom + $cipher_d))
			scenario1_total=$(($encrypt_scenario1_rom + $decrypt_scenario1_rom + $cipher_total))
			;;

		$SCRIPT_SCENARIO_2)
			# Scenario 2
			scenario2_e=$(($encrypt_scenario2_rom + $round_keys_rom + $cipher_e))
			;;
	esac
fi


# Dipslay results
if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
	# Table footer
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
	printf "\n" >> $SCRIPT_OUTPUT
else
	case $SCRIPT_SCENARIO in
		$SCRIPT_SCENARIO_0)
			# Display results
			printf "%s %s %s %s %s" $cipher_eks $cipher_e $cipher_dks $cipher_d $cipher_total > $SCRIPT_OUTPUT
			;;
		$SCRIPT_SCENARIO_1)
			# Display results
			printf "%s %s %s %s %s" $scenario1_eks $scenario1_e $scenario1_dks $scenario1_d $scenario1_total > $SCRIPT_OUTPUT
			;;
		$SCRIPT_SCENARIO_2)
			# Display results
			printf "%s" $scenario2_e > $SCRIPT_OUTPUT
			;;
	esac
fi


# Change current working directory
cd $current_directory
if [ $SCRIPT_MODE_0 -ne $SCRIPT_MODE ] ; then
	echo ""
fi
echo "End cipher code size - $(pwd)"
