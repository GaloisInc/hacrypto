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
# Call this script to get the results
# 	./get_results.sh [{-h|--help}] [--version] [{-f|--format}=[0|1|2|3|4|5]] [{-a|--architectures}=['PC AVR MSP ARM']] [{-s|--scenarios}=['0 1 2']] [{-c|--ciphers}=['Cipher1 Cipher2 ...']] [{-p|--prefix}='...'] [{-co|--compiler_options}='...'] [{-i|incremental}=[0|1]]
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
#			Specifies for which archiectures to get the results
#				List of values: 'PC AVR MSP ARM'
#				Default: all architectures
#		-s, --scenarios
#			Specifies for which scenarios to get the results
#				List of values: '0 1 2'
#				Default: all scenarios
#		-c, --ciphers
#			Specifies for which ciphers to get the results
#				List of values: 'CipherName_BlockSizeInBits_KeySizeInBits_v01 ...'
#				Default: all ciphers
#		-p, --prefix
#			Specifies the results file prefix
#				Default: current date in 'YYYY_mm_dd' format
#		-co,--compiler_options
#			Specifies the compiler options
#				List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'
#				Default: all compiler options
#		-i, --incremental
#			Specifies if script should use an incremntal strategy (collect results just for new and modified implementations since the last run)
#				0 - do not use incrmental strategy
#				1 - use incremental strategy
#				Default: 1
#
#	Examples:
#		./get_results.sh -f=0
#		./get_results.sh --format=1
#		./get_results.sh -a='PC AVR' --scenarios="1 2"
#


# Get current script path
script_path=$(dirname $0)

# Include constants files
source $script_path/constants/constants.sh
source $script_path/constants/get_results.sh

# Include help file
source $script_path/help/get_results.sh

# Include validation functions
source $script_path/common/validate.sh

# Include version file
source $script_path/common/version.sh


# Default values
SCRIPT_FORMAT=$SCRIPT_FORMAT_0
SCRIPT_INCREMENTAL_STRATEGY=$SCRIPT_INCREMENTAL_STRATEGY_ENABLED


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
		-p=*|--prefix=*)
			SCRIPT_USER_PREFIX="${i#*=}"
			shift
			;;
		-co=*|--compiler_options=*)
			SCRIPT_USER_COMPILER_OPTIONS="${i#*=}"
			shift
			;;
		-i=*|--incremental=*)
			SCRIPT_INCREMENTAL_STRATEGY="${i#*=}"
			shift
			;;
		*)
			# Unknown option
			;;
	esac
done


echo "Script settings:"
echo -e "\t SCRIPT_FORMAT \t\t\t = $SCRIPT_FORMAT"
echo -e "\t SCRIPT_INCREMENTAL_STRATEGY \t = $SCRIPT_INCREMENTAL_STRATEGY"


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


# Create directory structure
function create_directory_structure()
{
	mkdir -p $SCRIPT_RESULTS_DIR_PATH

	mkdir -p $SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME

	for architecture in ${architectures[@]}
	do
		mkdir -p $SCRIPT_RESULTS_DIR_PATH$architecture
	done

	# Create new timestamp
	echo $new_timestamp > $TIMESTAMP_FILE_PATH
}


# Move ciphers info
function move_ciphers_info()
{
	case $SCRIPT_FORMAT in
		$SCRIPT_FORMAT_0)
			raw_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_RAW_OUTPUT_EXTENSION
			source_file=$SCRIPT_OUTPUT_PATH/$raw_file
			destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$raw_file
			if [ -f $source_file ] ; then
				mv $source_file $destination_file
			fi

			mediawiki_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
			source_file=$SCRIPT_OUTPUT_PATH/$mediawiki_file
			destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$mediawiki_file
			if [ -f $source_file ] ; then
				mv $source_file $destination_file
			fi

			xml_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_XML_OUTPUT_EXTENSION
			source_file=$SCRIPT_OUTPUT_PATH/$xml_file
			destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$xml_file
			if [ -f $source_file ] ; then
				mv $source_file $destination_file
			fi

			latex_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_LATEX_OUTPUT_EXTENSION
			source_file=$SCRIPT_OUTPUT_PATH/$latex_file
			destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$latex_file
			if [ -f $source_file ] ; then
				mv $source_file $destination_file
			fi
		
			csv_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_CSV_OUTPUT_EXTENSION
			source_file=$SCRIPT_OUTPUT_PATH/$csv_file
			destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$csv_file
			if [ -f $source_file ] ; then
				mv $source_file $destination_file
			fi
			;;
		$SCRIPT_FORMAT_1)
			raw_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_RAW_OUTPUT_EXTENSION
			source_file=$SCRIPT_OUTPUT_PATH/$raw_file
			destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$raw_file
			if [ -f $source_file ] ; then
				mv $source_file $destination_file
			fi
			;;
		$SCRIPT_FORMAT_2)
			mediawiki_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
			source_file=$SCRIPT_OUTPUT_PATH/$mediawiki_file
			destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$mediawiki_file
			if [ -f $source_file ] ; then
				mv $source_file $destination_file
			fi
			;;
		$SCRIPT_FORMAT_3)
			xml_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_XML_OUTPUT_EXTENSION
			source_file=$SCRIPT_OUTPUT_PATH/$xml_file
			destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$xml_file
			if [ -f $source_file ] ; then
				mv $source_file $destination_file
			fi
			;;
		$SCRIPT_FORMAT_4)
			latex_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_LATEX_OUTPUT_EXTENSION
			source_file=$SCRIPT_OUTPUT_PATH/$latex_file
			destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$latex_file
			if [ -f $source_file ] ; then
				mv $source_file $destination_file
			fi
			;;
		$SCRIPT_FORMAT_5)
			csv_file=$INFO_OUTPUT_FILE_NAME$SCRIPT_CSV_OUTPUT_EXTENSION
			source_file=$SCRIPT_OUTPUT_PATH/$csv_file
			destination_file=$SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$file_prefix$csv_file
			if [ -f $source_file ] ; then
				mv $source_file $destination_file
			fi
			;;
	esac
}


# Change current directory to script source path directory
if [ '.' != $script_path ] ; then
	cd $script_path
fi


# Set the current working directory
current_directory=$(pwd)
echo "Begin get results - $current_directory"


# Get the last run timestamp
old_timestamp=0
if [ -f $TIMESTAMP_FILE_PATH ]; then
	old_timestamp=$(cat $TIMESTAMP_FILE_PATH)
fi

# Get the new timestamp
new_timestamp=$(date +%s)


# Change current working directory
cd $CIPHERS_PATH
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


# User did not select architectures
user_architectures=$FALSE

# If user architectures are not set, use all architectures
if [ -n "$SCRIPT_USER_ARCHITECTURES" ]; then
	architectures=$SCRIPT_USER_ARCHITECTURES
	user_architectures=$TRUE
else
	architectures=(${SCRIPT_ARCHITECTURES[@]}) 
fi


# User did not select scenarios
user_scenarios=$FALSE

# If user scenarios are not set, use all scenarios
if [ -n "$SCRIPT_USER_SCENARIOS" ]; then
	scenarios=$SCRIPT_USER_SCENARIOS
	user_scenarios=$TRUE
else
	scenarios=(${SCRIPT_SCENARIOS[@]}) 
fi


if [ $SCRIPT_INCREMENTAL_STRATEGY -eq $SCRIPT_INCREMENTAL_STRATEGY_ENABLED ] ; then
	# Identify changed ciphers
	declare -a changed_ciphers

	for directory in ${ciphers_directories[@]}
	do
		cd $directory/source/

		source_files=$(ls * | grep -v README)
		for source_file in $source_files
		do
			source_file_timestamp=$(date +%s -r $source_file)
			if [ $source_file_timestamp -ge $old_timestamp ]; then
				# Add in the changed ciphers list
				changed_ciphers+=($directory)
				break;
			fi
		done

		cd ./../../
	done


	# Add user ciphers
	for cipher in $SCRIPT_USER_CIPHERS
	do
		cipher_found=$FALSE
		for cipher_directory in $ciphers_directories
		do
			if [ $cipher == $cipher_directory ] ; then
				cipher_found=$TRUE
				break
			fi
		done

		if [ $FALSE == $cipher_found ] ; then
			echo "Unknown cipher '$cipher'!"
			exit
		else
			cipher_found=$FALSE
			for changed_cipher in ${changed_ciphers[@]}
			do
				if [ $cipher == $changed_cipher ] ; then
					cipher_found=$TRUE
					break
				fi
			done
			if [ $FALSE == $cipher_found ] ; then
				changed_ciphers+=($cipher)
			fi
		fi
	done


	if [ 0 -eq ${#changed_ciphers[@]} ] ; then
		echo "No cipher implementation changed!"
		exit
	fi
else
	# User did not select ciphers
	user_ciphers=$FALSE

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
		user_ciphers=$TRUE
	else
		directories=$ciphers_directories
	fi
fi


# User did not select compiler options
user_compiler_options=$FALSE

# If user compiler options are not set, use all compiler options
if [ -n "$SCRIPT_USER_COMPILER_OPTIONS" ]; then
	compiler_options="${SCRIPT_USER_COMPILER_OPTIONS[@]}"
	user_compiler_options=$TRUE
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


#Change current working directory
cd $current_directory
echo "Changed working directory: $(pwd)"
echo ""


# Set file prefix
if [ $SCRIPT_INCREMENTAL_STRATEGY -eq $SCRIPT_INCREMENTAL_STRATEGY_ENABLED ] ; then
	file_prefix=$DEFAULT_FILE_PREFIX$FILE_NAME_SEPARATOR
else
	if [ -n "$SCRIPT_USER_PREFIX" ] ; then
		file_prefix=$SCRIPT_USER_PREFIX$FILE_NAME_SEPARATOR	
		file_prefix=$(echo $file_prefix | tr -d ' ')
	else	
		file_prefix=$(date -u +"%Y_%m_%d")$FILE_NAME_SEPARATOR
	fi
fi


# Prepare script parameters
if [ $TRUE -eq $user_architectures ] ; then
	script_architectures_parameter="-a=${architectures[@]}"
else
	script_architectures_parameter=""
fi

if [ $TRUE -eq $user_scenarios ] ; then
	script_scenarios_parameter="-s=${scenarios[@]}"
else
	script_scenarios_parameter=""
fi

if [ $SCRIPT_INCREMENTAL_STRATEGY -eq $SCRIPT_INCREMENTAL_STRATEGY_ENABLED ] ; then
		script_ciphers_parameter="-c=${changed_ciphers[@]}"
else
	if [ $TRUE -eq $user_ciphers ] ; then
		script_ciphers_parameter="-c=${directories[@]}"
	else
		script_ciphers_parameter=""
	fi
fi

if [ $TRUE -eq $user_compiler_options ] ; then
	script_compiler_options_parameter="-co=${compiler_options[@]}"
else
	script_compiler_options_parameter=""
fi


# Copy existing results to old results directory (even when not using the incremental strategy)
if [ -d $SCRIPT_RESULTS_DIR_PATH ]; then
	mv $SCRIPT_RESULTS_DIR_PATH $SCRIPT_OLD_RESULTS_DIR_PATH
fi


# Get ciphers info
if [ $SCRIPT_INCREMENTAL_STRATEGY -eq $SCRIPT_INCREMENTAL_STRATEGY_DISABLED ] ; then
	./get_ciphers_info.sh -f=$SCRIPT_FORMAT "$script_ciphers_parameter"
fi

# Collect ciphers metrics
./collect_ciphers_metrics.sh -f=$SCRIPT_FORMAT "$script_architectures_parameter" "$script_scenarios_parameter" "$script_ciphers_parameter" "$script_compiler_options_parameter"


# Create directory structure
create_directory_structure


# Move ciphers info
move_ciphers_info


# Move files to new location
for architecture in ${architectures[@]}
do
	for scenario in ${scenarios[@]}
	do
		case $SCRIPT_FORMAT in
			$SCRIPT_FORMAT_0)
				raw_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_RAW_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$raw_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$raw_file
				if [ -f $source_file ] ; then
					mv $SCRIPT_OUTPUT_PATH/$source_file $destination_file
				fi

				mediawiki_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$mediawiki_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$mediawiki_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi

				xml_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_XML_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$xml_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$xml_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
		
				latex_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_LATEX_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$latex_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$latex_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi

				csv_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_CSV_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$csv_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$csv_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
				;;
			$SCRIPT_FORMAT_1)
				raw_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_RAW_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$raw_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$raw_file
				if [ -f $source_file ] ; then
					mv $SCRIPT_OUTPUT_PATH/$source_file $destination_file
				fi
				;;
			$SCRIPT_FORMAT_2)
				mediawiki_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$mediawiki_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$mediawiki_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
				;;
			$SCRIPT_FORMAT_3)
				xml_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_XML_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$xml_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$xml_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
				;;
			$SCRIPT_FORMAT_4)
				latex_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_LATEX_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$latex_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$latex_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
				;;
			$SCRIPT_FORMAT_5)
				csv_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_CSV_OUTPUT_EXTENSION
				source_file=$SCRIPT_OUTPUT_PATH/$csv_file
				destination_file=$SCRIPT_RESULTS_DIR_PATH$architecture/$file_prefix$csv_file
				if [ -f $source_file ] ; then
					mv $source_file $destination_file
				fi
				;;
		esac
	done
done


if [ $SCRIPT_INCREMENTAL_STRATEGY -eq $SCRIPT_INCREMENTAL_STRATEGY_ENABLED ] ; then
	# Copy incremental results to new results directory
	mv $SCRIPT_RESULTS_DIR_PATH $SCRIPT_NEW_RESULTS_DIR_PATH

	# Create directory structure
	create_directory_structure


	# Change current working directory
	cd $CIPHERS_PATH
	echo "Changed working directory: $(pwd)"
	echo ""


	declare -a implementations
	
	OLD_IFS=$IFS

	# Increment results
	for architecture in ${architectures[@]}
	do
		for scenario in ${scenarios[@]}
		do
				lines_to_ignore=$CSV_RESULTS_HEADER_LENGTH

				path=./../
				csv_file=$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_CSV_OUTPUT_EXTENSION
				old_csv_file=$path$SCRIPT_OLD_RESULTS_DIR_PATH$architecture/$file_prefix$csv_file
				new_csv_file=$path$SCRIPT_NEW_RESULTS_DIR_PATH$architecture/$file_prefix$csv_file

				old_csv_file_content=''
				if [ -f $old_csv_file ] ; then
					old_csv_file_content=$(cat $old_csv_file)
				fi

				new_csv_file_content=''
				if [ -f $new_csv_file ] ; then
					new_csv_file_content=$(cat $new_csv_file)
				fi
				
				declare -a elements=()


				# Add the first file content
				old_line_count=0
				IFS=$'\n'
				for old_line in $old_csv_file_content
				do
					old_line_count=$(($old_line_count + 1))
					if [ $lines_to_ignore -ge $old_line_count ] ; then
						continue
					fi
					
					IFS=',' read -a old_line <<< $old_line
					for ((index=0; index<${#old_line[@]}; index++))
					do
						element=${old_line[$index]}
						element=${element//\"/}
						element=${element//=/}
						old_line[$index]=$element
					done

					old_cipher=${old_line[0]}
					old_block_size=${old_line[1]}
					old_key_size=${old_line[2]}
					old_version=${old_line[3]}
					old_compiler_options=${old_line[5]}

					found=$FALSE
					new_line_count=0
					IFS=$'\n'
					for new_line in $new_csv_file_content
					do
						new_line_count=$(($new_line_count + 1))
						if [ $lines_to_ignore -ge $new_line_count ] ; then
							continue
						fi

						IFS=',' read -a new_line <<< $new_line
						for ((index=0; index<${#new_line[@]}; index++))
						do
							element=${new_line[$index]}
							element=${element//\"/}
							element=${element//=/}
							new_line[$index]=$element
						done

						new_cipher=${new_line[0]}
						new_block_size=${new_line[1]}
						new_key_size=${new_line[2]}
						new_version=${new_line[3]}
						new_compiler_options=${new_line[5]}

						if [ $old_cipher == $new_cipher ] && [ $old_block_size == $new_block_size ] && [ $old_key_size == $new_key_size ] && [ $old_version == $new_version ]  && [ $old_compiler_options == $new_compiler_options ] ; then
							found=$TRUE
							break
						fi
					done

					if [ $FALSE -eq $found ] ; then
						element=${old_line[@]}
						elements+=($element)
						
						implementation=$old_cipher"_"$old_block_size"_"$old_key_size"_v"$old_version
						found=$FALSE
						
						for current_implementation in ${implementations[@]}
						do
							if [ $implementation == $current_implementation ]; then
								found=$TRUE;
								break;
							fi
						done

						if [ $FALSE -eq $found ]; then
							implementations+=($implementation)
						fi
					fi
				done


				# Add the second file content
				new_line_count=0
				IFS=$'\n'
				for new_line in $new_csv_file_content
				do
					new_line_count=$(($new_line_count + 1))
					if [ $lines_to_ignore -ge $new_line_count ] ; then
						continue
					fi

					IFS=',' read -a new_line <<< $new_line
					for ((index=0; index<${#new_line[@]}; index++))
					do
						element=${new_line[$index]}
						element=${element//\"/}
						element=${element//=/}
						new_line[$index]=$element
					done

					new_cipher=${new_line[0]}
					new_block_size=${new_line[1]}
					new_key_size=${new_line[2]}
					new_version=${new_line[3]}

					element=${new_line[@]}
					elements+=($element)
					
					implementation=$new_cipher"_"$new_block_size"_"$new_key_size"_v"$new_version
					found=$FALSE
					
					for current_implementation in ${implementations[@]}
					do
						if [ $implementation == $current_implementation ]; then
							found=$TRUE;
							break;
						fi
					done

					if [ $FALSE -eq $found ]; then
						implementations+=($implementation)
					fi
				done


				# Sort elements
				IFS=$'\n' elements=($(sort <<<"${elements[*]}"))


				path=./../$SCRIPT_RESULTS_DIR_PATH

				script_raw_output=$path$architecture/$file_prefix$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_RAW_OUTPUT_EXTENSION
				script_mediawiki_output=$path$architecture/$file_prefix$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
				script_xml_output=$path$architecture/$file_prefix$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_XML_OUTPUT_EXTENSION
				script_latex_output=$path$architecture/$file_prefix$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_LATEX_OUTPUT_EXTENSION
				script_csv_output=$path$architecture/$file_prefix$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_CSV_OUTPUT_EXTENSION

				# Add file header
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

				# Add file content
				IFS=''
				for element in ${elements[@]}
				do
					IFS=' '
					values=($element)
					IFS=$'\n'

					# Add table row
					case $SCRIPT_FORMAT in
						$SCRIPT_FORMAT_0)
							add_raw_table_row $script_raw_output $scenario ${values[@]}
							add_mediawiki_table_row $script_mediawiki_output $scenario ${values[@]}
							add_xml_table_row $script_xml_output $scenario ${values[@]}
							add_latex_table_row $script_latex_output $scenario ${values[@]}
							add_csv_table_row $script_csv_output $scenario ${values[@]}
							;;
						$SCRIPT_FORMAT_1)
							add_raw_table_row $script_raw_output $scenario ${values[@]}
							;;
						$SCRIPT_FORMAT_2)
							add_mediawiki_table_row $script_mediawiki_output $scenario ${values[@]}
							;;
						$SCRIPT_FORMAT_3)
							add_xml_table_row $script_xml_output $scenario ${values[@]}
							;;
						$SCRIPT_FORMAT_4)
							add_results_latex_table_row $script_latex_output $scenario ${values[@]}
							;;
						$SCRIPT_FORMAT_5)
							add_csv_table_row $script_csv_output $scenario ${values[@]}
							;;
					esac
				done

				# Add file footer
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
	
	IFS=$OLD_IFS


	#Change current working directory
	cd $current_directory
	echo "Changed working directory: $(pwd)"
	echo ""


	# Get ciphers info
	if [ $SCRIPT_INCREMENTAL_STRATEGY -eq $SCRIPT_INCREMENTAL_STRATEGY_ENABLED ] ; then
		implementations=(${implementations[@]})

		OLD_IFS=$IFS
		IFS=$'\n' implementations=($(sort <<<"${implementations[*]}"))
		IFS=$OLD_IFS

		script_ciphers_parameter="-c=${implementations[@]}"

		./get_ciphers_info.sh -f=$SCRIPT_FORMAT "$script_ciphers_parameter"

		# Move ciphers info
		move_ciphers_info
	fi

	# Copy ciphers info
	cp -r $SCRIPT_NEW_RESULTS_DIR_PATH/$RESULTS_INFO_DIR_NAME $SCRIPT_RESULTS_DIR_PATH


	rm -rf $SCRIPT_OLD_RESULTS_DIR_PATH
	rm -rf $SCRIPT_NEW_RESULTS_DIR_PATH
fi


# Create the archive
cd $SCRIPT_OUTPUT_PATH
zip -r $SCRIPT_OUTPUT_PATH/$file_prefix$RESULTS_FILE_NAME$ZIP_FILE_EXTENSION $RESULTS_DIR_NAME
cd $current_directory


# Create MediWiki page
if [ $SCRIPT_FORMAT_0 -eq $SCRIPT_FORMAT ] || [ $SCRIPT_FORMAT_2 -eq $SCRIPT_FORMAT ] ; then
	mediawiki_results_file=$SCRIPT_OUTPUT_PATH$RESULTS_FILE_NAME$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION

	#echo "=Block Ciphers=" > $mediawiki_results_file
	#echo "" >> $mediawiki_results_file
	echo "" > $mediawiki_results_file

	mediawiki_file=$file_prefix$INFO_OUTPUT_FILE_NAME$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
	content=$(cat $SCRIPT_RESULTS_DIR_PATH$RESULTS_INFO_DIR_NAME/$mediawiki_file)

	echo "==Implementation Info==" >> $mediawiki_results_file
	echo "$content" >> $mediawiki_results_file
	echo "" >> $mediawiki_results_file

	for scenario in ${scenarios[@]} 
	do
		echo "==Scenario $scenario==" >> $mediawiki_results_file
		echo "" >> $mediawiki_results_file

		for architecture in ${architectures[@]}
		do
			mediawiki_file=$file_prefix$architecture$SCENARIO_NAME_PART$scenario$SCRIPT_MEDIAWIKI_OUTPUT_EXTENSION
			content=$(cat $SCRIPT_RESULTS_DIR_PATH$architecture/$mediawiki_file)

			echo "===$architecture===" >> $mediawiki_results_file
			echo "$content" >> $mediawiki_results_file
			echo "" >> $mediawiki_results_file
		done
	done

	echo "==Files==" >> $mediawiki_results_file
	echo "* All results: [[ Media:$file_prefix$RESULTS_FILE_NAME$ZIP_FILE_EXTENSION | [ZIP] ]]" >> $mediawiki_results_file

	echo "[[Category:ACRYPT]]" >> $mediawiki_results_file
fi


# Change current working directory
cd $current_directory
echo "End get results - $(pwd)"
