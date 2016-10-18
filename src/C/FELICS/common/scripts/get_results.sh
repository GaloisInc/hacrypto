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
# 	./get_results.sh
#


# Constants

COMMON_SCRIPTS_PATH=./../../common/scripts

SOURCE_RELATIVE_PATH=./../source

SCRIPTS_RELATIVE_PATH=./../scripts


# Block cipher constants

# Default all architectures: '' == 'PC AVR MSP ARM'
BLOCK_CIPHERS_ARCHITECTURES='AVR MSP ARM'

# Default all scenarios: '' == '0 1 2'
BLOCK_CIPHERS_SCENARIOS=''

# Default all ciphers: '' == all ciphers
BLOCK_CIPHERS_CIPHERS=''

# Default all formats: '' == '0'
BLOCK_CIPHERS_FORMAT=''

# Default all compiler options: '' == all compiler options
BLOCK_CIPHERS_COMPILER_OPTIONS=''

# Default current date in format 'YYYY-mm-dd': '' == current date in format 'YYYY-mm-dd'
BLOCK_CIPHERS_PREFIX='FELICS'

# Default enabled: '' == '1'
BLOCK_CIPHERS_INCREMENTAL_STRATEGY=''

BLOCK_CIPHERS_GET_RESULTS_LOG_FILE=./../results/get_results.log

BLOCK_CIPHERS_SCRIPTS_PATH=./../../block_ciphers/scripts

BLOCK_CIPHERS_CLEAN_TARGET=cleanall


# Stream ciphers constants

# Default all architectures: '' == 'PC AVR MSP ARM'
STREAM_CIPHERS_ARCHITECTURES='AVR MSP ARM'

# Default all scenarios: '' == '0 1'
STREAM_CIPHERS_SCENARIOS=''

# Default all ciphers: '' == all ciphers
STREAM_CIPHERS_CIPHERS=''

# Default all formats: '' == '0'
STREAM_CIPHERS_FORMAT=''

# Default all compiler options: '' == all compiler options
STREAM_CIPHERS_COMPILER_OPTIONS=''

# Default current date in format 'YYYY-mm-dd': '' == current date in format 'YYYY-mm-dd'
STREAM_CIPHERS_PREFIX='FELICS'

# Default enabled: '' == '1'
STREAM_CIPHERS_INCREMENTAL_STRATEGY=''

STREAM_CIPHERS_GET_RESULTS_LOG_FILE=./../results/get_results.log

STREAM_CIPHERS_SCRIPTS_PATH=./../../stream_ciphers/scripts

STREAM_CIPHERS_CLEAN_TARGET=cleanall



function print_time()
{
	local time=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
	
	echo $time
}


# Get current script path
script_path=$(dirname $0)


# Change current directory to script source path directory
if [ '.' != $script_path ] ; then
	cd $script_path
fi


# Set the current working directory
current_directory=$(pwd)
echo "Begin get results - $current_directory"



# Block ciphers
echo "Get results for block ciphers - begin:  $(print_time)"

cd $BLOCK_CIPHERS_SCRIPTS_PATH


if [ -n "$BLOCK_CIPHERS_ARCHITECTURES" ] ; then
	architectures="-a=$BLOCK_CIPHERS_ARCHITECTURES"
else
	architectures=""
fi

if [ -n "$BLOCK_CIPHERS_SCENARIOS" ] ; then
	scenarios="-s=$BLOCK_CIPHERS_SCENARIOS"
else
	scenarios=""
fi

if [ -n "$BLOCK_CIPHERS_CIPHERS" ] ; then
	ciphers="-c=$BLOCK_CIPHERS_CIPHERS"
else
	ciphers=""
fi

if [ -n "$BLOCK_CIPHERS_COMPILER_OPTIONS" ] ; then
	compiler_options="-co=$BLOCK_CIPHERS_COMPILER_OPTIONS"
else
	compiler_options=""
fi

if [ -n "$BLOCK_CIPHERS_FORMAT" ] ; then
	format="-f=$BLOCK_CIPHERS_FORMAT"
else
	format=""
fi

if [ -n "$BLOCK_CIPHERS_PREFIX" ] ; then
	prefix="-p=$BLOCK_CIPHERS_PREFIX"
else
	prefix=""
fi

if [ -n "$BLOCK_CIPHERS_INCREMENTAL_STRATEGY" ] ; then
	incremental_strategy="-i=$BLOCK_CIPHERS_INCREMENTAL_STRATEGY"
else
	incremental_strategy=""
fi


cd $SOURCE_RELATIVE_PATH

make $BLOCK_CIPHERS_CLEAN_TARGET > $BLOCK_CIPHERS_GET_RESULTS_LOG_FILE

cd $SCRIPTS_RELATIVE_PATH


time ./get_results.sh "$architectures" "$scenarios" "$ciphers" "$compiler_options" "$format" "$prefix" "$incremental_strategy" >> $BLOCK_CIPHERS_GET_RESULTS_LOG_FILE


cd $COMMON_SCRIPTS_PATH

echo "Get results for block ciphers - end:    $(print_time)"



# Stream ciphers
echo "Get results for stream ciphers - begin: $(print_time)"

cd $STREAM_CIPHERS_SCRIPTS_PATH


if [ -n "$STREAM_CIPHERS_ARCHITECTURES" ] ; then
	architectures="-a=$STREAM_CIPHERS_ARCHITECTURES"
else
	architectures=""
fi

if [ -n "$STREAM_CIPHERS_SCENARIOS" ] ; then
	scenarios="-s=$STREAM_CIPHERS_SCENARIOS"
else
	scenarios=""
fi

if [ -n "$STREAM_CIPHERS_CIPHERS" ] ; then
	ciphers="-c=$STREAM_CIPHERS_CIPHERS"
else
	ciphers=""
fi

if [ -n "$STREAM_CIPHERS_COMPILER_OPTIONS" ] ; then
	compiler_options="-co=$STREAM_CIPHERS_COMPILER_OPTIONS"
else
	compiler_options=""
fi

if [ -n "$STREAM_CIPHERS_FORMAT" ] ; then
	format="-f=$STREAM_CIPHERS_FORMAT"
else
	format=""
fi

if [ -n "$STREAM_CIPHERS_PREFIX" ] ; then
	prefix="-p=$STREAM_CIPHERS_PREFIX"
else
	prefix=""
fi

if [ -n "$STREAM_CIPHERS_INCREMENTAL_STRATEGY" ] ; then
	incremental_strategy="-i=$STREAM_CIPHERS_INCREMENTAL_STRATEGY"
else
	incremental_strategy=""
fi


cd $SOURCE_RELATIVE_PATH

make $STREAM_CIPHERS_CLEAN_TARGET > $STREAM_CIPHERS_GET_RESULTS_LOG_FILE

cd $SCRIPTS_RELATIVE_PATH


time ./get_results.sh "$architectures" "$scenarios" "$ciphers" "$compiler_options" "$format" "$prefix" "$incremental_strategy" >> $STREAM_CIPHERS_GET_RESULTS_LOG_FILE


cd $COMMON_SCRIPTS_PATH


echo "Get results for stream ciphers - end:   $(print_time)"



# Change current working directory
cd $current_directory
echo "End get results - $(pwd)"
