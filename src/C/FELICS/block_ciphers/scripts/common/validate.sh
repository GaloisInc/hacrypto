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


# Constants
TRUE=1
FALSE=0

INVALID_ARCHITECTURE_ERROR_MESSAGE='Invalid architecture:'
INVALID_SCENARIO_ERROR_MESSAGE='Invalid scenario:'
INVALID_MODE_ERROR_MESSAGE='Invalid mode:'
INVALID_FORMAT_ERROR_MESSAGE='Invalid format:'
INVALID_VERBOSITY_ERROR_MESSAGE='Invalid verbosity:'


# Check if the given value is in the given array
# Parameters:
# 	$1 - the searched value
#	$2 - the array to search into
function value_in_array()
{
	local searched_value=$1
	local array=( ${@:2} )

	local value_found=$FALSE
	for value in ${array[@]}
	do
		if [ $searched_value == $value ] ; then
			value_found=$TRUE
			break
		fi
	done

	echo $value_found
}


# Validate given architecture
# Parameters:
# 	$1 - the architecture to validate
function validate_architecture()
{
	local architecture=$1
	local result=$(value_in_array $architecture ${SCRIPT_ARCHITECTURES[@]})	

	if [ $FALSE -eq $result ] ; then
		echo "$INVALID_ARCHITECTURE_ERROR_MESSAGE '$architecture'!"
		exit
	fi
}

# Validate given scenario
# Parameters:
# 	$1 - the scenario to validate
function validate_scenario()
{
	local scenario=$1
	local result=$(value_in_array $scenario ${SCRIPT_SCENARIOS[@]})

	if [ $FALSE -eq $result ] ; then
		echo "$INVALID_SCENARIO_ERROR_MESSAGE '$scenario'!"
		exit
	fi
}

# Validate given mode
# Parameters:
# 	$1 - the scenario to validate
function validate_mode()
{
	local mode=$1
	local result=$(value_in_array $mode ${SCRIPT_MODES[@]})

	if [ $FALSE -eq $result ] ; then
		echo "$INVALID_MODE_ERROR_MESSAGE '$mode'!"
		exit
	fi
}

# Validate given format
# Parameters:
# 	$1 - the format to validate
function validate_format()
{
	local format=$1
	local result=$(value_in_array $format ${SCRIPT_FORMATS[@]})

	if [ $FALSE -eq $result ] ; then
		echo "$INVALID_FORMAT_ERROR_MESSAGE '$format'!"
		exit
	fi
}

# Validate given verbosity
# Parameters:
# 	$1 - the verbosity to validate
function validate_verbosity()
{
	local verbosity=$1
	local result=$(value_in_array $verbosity ${SCRIPT_VERBOSITIES[@]})

	if [ $FALSE -eq $result ] ; then
		echo "$INVALID_VERBOSITY_ERROR_MESSAGE '$verbosity'!"
		exit
	fi
}
