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
CHECK_STATUS_SUCCESS_EXIT_CODE=0
CHECK_STATUS_ERROR_MESSAGE="Error! For error details please read the log file:"


# Check for return status errors
# Parameters:
# 	$1 - the make file return status
# 	$2 - the make file log path and name
function check_status()
{
	local status=$1
	local log_file=$2

	if [ $CHECK_STATUS_SUCCESS_EXIT_CODE -ne $status ]; then
		echo "$CHECK_STATUS_ERROR_MESSAGE '$log_file'"
		exit
	fi
}
