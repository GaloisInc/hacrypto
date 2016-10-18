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


FRAMEWORK_NAME='FELICS'
FRAMEWORK_FULL_NAME="FELICS - Fair Evaluation of Lightweight Cryptographic Systems"
FRAMEWORK_VERSION_FILE_PATH=/../VERSION

FRAMEWORK_MODULE_NAME='Stream Ciphers'
FRAMEWORK_MODULE_DIRECTORY='stream_ciphers'

COPYRIGHT="Copyright (C) 2015 University of Luxembourg"

COPYRIGHT_NOTE="This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it 
under certain conditions.
You should have received a copy of the GNU General Public License
along with this program; if not, see <http://www.gnu.org/licenses/>."

HORIZONTAL_LINE_LENGTH=71


# Display version information
function display_version()
{
	line1=$FRAMEWORK_FULL_NAME
	line1_length=${#line1}
	position1=$(($HORIZONTAL_LINE_LENGTH / 2 + $line1_length / 2))
	

	script_path=$(pwd)/$(dirname $0)

	directory=$(basename $script_path)
	while [ $FRAMEWORK_MODULE_DIRECTORY != $directory ] && [ "/" != $directory ]
	do
		script_path=$(dirname $script_path)
		directory=$(basename $script_path)
	done
	
	version_file=$script_path$FRAMEWORK_VERSION_FILE_PATH
	if [ -f $version_file ] ; then
		framework_version=$(cat $version_file)
	else
		framework_version="unknown"
	fi

	
	line2="version $framework_version"
	line2_length=${#line2}
	position2=$(($HORIZONTAL_LINE_LENGTH / 2 + $line2_length / 2))


	line3="$FRAMEWORK_MODULE_NAME module"
	line3_length=${#line3}
	position3=$(($HORIZONTAL_LINE_LENGTH / 2 + $line3_length / 2))

	
	line4="$COPYRIGHT"
	line4_length=${#line4}
	position4=$(($HORIZONTAL_LINE_LENGTH / 2 + $line4_length / 2))

	
	printf "%0.s=" $(seq 1 $HORIZONTAL_LINE_LENGTH)
	printf "\n"

	printf " %"$position1"s " "$line1"
	printf "\n"

	printf " %"$position2"s " "$line2"
	printf "\n"
	
	printf "\n"

	printf " %"$position3"s " "$line3"
	printf "\n"

	printf "\n"

	printf " %"$position4"s " "$line4"
	printf "\n"
	printf "\n"

	printf "$COPYRIGHT_NOTE"
	printf "\n"

	printf "%0.s=" $(seq 1 $HORIZONTAL_LINE_LENGTH)
	printf "\n"

	
	exit
}
