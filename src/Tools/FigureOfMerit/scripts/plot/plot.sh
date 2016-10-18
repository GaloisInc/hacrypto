#!/bin/bash

#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FigureOfMerit (FOM)
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
#
# This file is part of FigureOfMerit.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

#
# Call this script to plot the results
#	./plot.sh
#


SCENARIOS=(1 2)
SCENARIO_DIR=scenario

GNUPLOT_CONFIG_FILE=config.gnu

ERROR_FILE_PATH=./../output/
ERROR_FILE_NAME=scenario
ERROR_FILE_EXTENSION=err

EXTENSION_SEPARATOR=.
NAME_SEPARATOR=_


# Save the current directory
current_dir=$(pwd)


if [ "." != $(dirname $0) ]
then
	# Change the current directory to the script directory
	cd $(dirname $0)
fi


base_dir=$(pwd)
cd $SCENARIO_DIR

for scenario in ${SCENARIOS[@]}
do
	echo "-> Scenario: $scenario"

	for plot in $(find . -name "*.gnu" -type f -printf "%f\n")
	do
		if [ -f $plot ] && [ $GNUPLOT_CONFIG_FILE != $plot ] ; then
			echo -ne "\t -> Plot: $plot - "

			# Error file
			error_file=$ERROR_FILE_PATH$ERROR_FILE_NAME$scenario$NAME_SEPARATOR$plot$EXTENSION_SEPARATOR$ERROR_FILE_EXTENSION
			rm -f $error_file

			# Plot 
			gnuplot --persist -e "SCENARIO="$scenario $plot 2> $error_file

			# Check for errors
			if [ -f $error_file ] ; then
				error=$(cat $error_file)
			fi

			if [ "" != "$error" ] ; then
				echo "$(tput setab 1)ERROR!$(tput sgr 0)"
			else
				echo "$(tput setab 2)OK!$(tput sgr 0)"
				rm -f $error_file
			fi
		fi
	done
done

cd $base_dir


# Change the current directory to old current directory 
cd $current_dir
