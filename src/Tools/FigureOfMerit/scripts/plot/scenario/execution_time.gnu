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
# Call this script to plot the execution time
#	gnuplot --persist -e "SCENARIO=0" execution_time.gnu
#	gnuplot --persist -e "SCENARIO=1" execution_time.gnu
#


OUTPUT_FILE_NAME = "execution_time"


load "config.gnu"


set ylabel "Execution time (cycles)"


plot \
	NAME_INPUT_FILE using AVR_EXECUTION_TIME:xtic(CIPHER_NAME) ls AVR_LS title AVR_TITLE, \
	NAME_INPUT_FILE using MSP_EXECUTION_TIME:xtic(CIPHER_NAME) ls MSP_LS title MSP_TITLE, \
	NAME_INPUT_FILE using ARM_EXECUTION_TIME:xtic(CIPHER_NAME) ls ARM_LS title ARM_TITLE
