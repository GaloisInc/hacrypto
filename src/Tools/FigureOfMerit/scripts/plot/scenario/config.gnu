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
# Constants
#

INPUT_FILE_PATH = "./../../../FigureOfMerit/BlockCiphers/Output/"
OUTPUT_FILE_PATH = "./../output/"

NAME_INPUT_FILE = INPUT_FILE_PATH."scenario".SCENARIO."_name.dat"
FOM_INPUT_FILE = INPUT_FILE_PATH."scenario".SCENARIO."_fom.dat"

OUTPUT_FILE_EXTENSION = "pdf"

OUTPUT_FILE = OUTPUT_FILE_PATH."scenario".SCENARIO."_".OUTPUT_FILE_NAME.".".OUTPUT_FILE_EXTENSION

AVR_LS = 1
MSP_LS = 2
ARM_LS = 3
FOM_LS = 1

AVR_TITLE = "AVR"
MSP_TITLE = "MSP"
ARM_TITLE = "ARM"
FOM_TITLE = ""

CIPHER_NAME = 1
CIPHER_BLOCK_SIZE = 2
CIPHER_KEY_SIZE = 3

AVR_CODE_SIZE = 4
AVR_RAM = 5
AVR_EXECUTION_TIME = 6

MSP_CODE_SIZE = 7
MSP_RAM = 8
MSP_EXECUTION_TIME = 9

ARM_CODE_SIZE = 10
ARM_RAM = 11
ARM_EXECUTION_TIME = 12

FOM = 13


#
# Script
#

set terminal pdf

set output OUTPUT_FILE


set xtic rotate by -45 scale 0

set format y "%10.0f"

set style data histograms
set style histogram cluster gap 1
set style fill solid border -1
set boxwidth 1
