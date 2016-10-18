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
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


__author__ = 'daniel.dinu'


# Architectures
ARCHITECTURE_AVR = 'AVR'
ARCHITECTURE_MSP = 'MSP'
ARCHITECTURE_ARM = 'ARM'


# FOM 1 weights
# AVR
FOM1_AVR_CODE_SIZE_WEIGHT = 1
FOM1_AVR_RAM_WEIGHT = 1
FOM1_AVR_EXECUTION_TIME_WEIGHT = 1

# MSP
FOM1_MSP_CODE_SIZE_WEIGHT = 1
FOM1_MSP_RAM_WEIGHT = 1
FOM1_MSP_EXECUTION_TIME_WEIGHT = 1

# ARM
FOM1_ARM_CODE_SIZE_WEIGHT = 1
FOM1_ARM_RAM_WEIGHT = 1
FOM1_ARM_EXECUTION_TIME_WEIGHT = 1


# FOM 2 weights
# AVR
FOM2_AVR_CODE_SIZE_WEIGHT = 1
FOM2_AVR_RAM_WEIGHT = 1
FOM2_AVR_EXECUTION_TIME_WEIGHT = 0

# MSP
FOM2_MSP_CODE_SIZE_WEIGHT = 1
FOM2_MSP_RAM_WEIGHT = 1
FOM2_MSP_EXECUTION_TIME_WEIGHT = 0

# ARM
FOM2_ARM_CODE_SIZE_WEIGHT = 1
FOM2_ARM_RAM_WEIGHT = 1
FOM2_ARM_EXECUTION_TIME_WEIGHT = 0


# FOM 3 weights
# AVR
FOM3_AVR_CODE_SIZE_WEIGHT = 0
FOM3_AVR_RAM_WEIGHT = 0
FOM3_AVR_EXECUTION_TIME_WEIGHT = 1

# MSP
FOM3_MSP_CODE_SIZE_WEIGHT = 0
FOM3_MSP_RAM_WEIGHT = 0
FOM3_MSP_EXECUTION_TIME_WEIGHT = 1

# ARM
FOM3_ARM_CODE_SIZE_WEIGHT = 0
FOM3_ARM_RAM_WEIGHT = 0
FOM3_ARM_EXECUTION_TIME_WEIGHT = 1


# Max RAM & ROM
AVR_MAX_RAM = 4 * 1024
AVR_MAX_ROM = 128 * 1024

MSP_MAX_RAM = 10 * 1024
MSP_MAX_ROM = 48 * 1024

ARM_MAX_RAM = 96 * 1024
ARM_MAX_ROM = 512 * 1024


# Recompute FOM
RECOMPUTE_FOM = False


# Input
CSV_FILE_PATH_FORMAT = 'Input/{0}/{1}_{0}_scenario2.csv'
FILE_PREFIX = 'FELICS'

CSV_DELIMITER = ','
CSV_QUOTECHAR = '"'
CSV_LINETERMINATOR = '\n'

CSV_HEADER_LINES = 3

CIPHER_NAME_COLUMN_INDEX = 0

BLOCK_SIZE_COLUMN_INDEX = 1
KEY_SIZE_COLUMN_INDEX = 2

IMPLEMENTATION_VERSION_COLUMN_INDEX = 3
IMPLEMENTATION_TYPE_COLUMN_INDEX = 4
IMPLEMENTATION_COMPILER_OPTIONS_COLUMN_INDEX = 5

CODE_SIZE_E_COLUMN_INDEX = 6

RAM_STACK_E_COLUMN_INDEX = 7
RAM_DATA_COLUMN_INDEX = 8

EXECUTION_TIME_E_COLUMN_INDEX = 9

IDENTITY_CIPHER_NAME = 'IdentityCipher'

IMPLEMENTATION_TYPE_ASM = 'ASM'
IMPLEMENTATION_TYPE_C = 'C'
IMPLEMENTATION_TYPE_C_ASM = 'C+ASM'

DEFAULT_IMPLEMENTATION_TYPE = '?'
DEFAULT_METRIC_VALUE = 10 ** 10


# Output
RESULT_LATEX_FILE_PATH = 'Output/TableScenario2.tex'
RESULT_MEDIAWIKI_FILE_PATH = 'Output/TableScenario2.mkw'
RESULT_GNUPLOT_NAME_DAT_FILE_PATH = 'Output/scenario2_name.dat'
RESULT_GNUPLOT_FOM_DAT_FILE_PATH = 'Output/scenario2_fom.dat'
RESULT_STATISTICS_CSV_FILE_PATH = 'Output/scenario2_statistics.csv'

RESULT_FILE_ACCESS_MODE = 'w'


# Debug levels
DEBUG_OFF = 0
DEBUG_ON = 1

DEBUG = 0


# Debug messages
CIPHER_IMPLEMENTATION_FOM1_DETAILS = 'FOM 1: {} {} {} [{}]   {} {} {} [{}]   {} {} {} [{}]'
CIPHER_IMPLEMENTATION_FOM2_DETAILS = 'FOM 2: {} {} {} [{}]   {} {} {} [{}]   {} {} {} [{}]'
CIPHER_IMPLEMENTATION_FOM3_DETAILS = 'FOM 3: {} {} {} [{}]   {} {} {} [{}]   {} {} {} [{}]'
CIPHER_SCENARIO_FOM1 = 'FOM 1: {}) [{}] [{} {} {}] [{} {} {}] {}'
CIPHER_SCENARIO_FOM2 = 'FOM 2: {}) [{}] [{} {} {}] [{} {} {}] {}'
CIPHER_SCENARIO_FOM3 = 'FOM 3: {}) [{}] [{} {} {}] [{} {} {}] {}'
SCENARIO_FOM_MIN_VALUES = 'FOM MIN values: [{} {} {}] [{} {} {}] [{} {} {}]'
SCENARIO_FOM_MAX_VALUES = 'FOM MAX values: [{} {} {}] [{} {} {}] [{} {} {}]'
SCENARIO_FOM1_MIN_VALUES = 'FOM 1 MIN values: [{} {} {}] [{} {} {}] [{} {} {}]'
SCENARIO_FOM1_MAX_VALUES = 'FOM 1 MAX values: [{} {} {}] [{} {} {}] [{} {} {}]'
SCENARIO_FOM2_MIN_VALUES = 'FOM 2 MIN values: [{} {} {}] [{} {} {}] [{} {} {}]'
SCENARIO_FOM2_MAX_VALUES = 'FOM 2 MAX values: [{} {} {}] [{} {} {}] [{} {} {}]'
SCENARIO_FOM3_MIN_VALUES = 'FOM 3 MIN values: [{} {} {}] [{} {} {}] [{} {} {}]'
SCENARIO_FOM3_MAX_VALUES = 'FOM 3 MAX values: [{} {} {}] [{} {} {}] [{} {} {}]'
DONE = 'Done!'

FOM1_AVR = 'FOM 1 AVR: {} {} {} {}'
FOM1_MSP = 'FOM 1 MSP: {} {} {} {}'
FOM1_ARM = 'FOM 1 ARM: {} {} {} {}'

FOM2_AVR = 'FOM 2 AVR: {} {} {} {}'
FOM2_MSP = 'FOM 2 MSP: {} {} {} {}'
FOM2_ARM = 'FOM 2 ARM: {} {} {} {}'

FOM3_AVR = 'FOM 3 AVR: {} {} {} {}'
FOM3_MSP = 'FOM 3 MSP: {} {} {} {}'
FOM3_ARM = 'FOM 3 ARM: {} {} {} {}'

FOM1_SELECTED_AVR = 'FOM 1 selected AVR: {} {} {}'
FOM1_SELECTED_MSP = 'FOM 1 selected MSP: {} {} {}'
FOM1_SELECTED_ARM = 'FOM 1 selected ARM: {} {} {}'

FOM2_SELECTED_AVR = 'FOM 2 selected AVR: {} {} {}'
FOM2_SELECTED_MSP = 'FOM 2 selected MSP: {} {} {}'
FOM2_SELECTED_ARM = 'FOM 2 selected ARM: {} {} {}'

FOM3_SELECTED_AVR = 'FOM 3 selected AVR: {} {} {}'
FOM3_SELECTED_MSP = 'FOM 3 selected MSP: {} {} {}'
FOM3_SELECTED_ARM = 'FOM 3 selected ARM: {} {} {}'


# LaTeX
LATEX_MIN_VALUE = '\\textbf{{{}}}'
LATEX_MAX_VALUE = '{}'

LATEX_ASM_VALUE = '{}\\tnote{{\\textasteriskcentered}}'  # '\\textit{{{}}}'
LATEX_C_VALUE = '{}'

LATEX_SECTION1_ROW_FORMAT = '\\textbf{{{}}} & {} & {} & {} & {} & {} & {} & {} & {} & {} & {} \\\\ ' \
                            '% AVR: v{} ({}); MSP: v{} ({}); ARM: v{} ({}); \n'
LATEX_SECTION2_ROW_FORMAT = '\\textbf{{{}}} & {} & {} & {} & {} & {} & {} & {} & {} & {} \\\\ ' \
                            '% AVR: v{} ({}); MSP: v{} ({}); ARM: v{} ({}); \n'
LATEX_SECTION3_ROW_FORMAT = '\\textbf{{{}}} & {} & {} & {} & {} & {} & {} & {} & {} & {} \\\\ ' \
                            '% AVR: v{} ({}); MSP: v{} ({}); ARM: v{} ({}); \n'

LATEX_ROUND_FOM = 1


# MediaWiki
MEDIAWIKI_MIN_VALUE = '<span style="color: green">\'\'\'{}\'\'\'</span>'
MEDIAWIKI_MAX_VALUE = '{}'  # '<span style="color: red">\'\'\'{}\'\'\'</span>'

MEDIAWIKI_ASM_VALUE = '\'\'{}\'\''
MEDIAWIKI_C_VALUE = '{}'

MEDIAWIKI_CIPHER_NAME_FORMAT = '[[Lightweight_Block_Ciphers#{}|{}]]'

MEDIAWIKI_SECTION1_ROW_FORMAT = '|-\n! {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n' \
                                '| {}\n ' \
                                '<!-- AVR: v{} ({}); MSP: v{} ({}); ARM: v{} ({}); -->\n'
MEDIAWIKI_SECTION2_ROW_FORMAT = '|-\n! {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n ' \
                                '<!-- AVR: v{} ({}); MSP: v{} ({}); ARM: v{} ({}); -->\n'
MEDIAWIKI_SECTION3_ROW_FORMAT = '|-\n! {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n| {}\n ' \
                                '<!-- AVR: v{} ({}); MSP: v{} ({}); ARM: v{} ({}); -->\n'

MEDIAWIKI_ROUND_FOM = 1


# Gnuplot dat
GNUPLOT_DAT_ROW_FORMAT = '{} {} {} {} {} {} {} {} {} {} {} {} {}\n'

GNUPLOT_ROUND_FOM = 1


# Statistics csv
IMPLEMENTATION_FULL_NAME_FORMAT = '{}_{}_{}_v{}'
STATISTICS_CSV_HEADER_ROW = ['Implementation', 'FOM Position', 'FOM Entries', 'Small code size & RAM Entries',
                             'Best execution time Entries']
