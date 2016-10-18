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


# FOM weights
# AVR
FOM_AVR_CODE_SIZE_WEIGHT = 1
FOM_AVR_RAM_WEIGHT = 1
FOM_AVR_EXECUTION_TIME_WEIGHT = 1

# MSP
FOM_MSP_CODE_SIZE_WEIGHT = 1
FOM_MSP_RAM_WEIGHT = 1
FOM_MSP_EXECUTION_TIME_WEIGHT = 1

# ARM
FOM_ARM_CODE_SIZE_WEIGHT = 1
FOM_ARM_RAM_WEIGHT = 1
FOM_ARM_EXECUTION_TIME_WEIGHT = 1


# Recompute FOM
RECOMPUTE_FOM = False


# Input
CSV_FILE_PATH_FORMAT = 'Input/{0}/{1}_{0}_scenario1.csv'
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

CODE_SIZE_EKS_COLUMN_INDEX = 6
CODE_SIZE_E_COLUMN_INDEX = 7
CODE_SIZE_DKS_COLUMN_INDEX = 8
CODE_SIZE_D_COLUMN_INDEX = 9
CODE_SIZE_TOTAL_COLUMN_INDEX = 10

RAM_STACK_EKS_COLUMN_INDEX = 11
RAM_STACK_E_COLUMN_INDEX = 12
RAM_STACK_DKS_COLUMN_INDEX = 13
RAM_STACK_D_COLUMN_INDEX = 14

RAM_DATA_EKS_COLUMN_INDEX = 15
RAM_DATA_E_COLUMN_INDEX = 16
RAM_DATA_DKS_COLUMN_INDEX = 17
RAM_DATA_D_COLUMN_INDEX = 18
RAM_DATA_COMMON_COLUMN_INDEX = 19
RAM_DATA_TOTAL_COLUMN_INDEX = 20

EXECUTION_TIME_EKS_COLUMN_INDEX = 21
EXECUTION_TIME_E_COLUMN_INDEX = 22
EXECUTION_TIME_DKS_COLUMN_INDEX = 23
EXECUTION_TIME_D_COLUMN_INDEX = 24

IDENTITY_CIPHER_NAME = 'IdentityCipher'

IMPLEMENTATION_TYPE_ASM = 'ASM'
IMPLEMENTATION_TYPE_C = 'C'
IMPLEMENTATION_TYPE_C_ASM = 'C+ASM'

DEFAULT_IMPLEMENTATION_TYPE = '?'
DEFAULT_METRIC_VALUE = 10 ** 10


# Output
RESULT_LATEX_FILE_PATH = 'Output/TableScenario1.tex'
RESULT_MEDIAWIKI_FILE_PATH = 'Output/TableScenario1.mkw'
RESULT_GNUPLOT_NAME_DAT_FILE_PATH = 'Output/scenario1_name.dat'
RESULT_GNUPLOT_FOM_DAT_FILE_PATH = 'Output/scenario1_fom.dat'
RESULT_STATISTICS_CSV_FILE_PATH = 'Output/scenario1_statistics.csv'

RESULT_FILE_ACCESS_MODE = 'w'


# Debug levels
DEBUG_OFF = 0
DEBUG_ON = 1

DEBUG = 0


# Debug messages
CIPHER_IMPLEMENTATION_FOM_DETAILS = '{} {} {} [{}]   {} {} {} [{}]   {} {} {} [{}]'
CIPHER_IMPLEMENTATION_FOM_INFO = '[{}] [{}] [{}]'
CIPHER_SCENARIO_FOM = '{}) [{}] [{} {} {}] [{} {} {}] [{} {} {}] {}'
SCENARIO_FOM_MIN_VALUES = 'MIN values: [{} {} {}] [{} {} {}] [{} {} {}]'
SCENARIO_FOM_MAX_VALUES = 'MAX values: [{} {} {}] [{} {} {}] [{} {} {}]'
DONE = 'Done!'

FOM_AVR = 'FOM AVR: {} {} {} {}'
FOM_MSP = 'FOM MSP: {} {} {} {}'
FOM_ARM = 'FOM ARM: {} {} {} {}'

FOM_SELECTED_AVR = 'FOM selected AVR: {} {} {}'
FOM_SELECTED_MSP = 'FOM selected MSP: {} {} {}'
FOM_SELECTED_ARM = 'FOM selected ARM: {} {} {}'


# LaTeX
LATEX_MIN_VALUE = '\\textbf{{{}}}'
LATEX_MAX_VALUE = '{}'

LATEX_ASM_VALUE = '{}\\tnote{{\\textasteriskcentered}}'  # '\\textit{{{}}}'
LATEX_C_VALUE = '{}'


LATEX_SECTION1_ROW_FORMAT = '\\textbf{{{}}} & {} & {} & {} & {} & {} & {} & {} & {} & {} & {} \\\\ ' \
                            '% AVR: v{} ({}); MSP: v{} ({}); ARM: v{} ({}); \n'
LATEX_SECTION2_ROW_FORMAT = '\\textbf{{{}}} & {} & {} & {} & {} & {} & {} & {} & {} & {} & \\\\ ' \
                            '% AVR: v{} ({}); MSP: v{} ({}); ARM: v{} ({}); \n'
LATEX_SECTION3_ROW_FORMAT = '\\textbf{{{}}} & {} & {} & {} & {} & {} & {} & {} & {} & {} & \\\\ ' \
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
STATISTICS_CSV_HEADER_ROW = ['Implementation', 'FOM Position', 'FOM Entries']