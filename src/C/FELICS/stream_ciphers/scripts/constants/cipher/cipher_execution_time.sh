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
# Constants
#


PC_CIPHER_FILE=./cipher.elf
PC_SCENARIO1_FILE=./scenario1.elf

PC_OUTPUT_FILE=pc_execution_time.log

AVR_EXECUTION_TIME_LOG_FILE=avr_execution_time.log

MSP_CIPHER_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_cipher_execution_time.cmd
MSP_CIPHER_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_cipher_execution_time_sections.cmd

MSP_SCENARIO1_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario1_execution_time.cmd
MSP_SCENARIO1_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario1_execution_time_sections.cmd

MSPDEBUG_EXECUTION_TIME_LOG_FILE=mspdebug_execution_time.log
MSPDEBUG_EXECUTION_TIME_SECTIONS_LOG_FILE=mspdebug_execution_time_sections.log

UPLOAD_CIPHER=upload-cipher
UPLOAD_SCENARIO1=upload-scenario1

MAKE_LOG_FILE=cipher_execution_time_make.log

ARM_SERIAL_TERMINAL=./../../../../../common/arm/arm_serial_terminal.py

ARM_SERIAL_TERMINAL_OUTPUT_FILE=serial.out

TABLE_HORIZONTAL_LINE_LENGTH=40

CIPHER_MAKEFILE=./../../../common/cipher.mk
