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


CONSTANTS_SOURCE_FILE=./../source/constants.h
SCENARIO1_CONSTANTS_SOURCE_FILE=./../../../common/scenario1/scenario1.h
SCENARIO2_CONSTANTS_SOURCE_FILE=./../../../common/scenario2/scenario2.h

BLOCK_SIZE_DEFINE='#define BLOCK_SIZE'
KEY_SIZE_DEFINE='#define KEY_SIZE'
ROUND_KEYS_SIZE_DEFINE='#define ROUND_KEYS_SIZE'
RAW_DATA_SIZE_DEFINE='#define RAW_DATA_SIZE'

MEMORY_PATTERN=(0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0xAA)

MEMORY_FILE=memory.mem
MEMORY_SIZE=2000

PC_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_cipher_stack.gdb
PC_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_cipher_stack_sections.gdb

PC_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1_stack.gdb
PC_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1_stack_sections.gdb

PC_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario2_stack.gdb
PC_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario2_stack_sections.gdb

AVR_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_cipher_stack.gdb
AVR_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_cipher_stack_sections.gdb

AVR_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1_stack.gdb
AVR_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1_stack_sections.gdb

AVR_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario2_stack.gdb
AVR_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario2_stack_sections.gdb

MSP_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_cipher_stack.gdb
MSP_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_cipher_stack_sections.gdb

MSP_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1_stack.gdb
MSP_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1_stack_sections.gdb

MSP_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario2_stack.gdb
MSP_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario2_stack_sections.gdb

ARM_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_cipher_stack.gdb
ARM_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_cipher_stack_sections.gdb

ARM_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1_stack.gdb
ARM_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1_stack_sections.gdb

ARM_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario2_stack.gdb
ARM_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario2_stack_sections.gdb


GDB_STACK_LOG_FILE=gdb_stack.log
GDB_STACK_SECTIONS_LOG_FILE=gdb_stack_sections.log

SIMAVR_STACK_LOG_FILE=simavr_stack.log
SIMAVR_STACK_SECTIONS_LOG_FILE=simavr_stack_sections.log

MSPDEBUG_STACK_LOG_FILE=mspdebug_stack.log
MSPDEBUG_STACK_SECTIONS_LOG_FILE=mspdebug_stack_sections.log

JLINK_GDB_SERVER_STACK_LOG_FILE=jlink_gdb_server_stack.log
JLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE=jlink_gdb_server_stack_sections.log

UPLOAD_CIPHER=upload-cipher
UPLOAD_SCENARIO1=upload-scenario1
UPLOAD_SCENARIO2=upload-scenario2

MAKE_LOG_FILE=cipher_ram_make.log

TABLE_HORIZONTAL_LINE_LENGTH=118
