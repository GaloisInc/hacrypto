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


CIPHER_SCRIPT_MODE=1

MAKE_FILE_LOG=collect_ciphers_metrics_make.log

CHECK_CIPHER_OUTPUT_FILE=check_cipher.log
CIPHER_CODE_SIZE_OUTPUT_FILE=cipher_code_size.log
CIPHER_RAM_OUTPUT_FILE=cipher_ram.log
CIPHER_EXECUTION_TIME_OUTPUT_FILE=cipher_execution_time.log

CHECK_CIPHER_ERROR_FILE=check_cipher.err
CIPHER_CODE_SIZE_ERROR_FILE=cipher_code_size.err
CIPHER_RAM_ERROR_FILE=cipher_ram.err
CIPHER_EXECUTION_TIME_ERROR_FILE=cipher_execution_time.err

CHECK_CIPHER_TIMEOUT=300
CIPHER_CODE_SIZE_TIMEOUT=300
CIPHER_RAM_TIMEOUT=300
CIPHER_EXECUTION_TIME_TIMEOUT=300
