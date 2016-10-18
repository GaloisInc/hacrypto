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


import csv

from Scenario2.CipherImplementationMetrics import CipherImplementationMetrics
from Scenario2.CipherImplementation import CipherImplementation
from Scenario2.SelectedCipher import SelectedCipher
from Scenario2.Statistics import Statistics
from Scenario2 import Constants

from CiphersInfo.CiphersInfo import CiphersInfo


__author__ = 'daniel.dinu'


class Scenario2:
    def __init__(self):
        """
        Initialize scenario 2

        """

        self.ciphers_implementations = []
        self.selected_ciphers = []

        self.ciphers_info = CiphersInfo()

        self.read_csv_file(Constants.ARCHITECTURE_AVR)
        self.read_csv_file(Constants.ARCHITECTURE_MSP)
        self.read_csv_file(Constants.ARCHITECTURE_ARM)

    def get_cipher_implementation(self, name, block_size, key_size, implementation_version,
                                  implementation_compiler_options):
        """
        Get cipher implementation by given characteristics
        :param name: Cipher name
        :param name: Cipher block size
        :param name: Cipher key size
        :param implementation_version: Cipher implementation version
        :param implementation_compiler_options: Cipher implementation compiler options
        :return: Searched cipher implementation if found, else false
        """

        for cipher_implementation in self.ciphers_implementations:
            if cipher_implementation.name == name and cipher_implementation.block_size == block_size and \
                            cipher_implementation.key_size == key_size and \
                            cipher_implementation.version == implementation_version and \
                            cipher_implementation.compiler_options == implementation_compiler_options:
                return cipher_implementation
        return False

    def get_selected_cipher(self, name, block_size, key_size):
        """
        Get selected cipher by given characteristics
        :param name: Cipher name
        :param name: Cipher block size
        :param name: Cipher key size
        :return: Searched cipher if found, else false
        """

        for selected_cipher in self.selected_ciphers:
            if selected_cipher.name == name and selected_cipher.block_size == block_size and \
                            selected_cipher.key_size == key_size:
                return selected_cipher
        return False

    def read_csv_file(self, architecture):
        """
        Read the given architecture CSV file
        :param architecture: Architecture
        """

        file = Constants.CSV_FILE_PATH_FORMAT.format(architecture, Constants.FILE_PREFIX)

        with open(file) as csv_file:
            reader = csv.reader(csv_file, delimiter=Constants.CSV_DELIMITER, quotechar=Constants.CSV_QUOTECHAR)

            count = 0
            for row in reader:
                count += 1

                if Constants.CSV_HEADER_LINES >= count:
                    continue

                name = row[Constants.CIPHER_NAME_COLUMN_INDEX]

                if Constants.IDENTITY_CIPHER_NAME == name:
                    continue

                block_size = int(row[Constants.BLOCK_SIZE_COLUMN_INDEX])
                key_size = int(row[Constants.KEY_SIZE_COLUMN_INDEX])

                implementation_version = row[Constants.IMPLEMENTATION_VERSION_COLUMN_INDEX]
                implementation_type = row[Constants.IMPLEMENTATION_TYPE_COLUMN_INDEX]
                implementation_compiler_options = row[Constants.IMPLEMENTATION_COMPILER_OPTIONS_COLUMN_INDEX][2:-1]

                code_size_e = int(row[Constants.CODE_SIZE_E_COLUMN_INDEX])

                ram_stack_e = int(row[Constants.RAM_STACK_E_COLUMN_INDEX])
                ram_data = int(row[Constants.RAM_DATA_COLUMN_INDEX])

                execution_time_e = int(row[Constants.EXECUTION_TIME_E_COLUMN_INDEX])

                cipher_implementation_metrics = CipherImplementationMetrics(implementation_type,

                                                                            code_size_e,
                                                                            ram_stack_e,
                                                                            ram_data,
                                                                            execution_time_e)

                cipher_implementation = self.get_cipher_implementation(name, block_size, key_size,
                                                                       implementation_version,
                                                                       implementation_compiler_options)
                if not cipher_implementation:
                    cipher_implementation = CipherImplementation(name, block_size, key_size, implementation_version,
                                                                 implementation_compiler_options)
                    self.ciphers_implementations.append(cipher_implementation)
                cipher_implementation.add_metrics(architecture, cipher_implementation_metrics)

                selected_cipher = self.get_selected_cipher(name, block_size, key_size)
                if not selected_cipher:
                    [link, security_level] = self.ciphers_info.get_info(name, block_size, key_size)
                    selected_cipher = SelectedCipher(name, block_size, key_size, link, security_level)
                    self.selected_ciphers.append(selected_cipher)

    def fom(self):
        """
        Compute scenario 2 FOM 1, FOM 2 and FOM 3

        """

        # Code size
        avr_min_code_size = 1e10
        avr_max_code_size = 0

        msp_min_code_size = 1e10
        msp_max_code_size = 0

        arm_min_code_size = 1e10
        arm_max_code_size = 0

        # RAM
        avr_min_ram = 1e10
        avr_max_ram = 0

        msp_min_ram = 1e10
        msp_max_ram = 0

        arm_min_ram = 1e10
        arm_max_ram = 0

        # Execution time
        avr_min_execution_time = 1e10
        avr_max_execution_time = 0

        msp_min_execution_time = 1e10
        msp_max_execution_time = 0

        arm_min_execution_time = 1e10
        arm_max_execution_time = 0

        for cipher_implementation in self.ciphers_implementations:
            # Code size
            value = cipher_implementation.avr_metrics.code_size_e
            if avr_min_code_size > value:
                avr_min_code_size = value
            if avr_max_code_size < value:
                avr_max_code_size = value

            value = cipher_implementation.msp_metrics.code_size_e
            if msp_min_code_size > value:
                msp_min_code_size = value
            if msp_max_code_size < value:
                msp_max_code_size = value

            value = cipher_implementation.arm_metrics.code_size_e
            if arm_min_code_size > value:
                arm_min_code_size = value
            if arm_max_code_size < value:
                arm_max_code_size = value

            # RAM
            value = cipher_implementation.avr_metrics.ram_data + \
                    cipher_implementation.avr_metrics.ram_stack_e
            if avr_min_ram > value:
                avr_min_ram = value
            if avr_max_ram < value:
                avr_max_ram = value

            value = cipher_implementation.msp_metrics.ram_data + \
                    cipher_implementation.msp_metrics.ram_stack_e
            if msp_min_ram > value:
                msp_min_ram = value
            if msp_max_ram < value:
                msp_max_ram = value

            value = cipher_implementation.arm_metrics.ram_data + \
                    cipher_implementation.arm_metrics.ram_stack_e
            if arm_min_ram > value:
                arm_min_ram = value
            if arm_max_ram < value:
                arm_max_ram = value

            # Execution time
            value = cipher_implementation.avr_metrics.execution_time_e
            if avr_min_execution_time > value:
                avr_min_execution_time = value
            if avr_max_execution_time < value:
                avr_max_execution_time = value

            value = cipher_implementation.msp_metrics.execution_time_e
            if msp_min_execution_time > value:
                msp_min_execution_time = value
            if msp_max_execution_time < value:
                msp_max_execution_time = value

            value = cipher_implementation.arm_metrics.execution_time_e
            if arm_min_execution_time > value:
                arm_min_execution_time = value
            if arm_max_execution_time < value:
                arm_max_execution_time = value

        if Constants.DEBUG_ON == Constants.DEBUG:
            print(Constants.SCENARIO_FOM_MIN_VALUES.format(avr_min_code_size, avr_min_ram, avr_min_execution_time,
                                                           msp_min_code_size, msp_min_ram, msp_min_execution_time,
                                                           arm_min_code_size, arm_min_ram, arm_min_execution_time))
            print(Constants.SCENARIO_FOM_MAX_VALUES.format(avr_max_code_size, avr_max_ram, avr_max_execution_time,
                                                           msp_max_code_size, msp_max_ram, msp_max_execution_time,
                                                           arm_max_code_size, arm_max_ram, arm_max_execution_time))

        for cipher_implementation in self.ciphers_implementations:
            cipher_implementation.compute_fom(avr_min_code_size,
                                              msp_min_code_size,
                                              arm_min_code_size,

                                              avr_min_ram,
                                              msp_min_ram,
                                              arm_min_ram,

                                              avr_min_execution_time,
                                              msp_min_execution_time,
                                              arm_min_execution_time,

                                              avr_max_code_size,
                                              msp_max_code_size,
                                              arm_max_code_size,

                                              avr_max_ram,
                                              msp_max_ram,
                                              arm_max_ram,

                                              avr_max_execution_time,
                                              msp_max_execution_time,
                                              arm_max_execution_time)

        # FOM 1
        # AVR
        self.ciphers_implementations.sort(key=lambda c: (c.fom1_avr, c.version))

        if Constants.DEBUG_ON == Constants.DEBUG:
            for cipher_implementation in self.ciphers_implementations:
                print(Constants.FOM1_AVR.format(cipher_implementation.name, cipher_implementation.version,
                                                cipher_implementation.compiler_options, cipher_implementation.fom1_avr))

        for selected_cipher in self.selected_ciphers:
            for cipher_implementation in self.ciphers_implementations:
                if selected_cipher.name == cipher_implementation.name and \
                                selected_cipher.block_size == cipher_implementation.block_size and \
                                selected_cipher.key_size == cipher_implementation.key_size:
                    selected_cipher.avr_metrics1 = cipher_implementation.avr_metrics
                    selected_cipher.fom1_avr = cipher_implementation.fom1_avr
                    selected_cipher.avr_version1 = cipher_implementation.version
                    selected_cipher.avr_compiler_options1 = cipher_implementation.compiler_options
                    break

        if Constants.DEBUG_ON == Constants.DEBUG:
            for selected_cipher in self.selected_ciphers:
                print(Constants.FOM1_SELECTED_AVR.format(selected_cipher.name, selected_cipher.avr_version1,
                                                         selected_cipher.avr_compiler_options1))

        # MSP
        self.ciphers_implementations.sort(key=lambda c: (c.fom1_msp, c.version))

        if Constants.DEBUG_ON == Constants.DEBUG:
            for cipher_implementation in self.ciphers_implementations:
                print(Constants.FOM1_MSP.format(cipher_implementation.name, cipher_implementation.version,
                                                cipher_implementation.compiler_options, cipher_implementation.fom1_msp))

        for selected_cipher in self.selected_ciphers:
            for cipher_implementation in self.ciphers_implementations:
                if selected_cipher.name == cipher_implementation.name and \
                                selected_cipher.block_size == cipher_implementation.block_size and \
                                selected_cipher.key_size == cipher_implementation.key_size:
                    selected_cipher.msp_metrics1 = cipher_implementation.msp_metrics
                    selected_cipher.fom1_msp = cipher_implementation.fom1_msp
                    selected_cipher.msp_version1 = cipher_implementation.version
                    selected_cipher.msp_compiler_options1 = cipher_implementation.compiler_options
                    break

        if Constants.DEBUG_ON == Constants.DEBUG:
            for selected_cipher in self.selected_ciphers:
                print(Constants.FOM1_SELECTED_MSP.format(selected_cipher.name, selected_cipher.msp_version1,
                                                         selected_cipher.msp_compiler_options1))

        # ARM
        self.ciphers_implementations.sort(key=lambda c: (c.fom1_arm, c.version))

        if Constants.DEBUG_ON == Constants.DEBUG:
            for cipher_implementation in self.ciphers_implementations:
                print(Constants.FOM1_ARM.format(cipher_implementation.name, cipher_implementation.version,
                                                cipher_implementation.compiler_options, cipher_implementation.fom1_arm))

        for selected_cipher in self.selected_ciphers:
            for cipher_implementation in self.ciphers_implementations:
                if selected_cipher.name == cipher_implementation.name and \
                                selected_cipher.block_size == cipher_implementation.block_size and \
                                selected_cipher.key_size == cipher_implementation.key_size:
                    selected_cipher.arm_metrics1 = cipher_implementation.arm_metrics
                    selected_cipher.fom1_arm = cipher_implementation.fom1_arm
                    selected_cipher.arm_version1 = cipher_implementation.version
                    selected_cipher.arm_compiler_options1 = cipher_implementation.compiler_options
                    break

        if Constants.DEBUG_ON == Constants.DEBUG:
            for selected_cipher in self.selected_ciphers:
                print(Constants.FOM1_SELECTED_ARM.format(selected_cipher.name, selected_cipher.arm_version1,
                                                         selected_cipher.arm_compiler_options1))

        # FOM 2
        # AVR
        self.ciphers_implementations.sort(key=lambda c: (c.fom2_avr, c.version))

        if Constants.DEBUG_ON == Constants.DEBUG:
            for cipher_implementation in self.ciphers_implementations:
                print(Constants.FOM2_AVR.format(cipher_implementation.name, cipher_implementation.version,
                                                cipher_implementation.compiler_options, cipher_implementation.fom2_avr))

        for selected_cipher in self.selected_ciphers:
            for cipher_implementation in self.ciphers_implementations:
                if selected_cipher.name == cipher_implementation.name and \
                                selected_cipher.block_size == cipher_implementation.block_size and \
                                selected_cipher.key_size == cipher_implementation.key_size:
                    selected_cipher.avr_metrics2 = cipher_implementation.avr_metrics
                    selected_cipher.fom2_avr = cipher_implementation.fom2_avr
                    selected_cipher.avr_version2 = cipher_implementation.version
                    selected_cipher.avr_compiler_options2 = cipher_implementation.compiler_options
                    break

        if Constants.DEBUG_ON == Constants.DEBUG:
            for selected_cipher in self.selected_ciphers:
                print(Constants.FOM2_SELECTED_AVR.format(selected_cipher.name, selected_cipher.avr_version2,
                                                         selected_cipher.avr_compiler_options2))

        # MSP
        self.ciphers_implementations.sort(key=lambda c: (c.fom2_msp, c.version))

        if Constants.DEBUG_ON == Constants.DEBUG:
            for cipher_implementation in self.ciphers_implementations:
                print(Constants.FOM2_MSP.format(cipher_implementation.name, cipher_implementation.version,
                                                cipher_implementation.compiler_options, cipher_implementation.fom2_msp))

        for selected_cipher in self.selected_ciphers:
            for cipher_implementation in self.ciphers_implementations:
                if selected_cipher.name == cipher_implementation.name and \
                                selected_cipher.block_size == cipher_implementation.block_size and \
                                selected_cipher.key_size == cipher_implementation.key_size:
                    selected_cipher.msp_metrics2 = cipher_implementation.msp_metrics
                    selected_cipher.fom2_msp = cipher_implementation.fom2_msp
                    selected_cipher.msp_version2 = cipher_implementation.version
                    selected_cipher.msp_compiler_options2 = cipher_implementation.compiler_options
                    break

        if Constants.DEBUG_ON == Constants.DEBUG:
            for selected_cipher in self.selected_ciphers:
                print(Constants.FOM2_SELECTED_MSP.format(selected_cipher.name, selected_cipher.msp_version2,
                                                         selected_cipher.msp_compiler_options2))

        # ARM
        self.ciphers_implementations.sort(key=lambda c: (c.fom2_arm, c.version))

        if Constants.DEBUG_ON == Constants.DEBUG:
            for cipher_implementation in self.ciphers_implementations:
                print(Constants.FOM2_ARM.format(cipher_implementation.name, cipher_implementation.version,
                                                cipher_implementation.compiler_options, cipher_implementation.fom2_arm))

        for selected_cipher in self.selected_ciphers:
            for cipher_implementation in self.ciphers_implementations:
                if selected_cipher.name == cipher_implementation.name and \
                                selected_cipher.block_size == cipher_implementation.block_size and \
                                selected_cipher.key_size == cipher_implementation.key_size:
                    selected_cipher.arm_metrics2 = cipher_implementation.arm_metrics
                    selected_cipher.fom2_arm = cipher_implementation.fom2_arm
                    selected_cipher.arm_version2 = cipher_implementation.version
                    selected_cipher.arm_compiler_options2 = cipher_implementation.compiler_options
                    break

        if Constants.DEBUG_ON == Constants.DEBUG:
            for selected_cipher in self.selected_ciphers:
                print(Constants.FOM2_SELECTED_ARM.format(selected_cipher.name, selected_cipher.arm_version2,
                                                         selected_cipher.arm_compiler_options2))

        # FOM 3
        # AVR
        self.ciphers_implementations.sort(key=lambda c: (c.fom3_avr, c.version))

        if Constants.DEBUG_ON == Constants.DEBUG:
            for cipher_implementation in self.ciphers_implementations:
                print(Constants.FOM3_AVR.format(cipher_implementation.name, cipher_implementation.version,
                                                cipher_implementation.compiler_options, cipher_implementation.fom3_avr))

        for selected_cipher in self.selected_ciphers:
            for cipher_implementation in self.ciphers_implementations:
                if selected_cipher.name == cipher_implementation.name and \
                                selected_cipher.block_size == cipher_implementation.block_size and \
                                selected_cipher.key_size == cipher_implementation.key_size:
                    selected_cipher.avr_metrics3 = cipher_implementation.avr_metrics
                    selected_cipher.fom3_avr = cipher_implementation.fom3_avr
                    selected_cipher.avr_version3 = cipher_implementation.version
                    selected_cipher.avr_compiler_options3 = cipher_implementation.compiler_options
                    break

        if Constants.DEBUG_ON == Constants.DEBUG:
            for selected_cipher in self.selected_ciphers:
                print(Constants.FOM3_SELECTED_AVR.format(selected_cipher.name, selected_cipher.avr_version3,
                                                         selected_cipher.avr_compiler_options3))

        # MSP
        self.ciphers_implementations.sort(key=lambda c: (c.fom3_msp, c.version))

        if Constants.DEBUG_ON == Constants.DEBUG:
            for cipher_implementation in self.ciphers_implementations:
                print(Constants.FOM3_MSP.format(cipher_implementation.name, cipher_implementation.version,
                                                cipher_implementation.compiler_options, cipher_implementation.fom3_msp))

        for selected_cipher in self.selected_ciphers:
            for cipher_implementation in self.ciphers_implementations:
                if selected_cipher.name == cipher_implementation.name and \
                                selected_cipher.block_size == cipher_implementation.block_size and \
                                selected_cipher.key_size == cipher_implementation.key_size:
                    selected_cipher.msp_metrics3 = cipher_implementation.msp_metrics
                    selected_cipher.fom3_msp = cipher_implementation.fom3_msp
                    selected_cipher.msp_version3 = cipher_implementation.version
                    selected_cipher.msp_compiler_options3 = cipher_implementation.compiler_options
                    break

        if Constants.DEBUG_ON == Constants.DEBUG:
            for selected_cipher in self.selected_ciphers:
                print(Constants.FOM3_SELECTED_MSP.format(selected_cipher.name, selected_cipher.msp_version3,
                                                         selected_cipher.msp_compiler_options3))

        # ARM
        self.ciphers_implementations.sort(key=lambda c: (c.fom3_arm, c.version))

        if Constants.DEBUG_ON == Constants.DEBUG:
            for cipher_implementation in self.ciphers_implementations:
                print(Constants.FOM3_ARM.format(cipher_implementation.name, cipher_implementation.version,
                                                cipher_implementation.compiler_options, cipher_implementation.fom3_arm))

        for selected_cipher in self.selected_ciphers:
            for cipher_implementation in self.ciphers_implementations:
                if selected_cipher.name == cipher_implementation.name and \
                                selected_cipher.block_size == cipher_implementation.block_size and \
                                selected_cipher.key_size == cipher_implementation.key_size:
                    selected_cipher.arm_metrics3 = cipher_implementation.arm_metrics
                    selected_cipher.fom3_arm = cipher_implementation.fom3_arm
                    selected_cipher.arm_version3 = cipher_implementation.version
                    selected_cipher.arm_compiler_options3 = cipher_implementation.compiler_options
                    break

        if Constants.DEBUG_ON == Constants.DEBUG:
            for selected_cipher in self.selected_ciphers:
                print(Constants.FOM3_SELECTED_ARM.format(selected_cipher.name, selected_cipher.arm_version3,
                                                         selected_cipher.arm_compiler_options3))

        # Recompute FOM
        if Constants.RECOMPUTE_FOM:
            # FOM 1
            # Code size
            avr_min_code_size = 1e10
            avr_max_code_size = 0

            msp_min_code_size = 1e10
            msp_max_code_size = 0

            arm_min_code_size = 1e10
            arm_max_code_size = 0

            # RAM
            avr_min_ram = 1e10
            avr_max_ram = 0

            msp_min_ram = 1e10
            msp_max_ram = 0

            arm_min_ram = 1e10
            arm_max_ram = 0

            # Execution time
            avr_min_execution_time = 1e10
            avr_max_execution_time = 0

            msp_min_execution_time = 1e10
            msp_max_execution_time = 0

            arm_min_execution_time = 1e10
            arm_max_execution_time = 0

            for selected_cipher in self.selected_ciphers:
                # Code size
                value = selected_cipher.avr_metrics1.code_size_e
                if avr_min_code_size > value:
                    avr_min_code_size = value
                if avr_max_code_size < value:
                    avr_max_code_size = value

                value = selected_cipher.msp_metrics1.code_size_e
                if msp_min_code_size > value:
                    msp_min_code_size = value
                if msp_max_code_size < value:
                    msp_max_code_size = value

                value = selected_cipher.arm_metrics1.code_size_e
                if arm_min_code_size > value:
                    arm_min_code_size = value
                if arm_max_code_size < value:
                    arm_max_code_size = value

                # RAM
                value = selected_cipher.avr_metrics1.ram_data + \
                        selected_cipher.avr_metrics1.ram_stack_e
                if avr_min_ram > value:
                    avr_min_ram = value
                if avr_max_ram < value:
                    avr_max_ram = value

                value = selected_cipher.msp_metrics1.ram_data + \
                        selected_cipher.msp_metrics1.ram_stack_e
                if msp_min_ram > value:
                    msp_min_ram = value
                if msp_max_ram < value:
                    msp_max_ram = value

                value = selected_cipher.arm_metrics1.ram_data + \
                        selected_cipher.arm_metrics1.ram_stack_e
                if arm_min_ram > value:
                    arm_min_ram = value
                if arm_max_ram < value:
                    arm_max_ram = value

                # Execution time
                value = selected_cipher.avr_metrics1.execution_time_e
                if avr_min_execution_time > value:
                    avr_min_execution_time = value
                if avr_max_execution_time < value:
                    avr_max_execution_time = value

                value = selected_cipher.msp_metrics1.execution_time_e
                if msp_min_execution_time > value:
                    msp_min_execution_time = value
                if msp_max_execution_time < value:
                    msp_max_execution_time = value

                value = selected_cipher.arm_metrics1.execution_time_e
                if arm_min_execution_time > value:
                    arm_min_execution_time = value
                if arm_max_execution_time < value:
                    arm_max_execution_time = value

            if Constants.DEBUG_ON == Constants.DEBUG:
                print(Constants.SCENARIO_FOM1_MIN_VALUES.format(avr_min_code_size, avr_min_ram, avr_min_execution_time,
                                                                msp_min_code_size, msp_min_ram, msp_min_execution_time,
                                                                arm_min_code_size, arm_min_ram, arm_min_execution_time))
                print(Constants.SCENARIO_FOM1_MAX_VALUES.format(avr_max_code_size, avr_max_ram, avr_max_execution_time,
                                                                msp_max_code_size, msp_max_ram, msp_max_execution_time,
                                                                arm_max_code_size, arm_max_ram, arm_max_execution_time))

            for selected_cipher in self.selected_ciphers:
                selected_cipher.compute_fom1(avr_min_code_size,
                                             msp_min_code_size,
                                             arm_min_code_size,

                                             avr_min_ram,
                                             msp_min_ram,
                                             arm_min_ram,

                                             avr_min_execution_time,
                                             msp_min_execution_time,
                                             arm_min_execution_time,

                                             avr_max_code_size,
                                             msp_max_code_size,
                                             arm_max_code_size,

                                             avr_max_ram,
                                             msp_max_ram,
                                             arm_max_ram,

                                             avr_max_execution_time,
                                             msp_max_execution_time,
                                             arm_max_execution_time)

            # FOM 2
            # Code size
            avr_min_code_size = 1e10
            avr_max_code_size = 0

            msp_min_code_size = 1e10
            msp_max_code_size = 0

            arm_min_code_size = 1e10
            arm_max_code_size = 0

            # RAM
            avr_min_ram = 1e10
            avr_max_ram = 0

            msp_min_ram = 1e10
            msp_max_ram = 0

            arm_min_ram = 1e10
            arm_max_ram = 0

            # Execution time
            avr_min_execution_time = 1e10
            avr_max_execution_time = 0

            msp_min_execution_time = 1e10
            msp_max_execution_time = 0

            arm_min_execution_time = 1e10
            arm_max_execution_time = 0

            for selected_cipher in self.selected_ciphers:
                # Code size
                value = selected_cipher.avr_metrics2.code_size_e
                if avr_min_code_size > value:
                    avr_min_code_size = value
                if avr_max_code_size < value:
                    avr_max_code_size = value

                value = selected_cipher.msp_metrics2.code_size_e
                if msp_min_code_size > value:
                    msp_min_code_size = value
                if msp_max_code_size < value:
                    msp_max_code_size = value

                value = selected_cipher.arm_metrics2.code_size_e
                if arm_min_code_size > value:
                    arm_min_code_size = value
                if arm_max_code_size < value:
                    arm_max_code_size = value

                # RAM
                value = selected_cipher.avr_metrics2.ram_data + \
                        selected_cipher.avr_metrics2.ram_stack_e
                if avr_min_ram > value:
                    avr_min_ram = value
                if avr_max_ram < value:
                    avr_max_ram = value

                value = selected_cipher.msp_metrics2.ram_data + \
                        selected_cipher.msp_metrics2.ram_stack_e
                if msp_min_ram > value:
                    msp_min_ram = value
                if msp_max_ram < value:
                    msp_max_ram = value

                value = selected_cipher.arm_metrics2.ram_data + \
                        selected_cipher.arm_metrics2.ram_stack_e
                if arm_min_ram > value:
                    arm_min_ram = value
                if arm_max_ram < value:
                    arm_max_ram = value

                # Execution time
                value = selected_cipher.avr_metrics2.execution_time_e
                if avr_min_execution_time > value:
                    avr_min_execution_time = value
                if avr_max_execution_time < value:
                    avr_max_execution_time = value

                value = selected_cipher.msp_metrics2.execution_time_e
                if msp_min_execution_time > value:
                    msp_min_execution_time = value
                if msp_max_execution_time < value:
                    msp_max_execution_time = value

                value = selected_cipher.arm_metrics2.execution_time_e
                if arm_min_execution_time > value:
                    arm_min_execution_time = value
                if arm_max_execution_time < value:
                    arm_max_execution_time = value

            if Constants.DEBUG_ON == Constants.DEBUG:
                print(Constants.SCENARIO_FOM2_MIN_VALUES.format(avr_min_code_size, avr_min_ram, avr_min_execution_time,
                                                                msp_min_code_size, msp_min_ram, msp_min_execution_time,
                                                                arm_min_code_size, arm_min_ram, arm_min_execution_time))
                print(Constants.SCENARIO_FOM2_MAX_VALUES.format(avr_max_code_size, avr_max_ram, avr_max_execution_time,
                                                                msp_max_code_size, msp_max_ram, msp_max_execution_time,
                                                                arm_max_code_size, arm_max_ram, arm_max_execution_time))

            for selected_cipher in self.selected_ciphers:
                selected_cipher.compute_fom2(avr_min_code_size,
                                             msp_min_code_size,
                                             arm_min_code_size,

                                             avr_min_ram,
                                             msp_min_ram,
                                             arm_min_ram,

                                             avr_min_execution_time,
                                             msp_min_execution_time,
                                             arm_min_execution_time,

                                             avr_max_code_size,
                                             msp_max_code_size,
                                             arm_max_code_size,

                                             avr_max_ram,
                                             msp_max_ram,
                                             arm_max_ram,

                                             avr_max_execution_time,
                                             msp_max_execution_time,
                                             arm_max_execution_time)

            # FOM 3
            # Code size
            avr_min_code_size = 1e10
            avr_max_code_size = 0

            msp_min_code_size = 1e10
            msp_max_code_size = 0

            arm_min_code_size = 1e10
            arm_max_code_size = 0

            # RAM
            avr_min_ram = 1e10
            avr_max_ram = 0

            msp_min_ram = 1e10
            msp_max_ram = 0

            arm_min_ram = 1e10
            arm_max_ram = 0

            # Execution time
            avr_min_execution_time = 1e10
            avr_max_execution_time = 0

            msp_min_execution_time = 1e10
            msp_max_execution_time = 0

            arm_min_execution_time = 1e10
            arm_max_execution_time = 0

            for selected_cipher in self.selected_ciphers:
                # Code size
                value = selected_cipher.avr_metrics3.code_size_e
                if avr_min_code_size > value:
                    avr_min_code_size = value
                if avr_max_code_size < value:
                    avr_max_code_size = value

                value = selected_cipher.msp_metrics3.code_size_e
                if msp_min_code_size > value:
                    msp_min_code_size = value
                if msp_max_code_size < value:
                    msp_max_code_size = value

                value = selected_cipher.arm_metrics3.code_size_e
                if arm_min_code_size > value:
                    arm_min_code_size = value
                if arm_max_code_size < value:
                    arm_max_code_size = value

                # RAM
                value = selected_cipher.avr_metrics3.ram_data + \
                        selected_cipher.avr_metrics3.ram_stack_e
                if avr_min_ram > value:
                    avr_min_ram = value
                if avr_max_ram < value:
                    avr_max_ram = value

                value = selected_cipher.msp_metrics3.ram_data + \
                        selected_cipher.msp_metrics3.ram_stack_e
                if msp_min_ram > value:
                    msp_min_ram = value
                if msp_max_ram < value:
                    msp_max_ram = value

                value = selected_cipher.arm_metrics3.ram_data + \
                        selected_cipher.arm_metrics3.ram_stack_e
                if arm_min_ram > value:
                    arm_min_ram = value
                if arm_max_ram < value:
                    arm_max_ram = value

                # Execution time
                value = selected_cipher.avr_metrics3.execution_time_e
                if avr_min_execution_time > value:
                    avr_min_execution_time = value
                if avr_max_execution_time < value:
                    avr_max_execution_time = value

                value = selected_cipher.msp_metrics3.execution_time_e
                if msp_min_execution_time > value:
                    msp_min_execution_time = value
                if msp_max_execution_time < value:
                    msp_max_execution_time = value

                value = selected_cipher.arm_metrics3.execution_time_e
                if arm_min_execution_time > value:
                    arm_min_execution_time = value
                if arm_max_execution_time < value:
                    arm_max_execution_time = value

            if Constants.DEBUG_ON == Constants.DEBUG:
                print(Constants.SCENARIO_FOM3_MIN_VALUES.format(avr_min_code_size, avr_min_ram, avr_min_execution_time,
                                                                msp_min_code_size, msp_min_ram, msp_min_execution_time,
                                                                arm_min_code_size, arm_min_ram, arm_min_execution_time))
                print(Constants.SCENARIO_FOM3_MAX_VALUES.format(avr_max_code_size, avr_max_ram, avr_max_execution_time,
                                                                msp_max_code_size, msp_max_ram, msp_max_execution_time,
                                                                arm_max_code_size, arm_max_ram, arm_max_execution_time))

            for selected_cipher in self.selected_ciphers:
                selected_cipher.compute_fom3(avr_min_code_size,
                                             msp_min_code_size,
                                             arm_min_code_size,

                                             avr_min_ram,
                                             msp_min_ram,
                                             arm_min_ram,

                                             avr_min_execution_time,
                                             msp_min_execution_time,
                                             arm_min_execution_time,

                                             avr_max_code_size,
                                             msp_max_code_size,
                                             arm_max_code_size,

                                             avr_max_ram,
                                             msp_max_ram,
                                             arm_max_ram,

                                             avr_max_execution_time,
                                             msp_max_execution_time,
                                             arm_max_execution_time)

        for selected_cipher in self.selected_ciphers:
            selected_cipher.fom1 = (selected_cipher.fom1_avr + selected_cipher.fom1_msp + selected_cipher.fom1_arm) / 3
            selected_cipher.fom2 = (selected_cipher.fom2_avr + selected_cipher.fom2_msp + selected_cipher.fom2_arm) / 3
            selected_cipher.fom3 = (selected_cipher.fom3_avr + selected_cipher.fom3_msp + selected_cipher.fom3_arm) / 3

        self.selected_ciphers.sort(key=lambda c: c.fom1)

        if Constants.DEBUG_ON == Constants.DEBUG:
            i = 0
            for selected_cipher in self.selected_ciphers:
                i += 1
                print(Constants.CIPHER_SCENARIO_FOM1.format(i, selected_cipher.name,

                                                            selected_cipher.avr_version1,
                                                            selected_cipher.msp_version1,
                                                            selected_cipher.arm_version1,

                                                            selected_cipher.fom1_avr,
                                                            selected_cipher.fom1_msp,
                                                            selected_cipher.fom1_arm,

                                                            selected_cipher.fom1))

        self.selected_ciphers.sort(key=lambda c: c.fom2)

        if Constants.DEBUG_ON == Constants.DEBUG:
            i = 0
            for selected_cipher in self.selected_ciphers:
                i += 1
                print(Constants.CIPHER_SCENARIO_FOM2.format(i, selected_cipher.name,

                                                            selected_cipher.avr_version2,
                                                            selected_cipher.msp_version2,
                                                            selected_cipher.arm_version2,

                                                            selected_cipher.fom2_avr,
                                                            selected_cipher.fom2_msp,
                                                            selected_cipher.fom2_arm,

                                                            selected_cipher.fom2))

        self.selected_ciphers.sort(key=lambda c: c.fom3)

        if Constants.DEBUG_ON == Constants.DEBUG:
            i = 0
            for selected_cipher in self.selected_ciphers:
                i += 1
                print(Constants.CIPHER_SCENARIO_FOM3.format(i, selected_cipher.name,

                                                            selected_cipher.avr_version3,
                                                            selected_cipher.msp_version3,
                                                            selected_cipher.arm_version3,

                                                            selected_cipher.fom3_avr,
                                                            selected_cipher.fom3_msp,
                                                            selected_cipher.fom3_arm,

                                                            selected_cipher.fom3))

    def generate_latex_table_row_data(self,
                                      avr_value1, avr_value2, avr_value3,
                                      msp_value1, msp_value2, msp_value3,
                                      arm_value1, arm_value2, arm_value3,

                                      avr_min_code_size,
                                      avr_max_code_size,
                                      msp_min_code_size,
                                      msp_max_code_size,
                                      arm_min_code_size,
                                      arm_max_code_size,

                                      avr_min_ram,
                                      avr_max_ram,
                                      msp_min_ram,
                                      msp_max_ram,
                                      arm_min_ram,
                                      arm_max_ram,

                                      avr_min_execution_time,
                                      avr_max_execution_time,
                                      msp_min_execution_time,
                                      msp_max_execution_time,
                                      arm_min_execution_time,
                                      arm_max_execution_time,

                                      avr_implementation_type,
                                      msp_implementation_type,
                                      arm_implementation_type):

        """
        Generate LaTeX table row data
        :param avr_value1: AVR metric 1 (code size) value
        :param avr_value2: AVR metric 2 (RAM) value
        :param avr_value3: AVR metric 3 (execution time) value
        :param msp_value1: MSP metric 1 (code size) value
        :param msp_value2: MSP metric 2 (RAM) value
        :param msp_value3: MSP metric 3 (execution time) value
        :param arm_value1: ARM metric 1 (code size) value
        :param arm_value2: ARM metric 2 (RAM) value
        :param arm_value3: ARM metric 3 (execution time) value
        :param avr_min_code_size: AVR min code size value
        :param avr_max_code_size: AVR max code size value
        :param msp_min_code_size: MSP min code size value
        :param msp_max_code_size: MSP max code size value
        :param arm_min_code_size: ARM min code size value
        :param arm_max_code_size: ARM max code size value
        :param avr_min_ram: AVR min RAM value
        :param avr_max_ram: AVR max RAM value
        :param msp_min_ram: MSP min RAM value
        :param msp_max_ram: MSP max RAM value
        :param arm_min_ram: ARM min RAM value
        :param arm_max_ram: ARM max RAM value
        :param avr_min_execution_time: AVR min execution time value
        :param avr_max_execution_time: AVR max execution time value
        :param msp_min_execution_time: MSP min execution time value
        :param msp_max_execution_time: MSP max execution time value
        :param arm_min_execution_time: ARM min execution time value
        :param arm_max_execution_time: ARM max execution time value
        :param avr_implementation_type: AVR implementation type
        :param msp_implementation_type: MSP implementation type
        :param arm_implementation_type: ARM implementation type
        :return: The LaTeX table row data
        """

        # AVR
        if avr_min_code_size == avr_value1:
            avr_value1 = Constants.LATEX_MIN_VALUE.format(avr_value1)
        if avr_max_code_size == avr_value1:
            avr_value1 = Constants.LATEX_MAX_VALUE.format(avr_value1)

        if avr_min_ram == avr_value2:
            avr_value2 = Constants.LATEX_MIN_VALUE.format(avr_value2)
        if avr_max_ram == avr_value2:
            avr_value2 = Constants.LATEX_MAX_VALUE.format(avr_value2)

        if avr_min_execution_time == avr_value3:
            avr_value3 = Constants.LATEX_MIN_VALUE.format(avr_value3)
        if avr_max_execution_time == avr_value3:
            avr_value3 = Constants.LATEX_MAX_VALUE.format(avr_value3)

        # MSP
        if msp_min_code_size == msp_value1:
            msp_value1 = Constants.LATEX_MIN_VALUE.format(msp_value1)
        if msp_max_code_size == msp_value1:
            msp_value1 = Constants.LATEX_MAX_VALUE.format(msp_value1)

        if msp_min_ram == msp_value2:
            msp_value2 = Constants.LATEX_MIN_VALUE.format(msp_value2)
        if msp_max_ram == msp_value2:
            msp_value2 = Constants.LATEX_MAX_VALUE.format(msp_value2)

        if msp_min_execution_time == msp_value3:
            msp_value3 = Constants.LATEX_MIN_VALUE.format(msp_value3)
        if msp_max_execution_time == msp_value3:
            msp_value3 = Constants.LATEX_MAX_VALUE.format(msp_value3)

        # ARM
        if arm_min_code_size == arm_value1:
            arm_value1 = Constants.LATEX_MIN_VALUE.format(arm_value1)
        if arm_min_ram == arm_value2:
            arm_value2 = Constants.LATEX_MIN_VALUE.format(arm_value2)
        if arm_min_execution_time == arm_value3:
            arm_value3 = Constants.LATEX_MIN_VALUE.format(arm_value3)

        if Constants.IMPLEMENTATION_TYPE_ASM == avr_implementation_type or \
                        Constants.IMPLEMENTATION_TYPE_C_ASM == avr_implementation_type:
            avr_value1 = Constants.LATEX_ASM_VALUE.format(avr_value1)
            avr_value2 = Constants.LATEX_ASM_VALUE.format(avr_value2)
            avr_value3 = Constants.LATEX_ASM_VALUE.format(avr_value3)
        else:
            avr_value1 = Constants.LATEX_C_VALUE.format(avr_value1)
            avr_value2 = Constants.LATEX_C_VALUE.format(avr_value2)
            avr_value3 = Constants.LATEX_C_VALUE.format(avr_value3)

        if Constants.IMPLEMENTATION_TYPE_ASM == msp_implementation_type or \
                        Constants.IMPLEMENTATION_TYPE_C_ASM == msp_implementation_type:
            msp_value1 = Constants.LATEX_ASM_VALUE.format(msp_value1)
            msp_value2 = Constants.LATEX_ASM_VALUE.format(msp_value2)
            msp_value3 = Constants.LATEX_ASM_VALUE.format(msp_value3)
        else:
            msp_value1 = Constants.LATEX_C_VALUE.format(msp_value1)
            msp_value2 = Constants.LATEX_C_VALUE.format(msp_value2)
            msp_value3 = Constants.LATEX_C_VALUE.format(msp_value3)

        if Constants.IMPLEMENTATION_TYPE_ASM == arm_implementation_type or \
                        Constants.IMPLEMENTATION_TYPE_C_ASM == arm_implementation_type:
            arm_value1 = Constants.LATEX_ASM_VALUE.format(arm_value1)
            arm_value2 = Constants.LATEX_ASM_VALUE.format(arm_value2)
            arm_value3 = Constants.LATEX_ASM_VALUE.format(arm_value3)
        else:
            arm_value1 = Constants.LATEX_C_VALUE.format(arm_value1)
            arm_value2 = Constants.LATEX_C_VALUE.format(arm_value2)
            arm_value3 = Constants.LATEX_C_VALUE.format(arm_value3)

        return [avr_value1, avr_value2, avr_value3,
                msp_value1, msp_value2, msp_value3,
                arm_value1, arm_value2, arm_value3]

    def generate_latex_table(self):
        """
        Generate LaTeX table

        """

        f = open(Constants.RESULT_LATEX_FILE_PATH, Constants.RESULT_FILE_ACCESS_MODE)

        # Table 1 header
        f.write('\\begin{center} \n')
        f.write('\\begin{threeparttable} \n')
        # f.write('\\begin{table} \n')
        # f.write('\\scriptsize \n')
        # f.write('\\begin{center} \n')
        f.write('\\caption {Results for scenario 2. Encrypt 128 bits of data using CTR mode. For each cipher, an '
                'optimal implementation on each architecture is selected.} \label{tab:scen2a} \n')
        f.write('\\begin{tabular}{lccc|ccc|ccc|c} \n')
        f.write('\\toprule \n')
        f.write('\\multirow{2}{*}{\\textbf{Cipher}} & \n')
        f.write('\\multicolumn{3}{c}{\\textbf{AVR}} & \n')
        f.write('\\multicolumn{3}{c}{\\textbf{MSP}} & \n')
        f.write('\\multicolumn{3}{c}{\\textbf{ARM}} \\\\ \n')
        f.write('\\cmidrule(r){2-4} \cmidrule(r){5-7} \cmidrule(r){8-10} \n')
        f.write('& \n')
        f.write('\\thead{Code} & \n')
        f.write('\\thead{RAM} & \n')
        f.write('\\thead{Time} & \n')
        f.write('\\thead{Code} & \n')
        f.write('\\thead{RAM} & \n')
        f.write('\\thead{Time} & \n')
        f.write('\\thead{Code} & \n')
        f.write('\\thead{RAM} & \n')
        f.write('\\thead{Time} & \n')
        f.write('\\thead{FOM} \\\\ \n')
        f.write('& \n')
        f.write('[B] & \n')
        f.write('[B] & \n')
        f.write('[cyc.] & \n')
        f.write('[B] & \n')
        f.write('[B] & \n')
        f.write('[cyc.] & \n')
        f.write('[B] & \n')
        f.write('[B] & \n')
        f.write('[cyc.] & \n')
        f.write('\\\\ \n')

        # First section
        f.write('\\midrule \n')
        f.write('\\multicolumn{11}{c}{Balanced (globally efficient)} \\\\ \n')
        f.write('\\midrule \n')

        self.selected_ciphers.sort(key=lambda c: c.fom1)

        # Code size
        avr_min_code_size = 1e10
        avr_max_code_size = 0

        msp_min_code_size = 1e10
        msp_max_code_size = 0

        arm_min_code_size = 1e10
        arm_max_code_size = 0

        # RAM
        avr_min_ram = 1e10
        avr_max_ram = 0

        msp_min_ram = 1e10
        msp_max_ram = 0

        arm_min_ram = 1e10
        arm_max_ram = 0

        # Execution time
        avr_min_execution_time = 1e10
        avr_max_execution_time = 0

        msp_min_execution_time = 1e10
        msp_max_execution_time = 0

        arm_min_execution_time = 1e10
        arm_max_execution_time = 0

        for selected_cipher in self.selected_ciphers:
            # Code size
            value = selected_cipher.avr_metrics1.code_size_e
            if avr_min_code_size > value:
                avr_min_code_size = value
            if avr_max_code_size < value:
                avr_max_code_size = value

            value = selected_cipher.msp_metrics1.code_size_e
            if msp_min_code_size > value:
                msp_min_code_size = value
            if msp_max_code_size < value:
                msp_max_code_size = value

            value = selected_cipher.arm_metrics1.code_size_e
            if arm_min_code_size > value:
                arm_min_code_size = value
            if arm_max_code_size < value:
                arm_max_code_size = value

            # RAM
            value = selected_cipher.avr_metrics1.ram_data + \
                    selected_cipher.avr_metrics1.ram_stack_e
            if avr_min_ram > value:
                avr_min_ram = value
            if avr_max_ram < value:
                avr_max_ram = value

            value = selected_cipher.msp_metrics1.ram_data + \
                    selected_cipher.msp_metrics1.ram_stack_e
            if msp_min_ram > value:
                msp_min_ram = value
            if msp_max_ram < value:
                msp_max_ram = value

            value = selected_cipher.arm_metrics1.ram_data + \
                    selected_cipher.arm_metrics1.ram_stack_e
            if arm_min_ram > value:
                arm_min_ram = value
            if arm_max_ram < value:
                arm_max_ram = value

            # Execution time
            value = selected_cipher.avr_metrics1.execution_time_e
            if avr_min_execution_time > value:
                avr_min_execution_time = value
            if avr_max_execution_time < value:
                avr_max_execution_time = value

            value = selected_cipher.msp_metrics1.execution_time_e
            if msp_min_execution_time > value:
                msp_min_execution_time = value
            if msp_max_execution_time < value:
                msp_max_execution_time = value

            value = selected_cipher.arm_metrics1.execution_time_e
            if arm_min_execution_time > value:
                arm_min_execution_time = value
            if arm_max_execution_time < value:
                arm_max_execution_time = value

        for selected_cipher in self.selected_ciphers:
            avr_value1 = selected_cipher.avr_metrics1.code_size_e
            avr_value2 = selected_cipher.avr_metrics1.ram_data + \
                         selected_cipher.avr_metrics1.ram_stack_e
            avr_value3 = selected_cipher.avr_metrics1.execution_time_e

            msp_value1 = selected_cipher.msp_metrics1.code_size_e
            msp_value2 = selected_cipher.msp_metrics1.ram_data + \
                         selected_cipher.msp_metrics1.ram_stack_e
            msp_value3 = selected_cipher.msp_metrics1.execution_time_e

            arm_value1 = selected_cipher.arm_metrics1.code_size_e
            arm_value2 = selected_cipher.arm_metrics1.ram_data + \
                         selected_cipher.arm_metrics1.ram_stack_e
            arm_value3 = selected_cipher.arm_metrics1.execution_time_e

            [avr_value1, avr_value2, avr_value3,
             msp_value1, msp_value2, msp_value3,
             arm_value1, arm_value2, arm_value3] = \
                self.generate_latex_table_row_data(avr_value1, avr_value2, avr_value3,
                                                   msp_value1, msp_value2, msp_value3,
                                                   arm_value1, arm_value2, arm_value3,

                                                   avr_min_code_size,
                                                   avr_max_code_size,
                                                   msp_min_code_size,
                                                   msp_max_code_size,
                                                   arm_min_code_size,
                                                   arm_max_code_size,

                                                   avr_min_ram,
                                                   avr_max_ram,
                                                   msp_min_ram,
                                                   msp_max_ram,
                                                   arm_min_ram,
                                                   arm_max_ram,

                                                   avr_min_execution_time,
                                                   avr_max_execution_time,
                                                   msp_min_execution_time,
                                                   msp_max_execution_time,
                                                   arm_min_execution_time,
                                                   arm_max_execution_time,

                                                   selected_cipher.avr_metrics1.implementation_type,
                                                   selected_cipher.msp_metrics1.implementation_type,
                                                   selected_cipher.arm_metrics1.implementation_type)

            f.write(Constants.LATEX_SECTION1_ROW_FORMAT.format(selected_cipher.name,

                                                               avr_value1,
                                                               avr_value2,
                                                               avr_value3,

                                                               msp_value1,
                                                               msp_value2,
                                                               msp_value3,

                                                               arm_value1,
                                                               arm_value2,
                                                               arm_value3,

                                                               round(selected_cipher.fom1, Constants.LATEX_ROUND_FOM),

                                                               selected_cipher.avr_version1,
                                                               selected_cipher.avr_compiler_options1,
                                                               selected_cipher.msp_version1,
                                                               selected_cipher.msp_compiler_options1,
                                                               selected_cipher.arm_version1,
                                                               selected_cipher.arm_compiler_options1))

        # Code size
        avr_min_code_size = 1e10
        avr_max_code_size = 0

        msp_min_code_size = 1e10
        msp_max_code_size = 0

        arm_min_code_size = 1e10
        arm_max_code_size = 0

        # RAM
        avr_min_ram = 1e10
        avr_max_ram = 0

        msp_min_ram = 1e10
        msp_max_ram = 0

        arm_min_ram = 1e10
        arm_max_ram = 0

        # Execution time
        avr_min_execution_time = 1e10
        avr_max_execution_time = 0

        msp_min_execution_time = 1e10
        msp_max_execution_time = 0

        arm_min_execution_time = 1e10
        arm_max_execution_time = 0

        # Table 1 footer
        f.write('\\bottomrule \n')
        f.write('\\end{tabular} \n')
        # f.write('\\end{center} \n')
        # f.write('\\end{table} \n')
        f.write('\\begin{tablenotes} \n')
        f.write('\\item[\\textasteriskcentered] Results for assembly implementations. \n')
        f.write('\\end{tablenotes} \n')
        f.write('\\end{threeparttable} \n')
        f.write('\\end{center} \n')
        f.write('\n\n\n')

        # Table 2 header
        f.write('\\begin{center} \n')
        f.write('\\begin{threeparttable} \n')
        # f.write('\\begin{table} \n')
        # f.write('\\scriptsize \n')
        # f.write('\\begin{center} \n')
        f.write('\\caption {Results for scenario 2. Encrypt 128 bits of data using CTR mode. For each cipher, an '
                'optimal implementation on each architecture is selected.} \label{tab:scen2b} \n')
        f.write('\\begin{tabular}{lccc|ccc|ccc} \n')
        f.write('\\toprule \n')
        f.write('\\multirow{2}{*}{\\textbf{Cipher}} & \n')
        f.write('\\multicolumn{3}{c}{\\textbf{AVR}} & \n')
        f.write('\\multicolumn{3}{c}{\\textbf{MSP}} & \n')
        f.write('\\multicolumn{3}{c}{\\textbf{ARM}} \\\\ \n')
        f.write('\\cmidrule(r){2-4} \cmidrule(r){5-7} \cmidrule(r){8-10} \n')
        f.write('& \n')
        f.write('\\thead{Code} & \n')
        f.write('\\thead{RAM} & \n')
        f.write('\\thead{Time} & \n')
        f.write('\\thead{Code} & \n')
        f.write('\\thead{RAM} & \n')
        f.write('\\thead{Time} & \n')
        f.write('\\thead{Code} & \n')
        f.write('\\thead{RAM} & \n')
        f.write('\\thead{Time} \\\\ \n')
        f.write('& \n')
        f.write('[B] & \n')
        f.write('[B] & \n')
        f.write('[cyc.] & \n')
        f.write('[B] & \n')
        f.write('[B] & \n')
        f.write('[cyc.] & \n')
        f.write('[B] & \n')
        f.write('[B] & \n')
        f.write('[cyc.] \\\\ \n')

        # Second section
        f.write('\\midrule \n')
        f.write('\\multicolumn{10}{c}{I: Small code size \\& RAM} \\\\ \n')
        f.write('\\midrule \n')

        self.selected_ciphers.sort(key=lambda c: c.name)

        for selected_cipher in self.selected_ciphers:
            # Code size
            value = selected_cipher.avr_metrics2.code_size_e
            if avr_min_code_size > value:
                avr_min_code_size = value
            if avr_max_code_size < value:
                avr_max_code_size = value

            value = selected_cipher.msp_metrics2.code_size_e
            if msp_min_code_size > value:
                msp_min_code_size = value
            if msp_max_code_size < value:
                msp_max_code_size = value

            value = selected_cipher.arm_metrics2.code_size_e
            if arm_min_code_size > value:
                arm_min_code_size = value
            if arm_max_code_size < value:
                arm_max_code_size = value

            # RAM
            value = selected_cipher.avr_metrics2.ram_data + \
                    selected_cipher.avr_metrics2.ram_stack_e
            if avr_min_ram > value:
                avr_min_ram = value
            if avr_max_ram < value:
                avr_max_ram = value

            value = selected_cipher.msp_metrics2.ram_data + \
                    selected_cipher.msp_metrics2.ram_stack_e
            if msp_min_ram > value:
                msp_min_ram = value
            if msp_max_ram < value:
                msp_max_ram = value

            value = selected_cipher.arm_metrics2.ram_data + \
                    selected_cipher.arm_metrics2.ram_stack_e
            if arm_min_ram > value:
                arm_min_ram = value
            if arm_max_ram < value:
                arm_max_ram = value

            # Execution time
            value = selected_cipher.avr_metrics2.execution_time_e
            if avr_min_execution_time > value:
                avr_min_execution_time = value
            if avr_max_execution_time < value:
                avr_max_execution_time = value

            value = selected_cipher.msp_metrics2.execution_time_e
            if msp_min_execution_time > value:
                msp_min_execution_time = value
            if msp_max_execution_time < value:
                msp_max_execution_time = value

            value = selected_cipher.arm_metrics2.execution_time_e
            if arm_min_execution_time > value:
                arm_min_execution_time = value
            if arm_max_execution_time < value:
                arm_max_execution_time = value

        for selected_cipher in self.selected_ciphers:
            avr_value1 = selected_cipher.avr_metrics2.code_size_e
            avr_value2 = selected_cipher.avr_metrics2.ram_data + \
                         selected_cipher.avr_metrics2.ram_stack_e
            avr_value3 = selected_cipher.avr_metrics2.execution_time_e

            msp_value1 = selected_cipher.msp_metrics2.code_size_e
            msp_value2 = selected_cipher.msp_metrics2.ram_data + \
                         selected_cipher.msp_metrics2.ram_stack_e
            msp_value3 = selected_cipher.msp_metrics2.execution_time_e

            arm_value1 = selected_cipher.arm_metrics2.code_size_e
            arm_value2 = selected_cipher.arm_metrics2.ram_data + \
                         selected_cipher.arm_metrics2.ram_stack_e
            arm_value3 = selected_cipher.arm_metrics2.execution_time_e

            [avr_value1, avr_value2, avr_value3,
             msp_value1, msp_value2, msp_value3,
             arm_value1, arm_value2, arm_value3] = \
                self.generate_latex_table_row_data(avr_value1, avr_value2, avr_value3,
                                                   msp_value1, msp_value2, msp_value3,
                                                   arm_value1, arm_value2, arm_value3,

                                                   avr_min_code_size,
                                                   avr_max_code_size,
                                                   msp_min_code_size,
                                                   msp_max_code_size,
                                                   arm_min_code_size,
                                                   arm_max_code_size,

                                                   avr_min_ram,
                                                   avr_max_ram,
                                                   msp_min_ram,
                                                   msp_max_ram,
                                                   arm_min_ram,
                                                   arm_max_ram,

                                                   avr_min_execution_time,
                                                   avr_max_execution_time,
                                                   msp_min_execution_time,
                                                   msp_max_execution_time,
                                                   arm_min_execution_time,
                                                   arm_max_execution_time,

                                                   selected_cipher.avr_metrics2.implementation_type,
                                                   selected_cipher.msp_metrics2.implementation_type,
                                                   selected_cipher.arm_metrics2.implementation_type)

            f.write(Constants.LATEX_SECTION2_ROW_FORMAT.format(selected_cipher.name,

                                                               avr_value1,
                                                               avr_value2,
                                                               avr_value3,

                                                               msp_value1,
                                                               msp_value2,
                                                               msp_value3,

                                                               arm_value1,
                                                               arm_value2,
                                                               arm_value3,

                                                               selected_cipher.avr_version2,
                                                               selected_cipher.avr_compiler_options2,
                                                               selected_cipher.msp_version2,
                                                               selected_cipher.msp_compiler_options2,
                                                               selected_cipher.arm_version2,
                                                               selected_cipher.arm_compiler_options2))

        # Code size
        avr_min_code_size = 1e10
        avr_max_code_size = 0

        msp_min_code_size = 1e10
        msp_max_code_size = 0

        arm_min_code_size = 1e10
        arm_max_code_size = 0

        # RAM
        avr_min_ram = 1e10
        avr_max_ram = 0

        msp_min_ram = 1e10
        msp_max_ram = 0

        arm_min_ram = 1e10
        arm_max_ram = 0

        # Execution time
        avr_min_execution_time = 1e10
        avr_max_execution_time = 0

        msp_min_execution_time = 1e10
        msp_max_execution_time = 0

        arm_min_execution_time = 1e10
        arm_max_execution_time = 0

        # Third section
        f.write('\\midrule \n')
        f.write('\\multicolumn{10}{c}{II: Best execution time} \\\\ \n')
        f.write('\\midrule \n')

        self.selected_ciphers.sort(key=lambda c: c.name)

        for selected_cipher in self.selected_ciphers:
            # Code size
            value = selected_cipher.avr_metrics3.code_size_e
            if avr_min_code_size > value:
                avr_min_code_size = value
            if avr_max_code_size < value:
                avr_max_code_size = value

            value = selected_cipher.msp_metrics3.code_size_e
            if msp_min_code_size > value:
                msp_min_code_size = value
            if msp_max_code_size < value:
                msp_max_code_size = value

            value = selected_cipher.arm_metrics3.code_size_e
            if arm_min_code_size > value:
                arm_min_code_size = value
            if arm_max_code_size < value:
                arm_max_code_size = value

            # RAM
            value = selected_cipher.avr_metrics3.ram_data + \
                    selected_cipher.avr_metrics3.ram_stack_e
            if avr_min_ram > value:
                avr_min_ram = value
            if avr_max_ram < value:
                avr_max_ram = value

            value = selected_cipher.msp_metrics3.ram_data + \
                    selected_cipher.msp_metrics3.ram_stack_e
            if msp_min_ram > value:
                msp_min_ram = value
            if msp_max_ram < value:
                msp_max_ram = value

            value = selected_cipher.arm_metrics3.ram_data + \
                    selected_cipher.arm_metrics3.ram_stack_e
            if arm_min_ram > value:
                arm_min_ram = value
            if arm_max_ram < value:
                arm_max_ram = value

            # Execution time
            value = selected_cipher.avr_metrics3.execution_time_e
            if avr_min_execution_time > value:
                avr_min_execution_time = value
            if avr_max_execution_time < value:
                avr_max_execution_time = value

            value = selected_cipher.msp_metrics3.execution_time_e
            if msp_min_execution_time > value:
                msp_min_execution_time = value
            if msp_max_execution_time < value:
                msp_max_execution_time = value

            value = selected_cipher.arm_metrics3.execution_time_e
            if arm_min_execution_time > value:
                arm_min_execution_time = value
            if arm_max_execution_time < value:
                arm_max_execution_time = value


        for selected_cipher in self.selected_ciphers:
            avr_value1 = selected_cipher.avr_metrics3.code_size_e
            avr_value2 = selected_cipher.avr_metrics3.ram_data + \
                         selected_cipher.avr_metrics3.ram_stack_e
            avr_value3 = selected_cipher.avr_metrics3.execution_time_e

            msp_value1 = selected_cipher.msp_metrics3.code_size_e
            msp_value2 = selected_cipher.msp_metrics3.ram_data + \
                         selected_cipher.msp_metrics3.ram_stack_e
            msp_value3 = selected_cipher.msp_metrics3.execution_time_e

            arm_value1 = selected_cipher.arm_metrics3.code_size_e
            arm_value2 = selected_cipher.arm_metrics3.ram_data + \
                         selected_cipher.arm_metrics3.ram_stack_e
            arm_value3 = selected_cipher.arm_metrics3.execution_time_e

            [avr_value1, avr_value2, avr_value3,
             msp_value1, msp_value2, msp_value3,
             arm_value1, arm_value2, arm_value3] = \
                self.generate_latex_table_row_data(avr_value1, avr_value2, avr_value3,
                                                   msp_value1, msp_value2, msp_value3,
                                                   arm_value1, arm_value2, arm_value3,

                                                   avr_min_code_size,
                                                   avr_max_code_size,
                                                   msp_min_code_size,
                                                   msp_max_code_size,
                                                   arm_min_code_size,
                                                   arm_max_code_size,

                                                   avr_min_ram,
                                                   avr_max_ram,
                                                   msp_min_ram,
                                                   msp_max_ram,
                                                   arm_min_ram,
                                                   arm_max_ram,

                                                   avr_min_execution_time,
                                                   avr_max_execution_time,
                                                   msp_min_execution_time,
                                                   msp_max_execution_time,
                                                   arm_min_execution_time,
                                                   arm_max_execution_time,

                                                   selected_cipher.avr_metrics3.implementation_type,
                                                   selected_cipher.msp_metrics3.implementation_type,
                                                   selected_cipher.arm_metrics3.implementation_type)

            f.write(Constants.LATEX_SECTION3_ROW_FORMAT.format(selected_cipher.name,

                                                               avr_value1,
                                                               avr_value2,
                                                               avr_value3,

                                                               msp_value1,
                                                               msp_value2,
                                                               msp_value3,

                                                               arm_value1,
                                                               arm_value2,
                                                               arm_value3,

                                                               selected_cipher.avr_version3,
                                                               selected_cipher.avr_compiler_options3,
                                                               selected_cipher.msp_version3,
                                                               selected_cipher.msp_compiler_options3,
                                                               selected_cipher.arm_version3,
                                                               selected_cipher.arm_compiler_options3))

        # Table 2 footer
        f.write('\\bottomrule \n')
        f.write('\\end{tabular} \n')
        # f.write('\\end{center} \n')
        # f.write('\\end{table} \n')
        f.write('\\begin{tablenotes} \n')
        f.write('\\item[\\textasteriskcentered] Results for assembly implementations. \n')
        f.write('\\end{tablenotes} \n')
        f.write('\\end{threeparttable} \n')
        f.write('\\end{center} \n')

        f.close()

        if Constants.DEBUG_ON == Constants.DEBUG:
            print(Constants.DONE)

    def generate_mediawiki_table_row_data(self,
                             avr_value1, avr_value2, avr_value3,
                             msp_value1, msp_value2, msp_value3,
                             arm_value1, arm_value2, arm_value3,

                             avr_min_code_size,
                             avr_max_code_size,
                             msp_min_code_size,
                             msp_max_code_size,
                             arm_min_code_size,
                             arm_max_code_size,

                             avr_min_ram,
                             avr_max_ram,
                             msp_min_ram,
                             msp_max_ram,
                             arm_min_ram,
                             arm_max_ram,

                             avr_min_execution_time,
                             avr_max_execution_time,
                             msp_min_execution_time,
                             msp_max_execution_time,
                             arm_min_execution_time,
                             arm_max_execution_time,

                             avr_implementation_type,
                             msp_implementation_type,
                             arm_implementation_type):

        """
        Generate MediaWiki table row data
        :param avr_value1: AVR metric 1 (code size) value
        :param avr_value2: AVR metric 2 (RAM) value
        :param avr_value3: AVR metric 3 (execution time) value
        :param msp_value1: MSP metric 1 (code size) value
        :param msp_value2: MSP metric 2 (RAM) value
        :param msp_value3: MSP metric 3 (execution time) value
        :param arm_value1: ARM metric 1 (code size) value
        :param arm_value2: ARM metric 2 (RAM) value
        :param arm_value3: ARM metric 3 (execution time) value
        :param avr_min_code_size: AVR min code size value
        :param avr_max_code_size: AVR max code size value
        :param msp_min_code_size: MSP min code size value
        :param msp_max_code_size: MSP max code size value
        :param arm_min_code_size: ARM min code size value
        :param arm_max_code_size: ARM max code size value
        :param avr_min_ram: AVR min RAM value
        :param avr_max_ram: AVR max RAM value
        :param msp_min_ram: MSP min RAM value
        :param msp_max_ram: MSP max RAM value
        :param arm_min_ram: ARM min RAM value
        :param arm_max_ram: ARM max RAM value
        :param avr_min_execution_time: AVR min execution time value
        :param avr_max_execution_time: AVR max execution time value
        :param msp_min_execution_time: MSP min execution time value
        :param msp_max_execution_time: MSP max execution time value
        :param arm_min_execution_time: ARM min execution time value
        :param arm_max_execution_time: ARM max execution time value
        :param avr_implementation_type: AVR implementation type
        :param msp_implementation_type: MSP implementation type
        :param arm_implementation_type: ARM implementation type
        :return: The MediaWiki table row data
        """

        if Constants.IMPLEMENTATION_TYPE_ASM == avr_implementation_type or \
                        Constants.IMPLEMENTATION_TYPE_C_ASM == avr_implementation_type:
            avr_value1_string = Constants.MEDIAWIKI_ASM_VALUE.format(avr_value1)
            avr_value2_string = Constants.MEDIAWIKI_ASM_VALUE.format(avr_value2)
            avr_value3_string = Constants.MEDIAWIKI_ASM_VALUE.format(avr_value3)
        else:
            avr_value1_string = Constants.MEDIAWIKI_C_VALUE.format(avr_value1)
            avr_value2_string = Constants.MEDIAWIKI_C_VALUE.format(avr_value2)
            avr_value3_string = Constants.MEDIAWIKI_C_VALUE.format(avr_value3)

        if Constants.IMPLEMENTATION_TYPE_ASM == msp_implementation_type or \
                        Constants.IMPLEMENTATION_TYPE_C_ASM == msp_implementation_type:
            msp_value1_string = Constants.MEDIAWIKI_ASM_VALUE.format(msp_value1)
            msp_value2_string = Constants.MEDIAWIKI_ASM_VALUE.format(msp_value2)
            msp_value3_string = Constants.MEDIAWIKI_ASM_VALUE.format(msp_value3)
        else:
            msp_value1_string = Constants.MEDIAWIKI_C_VALUE.format(msp_value1)
            msp_value2_string = Constants.MEDIAWIKI_C_VALUE.format(msp_value2)
            msp_value3_string = Constants.MEDIAWIKI_C_VALUE.format(msp_value3)

        if Constants.IMPLEMENTATION_TYPE_ASM == arm_implementation_type and \
                        Constants.IMPLEMENTATION_TYPE_C_ASM == arm_implementation_type:
            arm_value1_string = Constants.MEDIAWIKI_ASM_VALUE.format(arm_value1)
            arm_value2_string = Constants.MEDIAWIKI_ASM_VALUE.format(arm_value2)
            arm_value3_string = Constants.MEDIAWIKI_ASM_VALUE.format(arm_value3)
        else:
            arm_value1_string = Constants.MEDIAWIKI_C_VALUE.format(arm_value1)
            arm_value2_string = Constants.MEDIAWIKI_C_VALUE.format(arm_value2)
            arm_value3_string = Constants.MEDIAWIKI_C_VALUE.format(arm_value3)

        # AVR
        if avr_min_code_size == avr_value1:
            avr_value1_string = Constants.MEDIAWIKI_MIN_VALUE.format(avr_value1_string)
        if avr_max_code_size == avr_value1:
            avr_value1_string = Constants.MEDIAWIKI_MAX_VALUE.format(avr_value1_string)

        if avr_min_ram == avr_value2:
            avr_value2_string = Constants.MEDIAWIKI_MIN_VALUE.format(avr_value2_string)
        if avr_max_ram == avr_value2:
            avr_value2_string = Constants.MEDIAWIKI_MAX_VALUE.format(avr_value2_string)

        if avr_min_execution_time == avr_value3:
            avr_value3_string = Constants.MEDIAWIKI_MIN_VALUE.format(avr_value3_string)
        if avr_max_execution_time == avr_value3:
            avr_value3_string = Constants.MEDIAWIKI_MAX_VALUE.format(avr_value3_string)

        # MSP
        if msp_min_code_size == msp_value1:
            msp_value1_string = Constants.MEDIAWIKI_MIN_VALUE.format(msp_value1_string)
        if msp_max_code_size == msp_value1:
            msp_value1_string = Constants.MEDIAWIKI_MAX_VALUE.format(msp_value1_string)

        if msp_min_ram == msp_value2:
            msp_value2_string = Constants.MEDIAWIKI_MIN_VALUE.format(msp_value2_string)
        if msp_max_ram == msp_value2:
            msp_value2_string = Constants.MEDIAWIKI_MAX_VALUE.format(msp_value2_string)

        if msp_min_execution_time == msp_value3:
            msp_value3_string = Constants.MEDIAWIKI_MIN_VALUE.format(msp_value3_string)
        if msp_max_execution_time == msp_value3:
            msp_value3_string = Constants.MEDIAWIKI_MAX_VALUE.format(msp_value3_string)

        # ARM
        if arm_min_code_size == arm_value1:
            arm_value1_string = Constants.MEDIAWIKI_MIN_VALUE.format(arm_value1_string)
        if arm_max_code_size == arm_value1:
            arm_value1_string = Constants.MEDIAWIKI_MAX_VALUE.format(arm_value1_string)

        if arm_min_ram == arm_value2:
            arm_value2_string = Constants.MEDIAWIKI_MIN_VALUE.format(arm_value2_string)
        if arm_max_ram == arm_value2:
            arm_value2_string = Constants.MEDIAWIKI_MAX_VALUE.format(arm_value2_string)

        if arm_min_execution_time == arm_value3:
            arm_value3_string = Constants.MEDIAWIKI_MIN_VALUE.format(arm_value3_string)
        if arm_max_execution_time == arm_value3:
            arm_value3_string = Constants.MEDIAWIKI_MAX_VALUE.format(arm_value3_string)

        return [avr_value1_string, avr_value2_string, avr_value3_string,
                msp_value1_string, msp_value2_string, msp_value3_string,
                arm_value1_string, arm_value2_string, arm_value3_string]

    def generate_mediawiki_table(self):
        """
        Generate MediaWiki table

        """

        f = open(Constants.RESULT_MEDIAWIKI_FILE_PATH, Constants.RESULT_FILE_ACCESS_MODE)

        # Table 1 header
        f.write('{| class="wikitable sortable" style="margin: auto;" \n')
        f.write('|+ Results for scenario 2 - I: Balanced (globally efficient). Encrypt 128 bits of data using CTR mode.'
                ' For each cipher, an optimal implementation on each architecture is selected. \n')
        f.write('|- \n')
        f.write('! scope="col" colspan="4" rowspan="2" | Cipher Info \n')
        f.write('! scope="col" colspan="10" | Results \n')
        f.write('|- \n')
        f.write('! scope="col" colspan="3" | AVR \n')
        f.write('! scope="col" colspan="3" | MSP \n')
        f.write('! scope="col" colspan="3" | ARM \n')
        f.write('! scope="col" | \n')
        f.write('|- \n')
        f.write('! scope="col" | Cipher \n')
        f.write('! scope="col" | Block [b] \n')
        f.write('! scope="col" | Key [b] \n')
        f.write('! scope="col" | Sec. \n')
        f.write('! scope="col" | Code [B] \n')
        f.write('! scope="col" | RAM [B] \n')
        f.write('! scope="col" | Time [cyc.] \n')
        f.write('! scope="col" | Code [B] \n')
        f.write('! scope="col" | RAM [B] \n')
        f.write('! scope="col" | Time [cyc.] \n')
        f.write('! scope="col" | Code [B] \n')
        f.write('! scope="col" | RAM [B] \n')
        f.write('! scope="col" | Time [cyc.] \n')
        f.write('! scope="col" | [[FELICS_Figure_Of_Merit|FOM]] \n')

        self.selected_ciphers.sort(key=lambda c: c.fom1)

        # Code size
        avr_min_code_size = 1e10
        avr_max_code_size = 0

        msp_min_code_size = 1e10
        msp_max_code_size = 0

        arm_min_code_size = 1e10
        arm_max_code_size = 0

        # RAM
        avr_min_ram = 1e10
        avr_max_ram = 0

        msp_min_ram = 1e10
        msp_max_ram = 0

        arm_min_ram = 1e10
        arm_max_ram = 0

        # Execution time
        avr_min_execution_time = 1e10
        avr_max_execution_time = 0

        msp_min_execution_time = 1e10
        msp_max_execution_time = 0

        arm_min_execution_time = 1e10
        arm_max_execution_time = 0

        for selected_cipher in self.selected_ciphers:
            # Code size
            value = selected_cipher.avr_metrics1.code_size_e
            if avr_min_code_size > value:
                avr_min_code_size = value
            if avr_max_code_size < value:
                avr_max_code_size = value

            value = selected_cipher.msp_metrics1.code_size_e
            if msp_min_code_size > value:
                msp_min_code_size = value
            if msp_max_code_size < value:
                msp_max_code_size = value

            value = selected_cipher.arm_metrics1.code_size_e
            if arm_min_code_size > value:
                arm_min_code_size = value
            if arm_max_code_size < value:
                arm_max_code_size = value

            # RAM
            value = selected_cipher.avr_metrics1.ram_data + \
                    selected_cipher.avr_metrics1.ram_stack_e
            if avr_min_ram > value:
                avr_min_ram = value
            if avr_max_ram < value:
                avr_max_ram = value

            value = selected_cipher.msp_metrics1.ram_data + \
                    selected_cipher.msp_metrics1.ram_stack_e
            if msp_min_ram > value:
                msp_min_ram = value
            if msp_max_ram < value:
                msp_max_ram = value

            value = selected_cipher.arm_metrics1.ram_data + \
                    selected_cipher.arm_metrics1.ram_stack_e
            if arm_min_ram > value:
                arm_min_ram = value
            if arm_max_ram < value:
                arm_max_ram = value

            # Execution time
            value = selected_cipher.avr_metrics1.execution_time_e
            if avr_min_execution_time > value:
                avr_min_execution_time = value
            if avr_max_execution_time < value:
                avr_max_execution_time = value

            value = selected_cipher.msp_metrics1.execution_time_e
            if msp_min_execution_time > value:
                msp_min_execution_time = value
            if msp_max_execution_time < value:
                msp_max_execution_time = value

            value = selected_cipher.arm_metrics1.execution_time_e
            if arm_min_execution_time > value:
                arm_min_execution_time = value
            if arm_max_execution_time < value:
                arm_max_execution_time = value

        for selected_cipher in self.selected_ciphers:
            avr_value1 = selected_cipher.avr_metrics1.code_size_e
            avr_value2 = selected_cipher.avr_metrics1.ram_data + \
                         selected_cipher.avr_metrics1.ram_stack_e
            avr_value3 = selected_cipher.avr_metrics1.execution_time_e

            msp_value1 = selected_cipher.msp_metrics1.code_size_e
            msp_value2 = selected_cipher.msp_metrics1.ram_data + \
                         selected_cipher.msp_metrics1.ram_stack_e
            msp_value3 = selected_cipher.msp_metrics1.execution_time_e

            arm_value1 = selected_cipher.arm_metrics1.code_size_e
            arm_value2 = selected_cipher.arm_metrics1.ram_data + \
                         selected_cipher.arm_metrics1.ram_stack_e
            arm_value3 = selected_cipher.arm_metrics1.execution_time_e

            [avr_value1, avr_value2, avr_value3,
             msp_value1, msp_value2, msp_value3,
             arm_value1, arm_value2, arm_value3] = \
                self.generate_mediawiki_table_row_data(avr_value1, avr_value2, avr_value3,
                                                       msp_value1, msp_value2, msp_value3,
                                                       arm_value1, arm_value2, arm_value3,

                                                       avr_min_code_size,
                                                       avr_max_code_size,
                                                       msp_min_code_size,
                                                       msp_max_code_size,
                                                       arm_min_code_size,
                                                       arm_max_code_size,

                                                       avr_min_ram,
                                                       avr_max_ram,
                                                       msp_min_ram,
                                                       msp_max_ram,
                                                       arm_min_ram,
                                                       arm_max_ram,

                                                       avr_min_execution_time,
                                                       avr_max_execution_time,
                                                       msp_min_execution_time,
                                                       msp_max_execution_time,
                                                       arm_min_execution_time,
                                                       arm_max_execution_time,

                                                       selected_cipher.avr_metrics1.implementation_type,
                                                       selected_cipher.msp_metrics1.implementation_type,
                                                       selected_cipher.arm_metrics1.implementation_type)

            f.write(Constants.MEDIAWIKI_SECTION1_ROW_FORMAT.format(selected_cipher.name_link,
                                                                   selected_cipher.block_size,
                                                                   selected_cipher.key_size,
                                                                   selected_cipher.security_level,

                                                                   avr_value1,
                                                                   avr_value2,
                                                                   avr_value3,

                                                                   msp_value1,
                                                                   msp_value2,
                                                                   msp_value3,

                                                                   arm_value1,
                                                                   arm_value2,
                                                                   arm_value3,

                                                                   round(selected_cipher.fom1,
                                                                         Constants.MEDIAWIKI_ROUND_FOM),

                                                                   selected_cipher.avr_version1,
                                                                   selected_cipher.avr_compiler_options1,
                                                                   selected_cipher.msp_version1,
                                                                   selected_cipher.msp_compiler_options1,
                                                                   selected_cipher.arm_version1,
                                                                   selected_cipher.arm_compiler_options1))

        # Code size
        avr_min_code_size = 1e10
        avr_max_code_size = 0

        msp_min_code_size = 1e10
        msp_max_code_size = 0

        arm_min_code_size = 1e10
        arm_max_code_size = 0

        # RAM
        avr_min_ram = 1e10
        avr_max_ram = 0

        msp_min_ram = 1e10
        msp_max_ram = 0

        arm_min_ram = 1e10
        arm_max_ram = 0

        # Execution time
        avr_min_execution_time = 1e10
        avr_max_execution_time = 0

        msp_min_execution_time = 1e10
        msp_max_execution_time = 0

        arm_min_execution_time = 1e10
        arm_max_execution_time = 0

        # Table 1 footer
        f.write('|}\n\n\n')

        # Table 2 header
        f.write('{| class="wikitable sortable" style="margin: auto;" \n')
        f.write('|+ Results for scenario 2 - II: Small code size & RAM. Encrypt 128 bits of data using CTR mode. '
                'For each cipher, an optimal implementation on each architecture is selected. \n')
        f.write('|- \n')
        f.write('! scope="col" colspan="4" rowspan="2" | Cipher Info \n')
        f.write('! scope="col" colspan="9" | Results \n')
        f.write('|- \n')
        f.write('! scope="col" colspan="3" | AVR \n')
        f.write('! scope="col" colspan="3" | MSP \n')
        f.write('! scope="col" colspan="3" | ARM \n')
        f.write('|- \n')
        f.write('! scope="col" | Cipher \n')
        f.write('! scope="col" | Block [b] \n')
        f.write('! scope="col" | Key [b] \n')
        f.write('! scope="col" | Sec. \n')
        f.write('! scope="col" | Code [B] \n')
        f.write('! scope="col" | RAM [B] \n')
        f.write('! scope="col" | Time [cyc.] \n')
        f.write('! scope="col" | Code [B] \n')
        f.write('! scope="col" | RAM [B] \n')
        f.write('! scope="col" | Time [cyc.] \n')
        f.write('! scope="col" | Code [B] \n')
        f.write('! scope="col" | RAM [B] \n')
        f.write('! scope="col" | Time [cyc.] \n')

        self.selected_ciphers.sort(key=lambda c: c.name)

        for selected_cipher in self.selected_ciphers:
            # Code size
            value = selected_cipher.avr_metrics2.code_size_e
            if avr_min_code_size > value:
                avr_min_code_size = value
            if avr_max_code_size < value:
                avr_max_code_size = value

            value = selected_cipher.msp_metrics2.code_size_e
            if msp_min_code_size > value:
                msp_min_code_size = value
            if msp_max_code_size < value:
                msp_max_code_size = value

            value = selected_cipher.arm_metrics2.code_size_e
            if arm_min_code_size > value:
                arm_min_code_size = value
            if arm_max_code_size < value:
                arm_max_code_size = value

            # RAM
            value = selected_cipher.avr_metrics2.ram_data + \
                    selected_cipher.avr_metrics2.ram_stack_e
            if avr_min_ram > value:
                avr_min_ram = value
            if avr_max_ram < value:
                avr_max_ram = value

            value = selected_cipher.msp_metrics2.ram_data + \
                    selected_cipher.msp_metrics2.ram_stack_e
            if msp_min_ram > value:
                msp_min_ram = value
            if msp_max_ram < value:
                msp_max_ram = value

            value = selected_cipher.arm_metrics2.ram_data + \
                    selected_cipher.arm_metrics2.ram_stack_e
            if arm_min_ram > value:
                arm_min_ram = value
            if arm_max_ram < value:
                arm_max_ram = value

            # Execution time
            value = selected_cipher.avr_metrics2.execution_time_e
            if avr_min_execution_time > value:
                avr_min_execution_time = value
            if avr_max_execution_time < value:
                avr_max_execution_time = value

            value = selected_cipher.msp_metrics2.execution_time_e
            if msp_min_execution_time > value:
                msp_min_execution_time = value
            if msp_max_execution_time < value:
                msp_max_execution_time = value

            value = selected_cipher.arm_metrics2.execution_time_e
            if arm_min_execution_time > value:
                arm_min_execution_time = value
            if arm_max_execution_time < value:
                arm_max_execution_time = value

        for selected_cipher in self.selected_ciphers:
            avr_value1 = selected_cipher.avr_metrics2.code_size_e
            avr_value2 = selected_cipher.avr_metrics2.ram_data + \
                         selected_cipher.avr_metrics2.ram_stack_e
            avr_value3 = selected_cipher.avr_metrics2.execution_time_e

            msp_value1 = selected_cipher.msp_metrics2.code_size_e
            msp_value2 = selected_cipher.msp_metrics2.ram_data + \
                         selected_cipher.msp_metrics2.ram_stack_e
            msp_value3 = selected_cipher.msp_metrics2.execution_time_e

            arm_value1 = selected_cipher.arm_metrics2.code_size_e
            arm_value2 = selected_cipher.arm_metrics2.ram_data + \
                         selected_cipher.arm_metrics2.ram_stack_e
            arm_value3 = selected_cipher.arm_metrics2.execution_time_e

            [avr_value1, avr_value2, avr_value3,
             msp_value1, msp_value2, msp_value3,
             arm_value1, arm_value2, arm_value3] = \
                self.generate_mediawiki_table_row_data(avr_value1, avr_value2, avr_value3,
                                                       msp_value1, msp_value2, msp_value3,
                                                       arm_value1, arm_value2, arm_value3,

                                                       avr_min_code_size,
                                                       avr_max_code_size,
                                                       msp_min_code_size,
                                                       msp_max_code_size,
                                                       arm_min_code_size,
                                                       arm_max_code_size,

                                                       avr_min_ram,
                                                       avr_max_ram,
                                                       msp_min_ram,
                                                       msp_max_ram,
                                                       arm_min_ram,
                                                       arm_max_ram,

                                                       avr_min_execution_time,
                                                       avr_max_execution_time,
                                                       msp_min_execution_time,
                                                       msp_max_execution_time,
                                                       arm_min_execution_time,
                                                       arm_max_execution_time,

                                                       selected_cipher.avr_metrics2.implementation_type,
                                                       selected_cipher.msp_metrics2.implementation_type,
                                                       selected_cipher.arm_metrics2.implementation_type)

            f.write(Constants.MEDIAWIKI_SECTION2_ROW_FORMAT.format(selected_cipher.name_link,
                                                                   selected_cipher.block_size,
                                                                   selected_cipher.key_size,
                                                                   selected_cipher.security_level,

                                                                   avr_value1,
                                                                   avr_value2,
                                                                   avr_value3,

                                                                   msp_value1,
                                                                   msp_value2,
                                                                   msp_value3,

                                                                   arm_value1,
                                                                   arm_value2,
                                                                   arm_value3,

                                                                   selected_cipher.avr_version2,
                                                                   selected_cipher.avr_compiler_options2,
                                                                   selected_cipher.msp_version2,
                                                                   selected_cipher.msp_compiler_options2,
                                                                   selected_cipher.arm_version2,
                                                                   selected_cipher.arm_compiler_options2))

        # Code size
        avr_min_code_size = 1e10
        avr_max_code_size = 0

        msp_min_code_size = 1e10
        msp_max_code_size = 0

        arm_min_code_size = 1e10
        arm_max_code_size = 0

        # RAM
        avr_min_ram = 1e10
        avr_max_ram = 0

        msp_min_ram = 1e10
        msp_max_ram = 0

        arm_min_ram = 1e10
        arm_max_ram = 0

        # Execution time
        avr_min_execution_time = 1e10
        avr_max_execution_time = 0

        msp_min_execution_time = 1e10
        msp_max_execution_time = 0

        arm_min_execution_time = 1e10
        arm_max_execution_time = 0

        # Table 2 footer
        f.write('|}\n\n\n')

        # Table 3 header
        f.write('{| class="wikitable sortable" style="margin: auto;" \n')
        f.write('|+ Results for scenario 2 - III: Best execution time. Encrypt 128 bits of data using CTR mode. '
                'For each cipher, an optimal implementation on each architecture is selected. \n')
        f.write('|- \n')
        f.write('! scope="col" colspan="4" rowspan="2" | Cipher Info \n')
        f.write('! scope="col" colspan="9" | Results \n')
        f.write('|- \n')
        f.write('! scope="col" colspan="3" | AVR \n')
        f.write('! scope="col" colspan="3" | MSP \n')
        f.write('! scope="col" colspan="3" | ARM \n')
        f.write('|- \n')
        f.write('! scope="col" | Cipher \n')
        f.write('! scope="col" | Block [b] \n')
        f.write('! scope="col" | Key [b] \n')
        f.write('! scope="col" | Sec. \n')
        f.write('! scope="col" | Code [B] \n')
        f.write('! scope="col" | RAM [B] \n')
        f.write('! scope="col" | Time [cyc.] \n')
        f.write('! scope="col" | Code [B] \n')
        f.write('! scope="col" | RAM [B] \n')
        f.write('! scope="col" | Time [cyc.] \n')
        f.write('! scope="col" | Code [B] \n')
        f.write('! scope="col" | RAM [B] \n')
        f.write('! scope="col" | Time [cyc.] \n')

        self.selected_ciphers.sort(key=lambda c: c.name)

        for selected_cipher in self.selected_ciphers:
            # Code size
            value = selected_cipher.avr_metrics3.code_size_e
            if avr_min_code_size > value:
                avr_min_code_size = value
            if avr_max_code_size < value:
                avr_max_code_size = value

            value = selected_cipher.msp_metrics3.code_size_e
            if msp_min_code_size > value:
                msp_min_code_size = value
            if msp_max_code_size < value:
                msp_max_code_size = value

            value = selected_cipher.arm_metrics3.code_size_e
            if arm_min_code_size > value:
                arm_min_code_size = value
            if arm_max_code_size < value:
                arm_max_code_size = value

            # RAM
            value = selected_cipher.avr_metrics3.ram_data + \
                    selected_cipher.avr_metrics3.ram_stack_e
            if avr_min_ram > value:
                avr_min_ram = value
            if avr_max_ram < value:
                avr_max_ram = value

            value = selected_cipher.msp_metrics3.ram_data + \
                    selected_cipher.msp_metrics3.ram_stack_e
            if msp_min_ram > value:
                msp_min_ram = value
            if msp_max_ram < value:
                msp_max_ram = value

            value = selected_cipher.arm_metrics3.ram_data + \
                    selected_cipher.arm_metrics3.ram_stack_e
            if arm_min_ram > value:
                arm_min_ram = value
            if arm_max_ram < value:
                arm_max_ram = value

            # Execution time
            value = selected_cipher.avr_metrics3.execution_time_e
            if avr_min_execution_time > value:
                avr_min_execution_time = value
            if avr_max_execution_time < value:
                avr_max_execution_time = value

            value = selected_cipher.msp_metrics3.execution_time_e
            if msp_min_execution_time > value:
                msp_min_execution_time = value
            if msp_max_execution_time < value:
                msp_max_execution_time = value

            value = selected_cipher.arm_metrics3.execution_time_e
            if arm_min_execution_time > value:
                arm_min_execution_time = value
            if arm_max_execution_time < value:
                arm_max_execution_time = value

        for selected_cipher in self.selected_ciphers:
            avr_value1 = selected_cipher.avr_metrics3.code_size_e
            avr_value2 = selected_cipher.avr_metrics3.ram_data + \
                         selected_cipher.avr_metrics3.ram_stack_e
            avr_value3 = selected_cipher.avr_metrics3.execution_time_e

            msp_value1 = selected_cipher.msp_metrics3.code_size_e
            msp_value2 = selected_cipher.msp_metrics3.ram_data + \
                         selected_cipher.msp_metrics3.ram_stack_e
            msp_value3 = selected_cipher.msp_metrics3.execution_time_e

            arm_value1 = selected_cipher.arm_metrics3.code_size_e
            arm_value2 = selected_cipher.arm_metrics3.ram_data + \
                         selected_cipher.arm_metrics3.ram_stack_e
            arm_value3 = selected_cipher.arm_metrics3.execution_time_e

            [avr_value1, avr_value2, avr_value3,
             msp_value1, msp_value2, msp_value3,
             arm_value1, arm_value2, arm_value3] = \
                self.generate_mediawiki_table_row_data(avr_value1, avr_value2, avr_value3,
                                                       msp_value1, msp_value2, msp_value3,
                                                       arm_value1, arm_value2, arm_value3,

                                                       avr_min_code_size,
                                                       avr_max_code_size,
                                                       msp_min_code_size,
                                                       msp_max_code_size,
                                                       arm_min_code_size,
                                                       arm_max_code_size,

                                                       avr_min_ram,
                                                       avr_max_ram,
                                                       msp_min_ram,
                                                       msp_max_ram,
                                                       arm_min_ram,
                                                       arm_max_ram,

                                                       avr_min_execution_time,
                                                       avr_max_execution_time,
                                                       msp_min_execution_time,
                                                       msp_max_execution_time,
                                                       arm_min_execution_time,
                                                       arm_max_execution_time,

                                                       selected_cipher.avr_metrics3.implementation_type,
                                                       selected_cipher.msp_metrics3.implementation_type,
                                                       selected_cipher.arm_metrics3.implementation_type)

            f.write(Constants.MEDIAWIKI_SECTION3_ROW_FORMAT.format(selected_cipher.name_link,
                                                                   selected_cipher.block_size,
                                                                   selected_cipher.key_size,
                                                                   selected_cipher.security_level,

                                                                   avr_value1,
                                                                   avr_value2,
                                                                   avr_value3,

                                                                   msp_value1,
                                                                   msp_value2,
                                                                   msp_value3,

                                                                   arm_value1,
                                                                   arm_value2,
                                                                   arm_value3,

                                                                   selected_cipher.avr_version3,
                                                                   selected_cipher.avr_compiler_options3,
                                                                   selected_cipher.msp_version3,
                                                                   selected_cipher.msp_compiler_options3,
                                                                   selected_cipher.arm_version3,
                                                                   selected_cipher.arm_compiler_options3))

        # Table 3 footer
        f.write('|}\n\n\n')

        f.close()

        if Constants.DEBUG_ON == Constants.DEBUG:
            print(Constants.DONE)

    def generate_gnuplot_dat_file(self):
        """
        Generate Gnuplot dat table

        """

        self.selected_ciphers.sort(key=lambda c: c.fom1)

        f = open(Constants.RESULT_GNUPLOT_FOM_DAT_FILE_PATH, Constants.RESULT_FILE_ACCESS_MODE)

        # File header
        f.write('# Cipher Block[b] Key[b] ')
        f.write('AVR_Code[B] AVR_RAM[B] AVR_Time[cyc.] ')
        f.write('MSP_Code[B] MSP_RAM[B] MSP_Time[cyc.] ')
        f.write('ARM_Code[B] ARM_RAM[B] ARM_Time[cyc.] ')
        f.write('FOM')
        f.write('\n')

        for selected_cipher in self.selected_ciphers:
            avr_value1 = selected_cipher.avr_metrics1.code_size_e
            avr_value2 = selected_cipher.avr_metrics1.ram_data + \
                         selected_cipher.avr_metrics1.ram_stack_e
            avr_value3 = selected_cipher.avr_metrics1.execution_time_e

            msp_value1 = selected_cipher.msp_metrics1.code_size_e
            msp_value2 = selected_cipher.msp_metrics1.ram_data + \
                         selected_cipher.msp_metrics1.ram_stack_e
            msp_value3 = selected_cipher.msp_metrics1.execution_time_e

            arm_value1 = selected_cipher.arm_metrics1.code_size_e
            arm_value2 = selected_cipher.arm_metrics1.ram_data + \
                         selected_cipher.arm_metrics1.ram_stack_e
            arm_value3 = selected_cipher.arm_metrics1.execution_time_e

            f.write(Constants.GNUPLOT_DAT_ROW_FORMAT.format(selected_cipher.name,
                                                            selected_cipher.block_size,
                                                            selected_cipher.key_size,

                                                            avr_value1,
                                                            avr_value2,
                                                            avr_value3,

                                                            msp_value1,
                                                            msp_value2,
                                                            msp_value3,

                                                            arm_value1,
                                                            arm_value2,
                                                            arm_value3,

                                                            round(selected_cipher.fom1, Constants.GNUPLOT_ROUND_FOM)))

        f.close()

        self.selected_ciphers.sort(key=lambda c: c.name)

        f = open(Constants.RESULT_GNUPLOT_NAME_DAT_FILE_PATH, Constants.RESULT_FILE_ACCESS_MODE)

        # File header
        f.write('# Cipher Block[b] Key[b] ')
        f.write('AVR_Code[B] AVR_RAM[B] AVR_Time[cyc.] ')
        f.write('MSP_Code[B] MSP_RAM[B] MSP_Time[cyc.] ')
        f.write('ARM_Code[B] ARM_RAM[B] ARM_Time[cyc.] ')
        f.write('FOM')
        f.write('\n')

        for selected_cipher in self.selected_ciphers:
            avr_value1 = selected_cipher.avr_metrics1.code_size_e
            avr_value2 = selected_cipher.avr_metrics1.ram_data + \
                         selected_cipher.avr_metrics1.ram_stack_e
            avr_value3 = selected_cipher.avr_metrics1.execution_time_e

            msp_value1 = selected_cipher.msp_metrics1.code_size_e
            msp_value2 = selected_cipher.msp_metrics1.ram_data + \
                         selected_cipher.msp_metrics1.ram_stack_e
            msp_value3 = selected_cipher.msp_metrics1.execution_time_e

            arm_value1 = selected_cipher.arm_metrics1.code_size_e
            arm_value2 = selected_cipher.arm_metrics1.ram_data + \
                         selected_cipher.arm_metrics1.ram_stack_e
            arm_value3 = selected_cipher.arm_metrics1.execution_time_e

            f.write(Constants.GNUPLOT_DAT_ROW_FORMAT.format(selected_cipher.name,
                                                            selected_cipher.block_size,
                                                            selected_cipher.key_size,

                                                            avr_value1,
                                                            avr_value2,
                                                            avr_value3,

                                                            msp_value1,
                                                            msp_value2,
                                                            msp_value3,

                                                            arm_value1,
                                                            arm_value2,
                                                            arm_value3,

                                                            round(selected_cipher.fom1, Constants.GNUPLOT_ROUND_FOM)))

        f.close()

        if Constants.DEBUG_ON == Constants.DEBUG:
            print(Constants.DONE)

    def generate_statistics_csv_file(self):
        """
        Generate statistics file

        """

        statistics = Statistics()

        self.selected_ciphers.sort(key=lambda c: c.fom1)

        position = 0

        for selected_cipher in self.selected_ciphers:
            position += 1

            statistics.add_fom_table_entry(selected_cipher.name, selected_cipher.block_size, selected_cipher.key_size,
                                     selected_cipher.avr_version1, position)
            statistics.add_fom_table_entry(selected_cipher.name, selected_cipher.block_size, selected_cipher.key_size,
                                     selected_cipher.msp_version1, position)
            statistics.add_fom_table_entry(selected_cipher.name, selected_cipher.block_size, selected_cipher.key_size,
                                     selected_cipher.arm_version1, position)

        self.selected_ciphers.sort(key=lambda c: c.fom2)

        for selected_cipher in self.selected_ciphers:
            statistics.add_small_code_size_and_ram_table_entry(selected_cipher.name, selected_cipher.block_size,
                                                               selected_cipher.key_size, selected_cipher.avr_version2)
            statistics.add_small_code_size_and_ram_table_entry(selected_cipher.name, selected_cipher.block_size,
                                                               selected_cipher.key_size, selected_cipher.msp_version2)
            statistics.add_small_code_size_and_ram_table_entry(selected_cipher.name, selected_cipher.block_size,
                                                               selected_cipher.key_size, selected_cipher.arm_version2)

        self.selected_ciphers.sort(key=lambda c: c.fom3)

        for selected_cipher in self.selected_ciphers:
            statistics.add_best_execution_table_entry(selected_cipher.name, selected_cipher.block_size,
                                                      selected_cipher.key_size, selected_cipher.avr_version3)
            statistics.add_best_execution_table_entry(selected_cipher.name, selected_cipher.block_size,
                                                      selected_cipher.key_size, selected_cipher.msp_version3)
            statistics.add_best_execution_table_entry(selected_cipher.name, selected_cipher.block_size,
                                                      selected_cipher.key_size, selected_cipher.arm_version3)

        statistics.generate_csv_file()
