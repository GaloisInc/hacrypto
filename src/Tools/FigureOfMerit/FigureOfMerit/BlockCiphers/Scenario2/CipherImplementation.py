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


from Scenario2.CipherImplementationMetrics import CipherImplementationMetrics
from Scenario2 import Constants


__author__ = 'daniel.dinu'


class CipherImplementation:
    def __init__(self, name, block_size, key_size, version, compiler_options):
        """
        Initialize cipher implementation
        :param name: Cipher name
        :param block_size: Cipher block size
        :param key_size: Cipher key size
        :param version: Cipher implementation version
        :param compiler_options: Cipher implementation compiler options
        """

        self.name = name

        self.block_size = block_size
        self.key_size = key_size

        self.version = version
        self.compiler_options = compiler_options

        self.avr_metrics = CipherImplementationMetrics()
        self.msp_metrics = CipherImplementationMetrics()
        self.arm_metrics = CipherImplementationMetrics()

        self.fom1_avr = 0
        self.fom1_msp = 0
        self.fom1_arm = 0

        self.fom2_avr = 0
        self.fom2_msp = 0
        self.fom2_arm = 0

        self.fom3_avr = 0
        self.fom3_msp = 0
        self.fom3_arm = 0

    def add_metrics(self, architecture, metrics):
        """
        Add cipher implementation metrics
        :param architecture: Cipher implementation architecture
        :param metrics: Cipher implementation metrics
        """

        if Constants.ARCHITECTURE_AVR == architecture:
            self.avr_metrics = metrics

        if Constants.ARCHITECTURE_MSP == architecture:
            self.msp_metrics = metrics

        if Constants.ARCHITECTURE_ARM == architecture:
            self.arm_metrics = metrics

    def compute_fom(self,

                    avr_min_code_size,
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
                    arm_max_execution_time):

        """
        Compute cipher implementation FOM 1, FOM 2 and FOM 3
        :param avr_min_code_size: AVR min code size
        :param msp_min_code_size:  MSP min code size
        :param arm_min_code_size: ARM min code size
        :param avr_min_ram: AVR min RAM
        :param msp_min_ram: MSP min RAM
        :param arm_min_ram: ARM min RAM
        :param avr_min_execution_time: AVR min execution time
        :param msp_min_execution_time: MSP min execution time
        :param arm_min_execution_time: ARM min execution time
        :param avr_max_code_size: AVR max code size
        :param msp_max_code_size: MSP max code size
        :param arm_max_code_size: ARM max code size
        :param avr_max_ram: AVR max RAM
        :param msp_max_ram: MSP max RAM
        :param arm_max_ram: ARM max RAM
        :param avr_max_execution_time: AVR max execution time
        :param msp_max_execution_time: MSP max execution time
        :param arm_max_execution_time: ARM max execution time
        """

        # AVR
        avr_code_size = self.avr_metrics.code_size_e
        avr_ram = self.avr_metrics.ram_data + self.avr_metrics.ram_stack_e
        avr_execution_time = self.avr_metrics.execution_time_e

        # MSP
        msp_code_size = self.msp_metrics.code_size_e
        msp_ram = self.msp_metrics.ram_data + self.msp_metrics.ram_stack_e
        msp_execution_time = self.msp_metrics.execution_time_e

        # ARM
        arm_code_size = self.arm_metrics.code_size_e
        arm_ram = self.arm_metrics.ram_data + self.arm_metrics.ram_stack_e
        arm_execution_time = self.arm_metrics.execution_time_e

        # AVR weights
        avr_code_size_weight = Constants.FOM1_AVR_CODE_SIZE_WEIGHT
        avr_ram_weight = Constants.FOM1_AVR_RAM_WEIGHT
        avr_execution_time_weight = Constants.FOM1_AVR_EXECUTION_TIME_WEIGHT

        # MSP weights
        msp_code_size_weight = Constants.FOM1_MSP_CODE_SIZE_WEIGHT
        msp_ram_weight = Constants.FOM1_MSP_RAM_WEIGHT
        msp_execution_time_weight = Constants.FOM1_MSP_EXECUTION_TIME_WEIGHT

        # ARM weights
        arm_code_size_weight = Constants.FOM1_ARM_CODE_SIZE_WEIGHT
        arm_ram_weight = Constants.FOM1_ARM_RAM_WEIGHT
        arm_execution_time_weight = Constants.FOM1_ARM_EXECUTION_TIME_WEIGHT

        # AVR
        avr_fom_code_size = avr_code_size_weight * (avr_code_size / avr_min_code_size)
        avr_fom_ram = avr_ram_weight * (avr_ram / avr_min_ram)
        avr_fom_execution_time = avr_execution_time_weight * (avr_execution_time / avr_min_execution_time)
        avr_fom = avr_fom_code_size + avr_fom_ram + avr_fom_execution_time

        # MSP
        msp_fom_code_size = msp_code_size_weight * (msp_code_size / msp_min_code_size)
        msp_fom_ram = msp_ram_weight * (msp_ram / msp_min_ram)
        msp_fom_execution_time = msp_execution_time_weight * (msp_execution_time / msp_min_execution_time)
        msp_fom = msp_fom_code_size + msp_fom_ram + msp_fom_execution_time

        # ARM
        arm_fom_code_size = arm_code_size_weight * (arm_code_size / arm_min_code_size)
        arm_fom_ram = arm_ram_weight * (arm_ram / arm_min_ram)
        arm_fom_execution_time = arm_execution_time_weight * (arm_execution_time / arm_min_execution_time)
        arm_fom = arm_fom_code_size + arm_fom_ram + arm_fom_execution_time

        if Constants.DEBUG_ON == Constants.DEBUG:
            print(Constants.CIPHER_IMPLEMENTATION_FOM1_DETAILS.format(avr_fom_code_size,
                                                                      avr_fom_ram,
                                                                      avr_fom_execution_time,
                                                                      avr_fom,

                                                                      msp_fom_code_size,
                                                                      msp_fom_ram,
                                                                      msp_fom_execution_time,
                                                                      msp_fom,

                                                                      arm_fom_code_size,
                                                                      arm_fom_ram,
                                                                      arm_fom_execution_time,
                                                                      arm_fom))

        # FOM 1
        self.fom1_avr = avr_fom
        self.fom1_msp = msp_fom
        self.fom1_arm = arm_fom

        # AVR weights
        avr_code_size_weight = Constants.FOM2_AVR_CODE_SIZE_WEIGHT
        avr_ram_weight = Constants.FOM2_AVR_RAM_WEIGHT
        avr_execution_time_weight = Constants.FOM2_AVR_EXECUTION_TIME_WEIGHT

        # MSP weights
        msp_code_size_weight = Constants.FOM2_MSP_CODE_SIZE_WEIGHT
        msp_ram_weight = Constants.FOM2_MSP_RAM_WEIGHT
        msp_execution_time_weight = Constants.FOM2_MSP_EXECUTION_TIME_WEIGHT

        # ARM weights
        arm_code_size_weight = Constants.FOM2_ARM_CODE_SIZE_WEIGHT
        arm_ram_weight = Constants.FOM2_ARM_RAM_WEIGHT
        arm_execution_time_weight = Constants.FOM2_ARM_EXECUTION_TIME_WEIGHT

        # AVR
        avr_fom_code_size = avr_code_size_weight * (avr_code_size / Constants.AVR_MAX_ROM)
        avr_fom_ram = avr_ram_weight * (avr_ram / Constants.AVR_MAX_RAM)
        avr_fom_execution_time = avr_execution_time_weight
        avr_fom = avr_fom_code_size + avr_fom_ram + avr_fom_execution_time

        # MSP
        msp_fom_code_size = msp_code_size_weight * (msp_code_size / Constants.MSP_MAX_ROM)
        msp_fom_ram = msp_ram_weight * (msp_ram / Constants.MSP_MAX_RAM)
        msp_fom_execution_time = msp_execution_time_weight
        msp_fom = msp_fom_code_size + msp_fom_ram + msp_fom_execution_time

        # ARM
        arm_fom_code_size = arm_code_size_weight * (arm_code_size / Constants.ARM_MAX_ROM)
        arm_fom_ram = arm_ram_weight * (arm_ram / Constants.ARM_MAX_RAM)
        arm_fom_execution_time = arm_execution_time_weight
        arm_fom = arm_fom_code_size + arm_fom_ram + arm_fom_execution_time

        if Constants.DEBUG_ON == Constants.DEBUG:
            print(Constants.CIPHER_IMPLEMENTATION_FOM2_DETAILS.format(avr_fom_code_size,
                                                                      avr_fom_ram,
                                                                      avr_fom_execution_time,
                                                                      avr_fom,

                                                                      msp_fom_code_size,
                                                                      msp_fom_ram,
                                                                      msp_fom_execution_time,
                                                                      msp_fom,

                                                                      arm_fom_code_size,
                                                                      arm_fom_ram,
                                                                      arm_fom_execution_time,
                                                                      arm_fom))

        # FOM 2
        self.fom2_avr = avr_fom
        self.fom2_msp = msp_fom
        self.fom2_arm = arm_fom

        # AVR weights
        avr_code_size_weight = Constants.FOM3_AVR_CODE_SIZE_WEIGHT
        avr_ram_weight = Constants.FOM3_AVR_RAM_WEIGHT
        avr_execution_time_weight = Constants.FOM3_AVR_EXECUTION_TIME_WEIGHT

        # MSP weights
        msp_code_size_weight = Constants.FOM3_MSP_CODE_SIZE_WEIGHT
        msp_ram_weight = Constants.FOM3_MSP_RAM_WEIGHT
        msp_execution_time_weight = Constants.FOM3_MSP_EXECUTION_TIME_WEIGHT

        # ARM weights
        arm_code_size_weight = Constants.FOM3_ARM_CODE_SIZE_WEIGHT
        arm_ram_weight = Constants.FOM3_ARM_RAM_WEIGHT
        arm_execution_time_weight = Constants.FOM3_ARM_EXECUTION_TIME_WEIGHT

        # AVR
        avr_fom_code_size = avr_code_size_weight
        avr_fom_ram = avr_ram_weight
        avr_fom_execution_time = avr_execution_time_weight * (avr_execution_time / avr_min_execution_time)
        avr_fom = avr_fom_code_size + avr_fom_ram + avr_fom_execution_time

        # MSP
        msp_fom_code_size = msp_code_size_weight
        msp_fom_ram = msp_ram_weight
        msp_fom_execution_time = msp_execution_time_weight * (msp_execution_time / msp_min_execution_time)
        msp_fom = msp_fom_code_size + msp_fom_ram + msp_fom_execution_time

        # ARM
        arm_fom_code_size = arm_code_size_weight
        arm_fom_ram = arm_ram_weight
        arm_fom_execution_time = arm_execution_time_weight * (arm_execution_time / arm_min_execution_time)
        arm_fom = arm_fom_code_size + arm_fom_ram + arm_fom_execution_time

        if Constants.DEBUG_ON == Constants.DEBUG:
            print(Constants.CIPHER_IMPLEMENTATION_FOM3_DETAILS.format(avr_fom_code_size,
                                                                      avr_fom_ram,
                                                                      avr_fom_execution_time,
                                                                      avr_fom,

                                                                      msp_fom_code_size,
                                                                      msp_fom_ram,
                                                                      msp_fom_execution_time,
                                                                      msp_fom,

                                                                      arm_fom_code_size,
                                                                      arm_fom_ram,
                                                                      arm_fom_execution_time,
                                                                      arm_fom))

        # FOM 3
        self.fom3_avr = avr_fom
        self.fom3_msp = msp_fom
        self.fom3_arm = arm_fom
