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


from Scenario1.CipherImplementationMetrics import CipherImplementationMetrics
from Scenario1 import Constants


from Scenario1 import Constants


__author__ = 'daniel.dinu'


class CipherImplementation:
    def __init__(self, name, state_size, key_size, iv_size, version, compiler_options):
        """
        Initialize cipher implementation
        :param name: Cipher name
        :param state_size: Cipher state size
        :param key_size: Cipher key size
        :param iv_size: Cipher IV size
        :param version: Cipher implementation version
        :param compiler_options: Cipher implementation compiler options
        """

        self.name = name

        self.state_size = state_size
        self.key_size = key_size
        self.iv_size = iv_size

        self.version = version
        self.compiler_options = compiler_options

        self.avr_metrics = CipherImplementationMetrics()
        self.msp_metrics = CipherImplementationMetrics()
        self.arm_metrics = CipherImplementationMetrics()

        self.fom_avr = 0
        self.fom_msp = 0
        self.fom_arm = 0

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
        Compute cipher implementation FOM
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

        #AVR
        avr_code_size = self.avr_metrics.code_size_total
        avr_ram = self.avr_metrics.ram_data_total + max([self.avr_metrics.ram_stack_s, self.avr_metrics.ram_stack_e])
        avr_execution_time = self.avr_metrics.execution_time_s + self.avr_metrics.execution_time_e

        # MSP
        msp_code_size = self.msp_metrics.code_size_total
        msp_ram = self.msp_metrics.ram_data_total + max([self.msp_metrics.ram_stack_s, self.msp_metrics.ram_stack_e])
        msp_execution_time = self.msp_metrics.execution_time_s + self.msp_metrics.execution_time_e

        # ARM
        arm_code_size = self.arm_metrics.code_size_total
        arm_ram = self.arm_metrics.ram_data_total + max([self.arm_metrics.ram_stack_s, self.arm_metrics.ram_stack_e])
        arm_execution_time = self.arm_metrics.execution_time_s + self.arm_metrics.execution_time_e

        # AVR weights
        avr_code_size_weight = Constants.FOM_AVR_CODE_SIZE_WEIGHT
        avr_ram_weight = Constants.FOM_AVR_RAM_WEIGHT
        avr_execution_time_weight = Constants.FOM_AVR_EXECUTION_TIME_WEIGHT

        # MSP weights
        msp_code_size_weight = Constants.FOM_MSP_CODE_SIZE_WEIGHT
        msp_ram_weight = Constants.FOM_MSP_RAM_WEIGHT
        msp_execution_time_weight = Constants.FOM_MSP_EXECUTION_TIME_WEIGHT

        # ARM weights
        arm_code_size_weight = Constants.FOM_ARM_CODE_SIZE_WEIGHT
        arm_ram_weight = Constants.FOM_ARM_RAM_WEIGHT
        arm_execution_time_weight = Constants.FOM_ARM_EXECUTION_TIME_WEIGHT

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
            print(Constants.CIPHER_IMPLEMENTATION_FOM_DETAILS.format(avr_fom_code_size,
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
            print(Constants.CIPHER_IMPLEMENTATION_FOM_INFO.format(avr_fom, msp_fom, arm_fom))

        self.fom_avr = avr_fom
        self.fom_msp = msp_fom
        self.fom_arm = arm_fom
