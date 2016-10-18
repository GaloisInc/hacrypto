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


from Scenario1 import Constants


__author__ = 'daniel.dinu'


class SelectedCipher:
    def __init__(self, name, block_size, key_size, link, security_level):
        """
        Initialize selected cipher
        :param name: Selected cipher name
        :param block_size: Selected cipher block size
        :param key_size: Selected cipher key size
        :param link: Selected cipher link
        :param security_level: Selected cipher security level
        """

        self.name = name
        self.block_size = block_size
        self.key_size = key_size

        self.link = link
        self.security_level = security_level

        self.name_link = Constants.MEDIAWIKI_CIPHER_NAME_FORMAT.format(self.link, self.name)

        self.avr_metrics = ''
        self.msp_metrics = ''
        self.arm_metrics = ''

        self.avr_version = 0
        self.msp_version = 0
        self.arm_version = 0

        self.avr_compiler_options = ''
        self.msp_compiler_options = ''
        self.arm_compiler_options = ''

        self.fom_avr = 0
        self.fom_msp = 0
        self.fom_arm = 0

        self.fom = 0

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
        Compute selected cipher FOM
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
        avr_ram = self.avr_metrics.ram_data_total + max([self.avr_metrics.ram_stack_eks,
                                                         self.avr_metrics.ram_stack_e,
                                                         self.avr_metrics.ram_stack_dks,
                                                         self.avr_metrics.ram_stack_d])
        avr_execution_time = self.avr_metrics.execution_time_eks + self.avr_metrics.execution_time_e + \
                             self.avr_metrics.execution_time_dks + self.avr_metrics.execution_time_d

        # MSP
        msp_code_size = self.msp_metrics.code_size_total
        msp_ram = self.msp_metrics.ram_data_total + max([self.msp_metrics.ram_stack_eks,
                                                         self.msp_metrics.ram_stack_e,
                                                         self.msp_metrics.ram_stack_dks,
                                                         self.msp_metrics.ram_stack_d])
        msp_execution_time = self.msp_metrics.execution_time_eks + self.msp_metrics.execution_time_e + \
                             self.msp_metrics.execution_time_dks + self.msp_metrics.execution_time_d

        # ARM
        arm_code_size = self.arm_metrics.code_size_total
        arm_ram = self.arm_metrics.ram_data_total + max([self.arm_metrics.ram_stack_eks,
                                                   self.arm_metrics.ram_stack_e,
                                                   self.arm_metrics.ram_stack_dks,
                                                   self.arm_metrics.ram_stack_d])
        arm_execution_time = self.arm_metrics.execution_time_eks + self.arm_metrics.execution_time_e + \
                             self.arm_metrics.execution_time_dks + self.arm_metrics.execution_time_d

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
