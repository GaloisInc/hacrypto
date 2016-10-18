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


class CipherImplementationMetrics:
    def __init__(self,

                 implementation_type=Constants.DEFAULT_IMPLEMENTATION_TYPE,

                 code_size_eks=Constants.DEFAULT_METRIC_VALUE,
                 code_size_e=Constants.DEFAULT_METRIC_VALUE,
                 code_size_dks=Constants.DEFAULT_METRIC_VALUE,
                 code_size_d=Constants.DEFAULT_METRIC_VALUE,
                 code_size_total=Constants.DEFAULT_METRIC_VALUE,

                 ram_stack_eks=Constants.DEFAULT_METRIC_VALUE,
                 ram_stack_e=Constants.DEFAULT_METRIC_VALUE,
                 ram_stack_dks=Constants.DEFAULT_METRIC_VALUE,
                 ram_stack_d=Constants.DEFAULT_METRIC_VALUE,

                 ram_data_eks=Constants.DEFAULT_METRIC_VALUE,
                 ram_data_e=Constants.DEFAULT_METRIC_VALUE,
                 ram_data_dks=Constants.DEFAULT_METRIC_VALUE,
                 ram_data_d=Constants.DEFAULT_METRIC_VALUE,
                 ram_data_common=Constants.DEFAULT_METRIC_VALUE,
                 ram_data_total=Constants.DEFAULT_METRIC_VALUE,

                 execution_time_eks=Constants.DEFAULT_METRIC_VALUE,
                 execution_time_e=Constants.DEFAULT_METRIC_VALUE,
                 execution_time_dks=Constants.DEFAULT_METRIC_VALUE,
                 execution_time_d=Constants.DEFAULT_METRIC_VALUE):

        """
        Initialize cipher implementation metrics
        :param implementation_type: Implementation type
        :param code_size_eks: Encryption key schedule code size
        :param code_size_e: Encryption code size
        :param code_size_dks: Decryption key schedule code size
        :param code_size_d: Decryption code size
        :param code_size_total: Total code size (encryption key schedule + encryption + decryption_key_schedule +
        decryption)
        :param ram_stack_eks: Encryption key schedule stack RAM
        :param ram_stack_e: Encryption stack RAM
        :param ram_stack_dks: Decryption key schedule stack RAM
        :param ram_stack_d: Decryption stack RAM
        :param ram_data_eks: Encryption key schedule data RAM
        :param ram_data_e: Encryption data RAM
        :param ram_data_dks: Decryption key schedule data RAM
        :param ram_data_d: Decryption data RAM
        :param ram_data_common: Common data RAM
        :param ram_data_total: Total data RAM
        :param execution_time_eks: Encryption key schedule execution time
        :param execution_time_e: Encryption execution time
        :param execution_time_dks: Decryption key schedule execution time
        :param execution_time_d: Decryption execution time
        """

        self.implementation_type = implementation_type

        self.code_size_eks = code_size_eks
        self.code_size_e = code_size_e
        self.code_size_dks = code_size_dks
        self.code_size_d = code_size_d
        self.code_size_total = code_size_total

        self.ram_stack_eks = ram_stack_eks
        self.ram_stack_e = ram_stack_e
        self.ram_stack_dks = ram_stack_dks
        self.ram_stack_d = ram_stack_d

        self.ram_data_eks = ram_data_eks
        self.ram_data_e = ram_data_e
        self.ram_data_dks = ram_data_dks
        self.ram_data_d = ram_data_d
        self.ram_data_common = ram_data_common
        self.ram_data_total = ram_data_total

        self.execution_time_eks = execution_time_eks
        self.execution_time_e = execution_time_e
        self.execution_time_dks = execution_time_dks
        self.execution_time_d = execution_time_d
