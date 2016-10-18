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

                 code_size_s=Constants.DEFAULT_METRIC_VALUE,
                 code_size_e=Constants.DEFAULT_METRIC_VALUE,
                 code_size_total=Constants.DEFAULT_METRIC_VALUE,

                 ram_stack_s=Constants.DEFAULT_METRIC_VALUE,
                 ram_stack_e=Constants.DEFAULT_METRIC_VALUE,

                 ram_data_s=Constants.DEFAULT_METRIC_VALUE,
                 ram_data_e=Constants.DEFAULT_METRIC_VALUE,
                 ram_data_common=Constants.DEFAULT_METRIC_VALUE,
                 ram_data_total=Constants.DEFAULT_METRIC_VALUE,

                 execution_time_s=Constants.DEFAULT_METRIC_VALUE,
                 execution_time_e=Constants.DEFAULT_METRIC_VALUE):

        """
        Initialize cipher implementation metrics
        :param implementation_type: Implementation type
        :param code_size_s: Setup code size
        :param code_size_e: Encryption code size
        :param code_size_total: Total code size (setup + encryption)
        :param ram_stack_s: Setup stack RAM
        :param ram_stack_e: Encryption stack RAM
        :param ram_data_s: Setup data RAM
        :param ram_data_e: Encryption data RAM
        :param ram_data_common: Common data RAM
        :param ram_data_total: Total data RAM
        :param execution_time_s: Setup execution time
        :param execution_time_e: Encryption execution time
        """

        self.implementation_type = implementation_type

        self.code_size_s = code_size_s
        self.code_size_e = code_size_e
        self.code_size_total = code_size_total

        self.ram_stack_s = ram_stack_s
        self.ram_stack_e = ram_stack_e

        self.ram_data_s = ram_data_s
        self.ram_data_e = ram_data_e
        self.ram_data_common = ram_data_common
        self.ram_data_total = ram_data_total

        self.execution_time_s = execution_time_s
        self.execution_time_e = execution_time_e
