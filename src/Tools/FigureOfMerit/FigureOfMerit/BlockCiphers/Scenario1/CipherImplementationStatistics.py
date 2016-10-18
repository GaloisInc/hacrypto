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


class CipherImplementationStatistics:
    def __init__(self, name, block_size, key_size, implementation_version, position):
        """
        Initialize cipher implementation statistics
        :param name: Cipher name
        :param block_size: Cipher block size
        :param key_size: Cipher key size
        :param implementation_version: Cipher implementation version
        :param position: Cipher implementation position in the table order by FOM
        """

        self.name = name
        self.block_size = block_size
        self.key_size = key_size

        self.implementation_version = implementation_version

        self.full_name = Constants.IMPLEMENTATION_FULL_NAME_FORMAT.format(self.name, self.block_size, self.key_size,
                                                                          self.implementation_version)

        self.fom_table_position = position
        self.fom_table_entries = 0
