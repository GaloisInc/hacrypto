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

from Scenario2.CipherImplementationStatistics import CipherImplementationStatistics
from Scenario2 import Constants


__author__ = 'daniel.dinu'


class Statistics:
    def __init__(self):
        """
        Initialize statistics

        """

        self.statistics = []

    def add_fom_table_entry(self, name, block_size, key_size, implementation_version, position):
        """
        Add FOM table entry into statistics
        :param name: Cipher name
        :param block_size: Cipher block size
        :param key_size: Cipher key size
        :param implementation_version: Cipher implementation version
        :param position: Implementation position in table ordered by FOM

        """

        for statistic in self.statistics:
            if statistic.name == name and statistic.block_size == block_size and statistic.key_size == key_size and \
                            statistic.implementation_version == implementation_version:
                statistic.fom_table_entries += 1
                return

        cipher_implementation_statistics = CipherImplementationStatistics(name, block_size, key_size,
                                                                          implementation_version, position)
        cipher_implementation_statistics.fom_table_entries += 1
        self.statistics.append(cipher_implementation_statistics)

    def add_small_code_size_and_ram_table_entry(self, name, block_size, key_size, implementation_version):
        """
        Add Small code size and RAM table entry into statistics
        :param name: Cipher name
        :param block_size: Cipher block size
        :param key_size: Cipher key size
        :param implementation_version: Cipher implementation version

        """

        for statistic in self.statistics:
            if statistic.name == name and statistic.block_size == block_size and statistic.key_size == key_size and \
                            statistic.implementation_version == implementation_version:
                statistic.small_code_size_and_ram_table_entries += 1
                return

        cipher_implementation_statistics = CipherImplementationStatistics(name, block_size, key_size,
                                                                          implementation_version)
        cipher_implementation_statistics.small_code_size_and_ram_table_entries += 1
        self.statistics.append(cipher_implementation_statistics)

    def add_best_execution_table_entry(self, name, block_size, key_size, implementation_version):
        """
        Add Best execution time table entry into statistics
        :param name: Cipher name
        :param block_size: Cipher block size
        :param key_size: Cipher key size
        :param implementation_version: Cipher implementation version

        """

        for statistic in self.statistics:
            if statistic.name == name and statistic.block_size == block_size and statistic.key_size == key_size and \
                            statistic.implementation_version == implementation_version:
                statistic.best_execution_time_table_entries += 1
                return

        cipher_implementation_statistics = CipherImplementationStatistics(name, block_size, key_size,
                                                                          implementation_version)
        cipher_implementation_statistics.best_execution_time_table_entries += 1
        self.statistics.append(cipher_implementation_statistics)

    def generate_csv_file(self):
        """
        Generate CSV file

        """

        self.statistics.sort(key=lambda c: c.full_name)

        with open(Constants.RESULT_STATISTICS_CSV_FILE_PATH, Constants.RESULT_FILE_ACCESS_MODE) as csv_file:
            writer = csv.writer(csv_file, delimiter=Constants.CSV_DELIMITER, quotechar=Constants.CSV_QUOTECHAR,
                                quoting=csv.QUOTE_MINIMAL, lineterminator=Constants.CSV_LINETERMINATOR)

            writer.writerow(Constants.STATISTICS_CSV_HEADER_ROW)

            for statistic in self.statistics:
                writer.writerow([statistic.full_name, statistic.fom_table_position, statistic.fom_table_entries,
                                 statistic.small_code_size_and_ram_table_entries,
                                 statistic.best_execution_time_table_entries])
