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

from CiphersInfo.CipherInfo import CipherInfo
from CiphersInfo import Constants


__author__ = 'daniel.dinu'


class CiphersInfo:
    def __init__(self):
        """
        Initialize ciphers info

        """

        self.ciphers_info = []

        with open(Constants.CIPHER_INFO_CSV_FILE_PATH) as csv_file:
            reader = csv.reader(csv_file, delimiter=Constants.CSV_DELIMITER, quotechar=Constants.CSV_QUOTECHAR)

            count = 0
            for row in reader:
                count += 1

                if Constants.CSV_HEADER_LINES >= count:
                    continue

                name = row[Constants.CIPHER_NAME_COLUMN_INDEX]
                block_size = int(row[Constants.BLOCK_SIZE_COLUMN_INDEX])
                key_size = int(row[Constants.KEY_SIZE_COLUMN_INDEX])

                link = row[Constants.LINK_COLUMN_INDEX]
                security_level = row[Constants.SECURITY_LEVEL_COLUMN_INDEX]

                cipher_info = CipherInfo(name, block_size, key_size, link, security_level)
                self.ciphers_info.append(cipher_info)

    def get_info(self, name, block_size, key_size):
        """
        Get the cipher info by given characteristics
        :param name: Cipher name
        :param block_size: Cipher block size
        :param key_size: Cipher key size
        :return: Searched cipher info if found, else default info
        """

        for cipher_info in self.ciphers_info:
            if cipher_info.name == name and cipher_info.block_size == block_size and cipher_info.key_size == key_size:
                return [cipher_info.link, cipher_info.security_level]

        return [Constants.DEFAULT_LINK, Constants.DEFAULT_SECURITY_LEVEL]
