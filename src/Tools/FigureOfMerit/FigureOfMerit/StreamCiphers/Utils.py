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


from Scenario1.Scenario1 import Scenario1
from Scenario1.Scenario1 import Constants as Scenario1Constants


__author__ = 'daniel.dinu'


MEDIAWIKI_PAGE_FILE_PATH = 'Output/StreamCiphers.mkw'
MEDIAWIKI_PAGE_FILE_ACCESS_MODE = 'w'

RESULT_FILE_ACCESS_MODE = 'r'


class Utils:
    @staticmethod
    def compute_scenario1_fom():
        print('===== Scenario 1 - begin =====')
        scenario1 = Scenario1()

        print('=== Compute FOM ===')
        scenario1.fom()

        print('=== Generate LaTeX table ===')
        scenario1.generate_latex_table()

        print('=== Generate MediaWiki table ===')
        scenario1.generate_mediawiki_table()
        print('===== Scenario 1 - end =====')

    @staticmethod
    def generate_mediawiki_page_notes():
        """
        Generate MediaWiki page notes

        """

        notes = '<span style="color: red">\'\'\'Note:\'\'\' </span>\n'
        notes += '* State, key and IV sizes are expressed in bits [b].\n'
        notes += '* Code size (Code) and RAM consumption (RAM) are expressed in bytes [B].\n'
        notes += '* Execution time (Time) is expressed in cycles [cyc.].\n'
        notes += '* Details about cryptographic properties of each cipher are available ' \
                 '[[Lightweight_Stream_Ciphers#Summary|here]].\n'
        notes += '* Results for assembly implementations are displayed in \'\'italic\'\'.\n'
        notes += '\n\n'
        return notes

    @staticmethod
    def generate_mediawiki_page():
        print('===== Generate Mediawiki page - begin =====')
        f = open(MEDIAWIKI_PAGE_FILE_PATH, MEDIAWIKI_PAGE_FILE_ACCESS_MODE)
        g = open(Scenario1Constants.RESULT_MEDIAWIKI_FILE_PATH, RESULT_FILE_ACCESS_MODE)

        f.write(Utils.generate_mediawiki_page_notes())

        f.write('=Scenario 1=\n')
        f.write('A description of scenario 1 can be found '
                '[[FELICS_Stream_Ciphers#Scenario_1_-_Communication_Protocol|here]].\n')

        f.write('\n')
        f.write(g.read())

        f.write(Utils.generate_mediawiki_page_notes())

        f.write('[[Category:ACRYPT]]')

        f.close()
        print('===== Generate MediaWiki page - end =====')
