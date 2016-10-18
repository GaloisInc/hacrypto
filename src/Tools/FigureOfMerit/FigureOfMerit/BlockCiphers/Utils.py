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
from Scenario2.Scenario2 import Scenario2
from Scenario1.Scenario1 import Constants as Scenario1Constants
from Scenario2.Scenario2 import Constants as Scenario2Constants
from Triathlon.Score import Score
from Triathlon import Constants as TriathlonConstants


__author__ = 'daniel.dinu'


MEDIAWIKI_PAGE_FILE_PATH = 'Output/BlockCiphers.mkw'
TRIATHLON_RESULTS_MEDIAWIKI_PAGE_FILE_PATH = 'Output/TriathlonResults.mkw'

MEDIAWIKI_PAGE_FILE_ACCESS_MODE = 'w'

RESULT_FILE_ACCESS_MODE = 'r'


class Utils:
    @staticmethod
    def compute_scenario1_fom():
        """
        Compute scenario 1 FOM

        """

        print('===== Scenario 1 - begin =====')

        scenario1 = Scenario1()

        print('=== Compute FOM ===')
        scenario1.fom()

        print('=== Generate LaTeX table ===')
        scenario1.generate_latex_table()

        print('=== Generate MediaWiki table ===')
        scenario1.generate_mediawiki_table()

        print('=== Generate Gnuplot dat file ===')
        scenario1.generate_gnuplot_dat_file()

        print('=== Generate Statistics csv file ===')
        scenario1.generate_statistics_csv_file()

        print('===== Scenario 1 - end =====')

    @staticmethod
    def compute_scenario2_fom():
        """
        Compute scenario 2 FOM

        """

        print('===== Scenario 2 - begin =====')

        scenario2 = Scenario2()

        print('=== Compute FOM ===')
        scenario2.fom()

        print('=== Generate LaTeX table ===')
        scenario2.generate_latex_table()

        print('=== Generate MediaWiki table ===')
        scenario2.generate_mediawiki_table()

        print('=== Generate Gnuplot dat file ===')
        scenario2.generate_gnuplot_dat_file()

        print('=== Generate Statistics csv file ===')
        scenario2.generate_statistics_csv_file()

        print('===== Scenario 2 - end =====')

    @staticmethod
    def generate_mediawiki_page_notes():
        """
        Generate MediaWiki page notes

        """

        notes = '<span style="color: red">\'\'\'Note:\'\'\' </span>\n'
        notes += '* Block and key sizes are expressed in bits [b].\n'
        notes += '* Code size (Code) and RAM consumption (RAM) are expressed in bytes [B].\n'
        notes += '* Execution time (Time) is expressed in cycles [cyc.].\n'
        notes += '* Security level (Sec.) is the ratio of the number of rounds broken in a single key setting to the' \
                 ' total number of rounds.\n'
        notes += '* For ciphers against which there is no attack (to the best of our knowledge) the security level' \
                 ' is set to -1.\n'
        notes += '* Details about cryptographic properties of each cipher are available ' \
                 '[[Lightweight_Block_Ciphers#Summary|here]].\n'
        notes += '* Results for assembly implementations are displayed in \'\'italic\'\'.\n'
        notes += '* \'\'Cipher-r\'\' denotes the cipher \'\'Cipher\'\' with \'\'r\'\' rounds instead of the default' \
                 ' number of rounds.\n'
        notes += '\n\n'
        return notes

    @staticmethod
    def generate_mediawiki_page():
        """
        Generate MediaWiki page

        """

        print('===== Generate Mediawiki page - begin =====')
        f = open(MEDIAWIKI_PAGE_FILE_PATH, MEDIAWIKI_PAGE_FILE_ACCESS_MODE)
        g = open(Scenario1Constants.RESULT_MEDIAWIKI_FILE_PATH, RESULT_FILE_ACCESS_MODE)
        h = open(Scenario2Constants.RESULT_MEDIAWIKI_FILE_PATH, RESULT_FILE_ACCESS_MODE)

        f.write(Utils.generate_mediawiki_page_notes())

        f.write('=Scenario 1=\n')
        f.write('A description of scenario 1 can be found '
                '[[FELICS_Block_Ciphers#Scenario_1_-_Communication_Protocol|here]].\n')

        f.write('\n')
        f.write(g.read())

        f.write('=Scenario 2=\n')
        f.write('A description of scenario 2 can be found '
                '[[FELICS_Block_Ciphers#Scenario_2_-_Challenge-Handshake_Authentication_Protocol|here]].\n')

        f.write('\n')
        f.write(h.read())

        f.write(Utils.generate_mediawiki_page_notes())

        f.write('[[Category:ACRYPT]]')

        f.close()
        g.close()
        h.close()
        print('===== Generate MediaWiki page - end =====')

    @staticmethod
    def generate_triathlon_mediawiki_page():
        score = Score()
        score.compute_score()
        score.generate_implementations_mediawiki_table()
        score.generate_players_mediawiki_table()

        print('===== Generate Triathlon Results Mediawiki page - begin =====')
        f = open(TRIATHLON_RESULTS_MEDIAWIKI_PAGE_FILE_PATH, MEDIAWIKI_PAGE_FILE_ACCESS_MODE)
        g = open(TriathlonConstants.TRIATHLON_RESULT_IMPLEMENTATIONS_MEDIAWIKI_FILE_PATH, RESULT_FILE_ACCESS_MODE)
        h = open(TriathlonConstants.TRIATHLON_RESULT_PLAYERS_MEDIAWIKI_FILE_PATH, RESULT_FILE_ACCESS_MODE)

        f.write('=Implementations=\n')

        f.write('\n')
        f.write(g.read())

        f.write('=Players=\n')

        f.write('\n')
        f.write(h.read())

        f.write('[[Category:ACRYPT]]')

        f.close()
        g.close()
        h.close()
        print('===== Generate Triathlon Results MediaWiki page - end =====')
