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

from Triathlon.CipherImplementationScore import CipherImplementationScore
from Triathlon.PlayerScore import PlayerScore
from Triathlon import Constants


__author__ = 'daniel.dinu'


class Score:
    def __init__(self):
        """
        Initialize the score
        """

        self.implementations_scores = []

        self.n1 = 0
        self.n2 = 0

    def load_competitors(self):
        """
        Load competing ciphers
        """

        with open(Constants.TRIATHLON_COMPETITORS_CSV_FILE) as csv_file:
            reader = csv.reader(csv_file, delimiter=Constants.CSV_DELIMITER, quotechar=Constants.CSV_QUOTECHAR)

            count = 0
            for row in reader:
                count += 1

                if Constants.TRIATHLON_COMPETITORS_CSV_HEADER_LINES >= count:
                    continue

                full_name = row[Constants.TRIATHLON_COMPETITORS_FULL_NAME_COLUMN_INDEX]
                submission_date = row[Constants.TRIATHLON_COMPETITORS_SUBMISSION_DATE_COLUMN_INDEX]
                b1_count = int(row[Constants.TRIATHLON_COMPETITORS_B1_COUNT_COLUMN_INDEX])
                b2_count = int(row[Constants.TRIATHLON_COMPETITORS_B2_COUNT_COLUMN_INDEX])
                b3_count = int(row[Constants.TRIATHLON_COMPETITORS_B3_COUNT_COLUMN_INDEX])
                b4_count = int(row[Constants.TRIATHLON_COMPETITORS_B4_COUNT_COLUMN_INDEX])
                b5_count = int(row[Constants.TRIATHLON_COMPETITORS_B5_COUNT_COLUMN_INDEX])

                cipher_implementation_score = CipherImplementationScore(full_name, submission_date, b1_count,
                                                                        b2_count, b3_count, b4_count, b5_count)
                self.implementations_scores.append(cipher_implementation_score)

    def load_implementation_info(self):
        """
        Load implementation info
        """

        implementation_info_csv_file = Constants.IMPLEMENTATIONS_INFO_CSV_FILE_PATH_FORMAT.format(
            Constants.IMPLEMENTATIONS_INFO_CSV_FILE_PREFIX)
        with open(implementation_info_csv_file) as csv_file:
            reader = csv.reader(csv_file, delimiter=Constants.CSV_DELIMITER, quotechar=Constants.CSV_QUOTECHAR)

            count = 0
            for row in reader:
                count += 1

                if Constants.IMPLEMENTATIONS_INFO_CSV_HEADER_LINES >= count:
                    continue

                name = row[Constants.IMPLEMENTATIONS_INFO_CIPHER_NAME_COLUMN_INDEX]
                block_size = int(row[Constants.IMPLEMENTATIONS_INFO_BLOCK_SIZE_COLUMN_INDEX])
                key_size = int(row[Constants.IMPLEMENTATIONS_INFO_KEY_SIZE_COLUMN_INDEX])
                implementation_version = row[Constants.IMPLEMENTATIONS_INFO_IMPLEMENTATION_VERSION_COLUMN_INDEX]
                implementation_description = row[Constants.IMPLEMENTATIONS_INFO_IMPLEMENTATION_DESCRIPTION_COLUMN_INDEX]
                implementers = row[Constants.IMPLEMENTATIONS_INFO_IMPLEMENTERS_COLUMN_INDEX]

                full_name = Constants.IMPLEMENTATION_FULL_NAME_FORMAT.format(name, block_size, key_size,
                                                                             implementation_version)

                implementers = implementers.replace(Constants.IMPLEMENTERS_INITIAL_SEPARATOR2,
                                                    Constants.IMPLEMENTERS_INITIAL_SEPARATOR1)
                implementers = implementers.split(Constants.IMPLEMENTERS_INITIAL_SEPARATOR1)
                implementers[:] = [implementer.strip() for implementer in implementers]
                implementers.sort()
                implementers = Constants.IMPLEMENTERS_SEPARATOR.join(implementers)

                self.add_implementers(full_name, implementers)

    def load_scenario1_statistics(self):
        """
        Load Scenario 1 statistics
        """

        with open(Constants.SCENARIO1_STATISTICS_CSV_FILE) as csv_file:
            reader = csv.reader(csv_file, delimiter=Constants.CSV_DELIMITER, quotechar=Constants.CSV_QUOTECHAR)

            count = 0
            for row in reader:
                count += 1

                if Constants.SCENARIO1_STATISTICS_CSV_HEADER_LINES >= count:
                    continue

                full_name = row[Constants.SCENARIO1_STATISTICS_FULL_NAME_COLUMN_INDEX]

                p1_position = int(row[Constants.SCENARIO1_STATISTICS_P1_POSITION_COLUMN_INDEX])
                p1_entries = int(row[Constants.SCENARIO1_STATISTICS_P1_ENTRIES_COLUMN_INDEX])

                self.add_scenario1_statistics(full_name, p1_position, p1_entries)

                if p1_position > self.n1:
                    self.n1 = p1_position

    def load_scenario2_statistics(self):
        """
        Load Scenario2 statistics
        """

        with open(Constants.SCENARIO2_STATISTICS_CSV_FILE) as csv_file:
            reader = csv.reader(csv_file, delimiter=Constants.CSV_DELIMITER, quotechar=Constants.CSV_QUOTECHAR)

            count = 0
            for row in reader:
                count += 1

                if Constants.SCENARIO2_STATISTICS_CSV_HEADER_LINES >= count:
                    continue

                full_name = row[Constants.SCENARIO2_STATISTICS_FULL_NAME_COLUMN_INDEX]

                p2_position = int(row[Constants.SCENARIO2_STATISTICS_P2_POSITION_COLUMN_INDEX])
                p2_entries = int(row[Constants.SCENARIO2_STATISTICS_P2_ENTRIES_COLUMN_INDEX])

                p3_entries = int(row[Constants.SCENARIO2_STATISTICS_P3_ENTRIES_COLUMN_INDEX])
                p4_entries = int(row[Constants.SCENARIO2_STATISTICS_P4_ENTRIES_COLUMN_INDEX])

                self.add_scenario2_statistics(full_name, p2_position, p2_entries, p3_entries, p4_entries)

                if p2_position > self.n2:
                    self.n2 = p2_position

    def add_implementers(self, full_name, implementers):
        """
        Add given implementers to the given implementation
        :param full_name: Implementation full name
        :param implementers: Implementers
        """

        for implementation_score in self.implementations_scores:
            if implementation_score.full_name == full_name:
                implementation_score.implementers = implementers
                break

    def add_scenario1_statistics(self, full_name, p1_position, p1_entries):
        """
        Add Scenario 1 statistics to given implementation
        :param full_name: Implementation full name
        :param p1_position: Rule P1 position
        :param p1_entries: Rule P1 entries
        """

        for implementation_score in self.implementations_scores:
            if implementation_score.full_name == full_name:
                implementation_score.p1_position = p1_position
                implementation_score.p1_entries = p1_entries
                break

    def add_scenario2_statistics(self, full_name, p2_position, p2_entries, p3_entries, p4_entries):
        """
        Add Scenario 2 statistics
        :param full_name: Implementation full name
        :param p2_position:  Rule P2 position
        :param p2_entries: Rule P2 entries
        :param p3_entries: Rule P3 entries
        :param p4_entries: Rule P4 entries
        """

        for implementation_score in self.implementations_scores:
            if implementation_score.full_name == full_name:
                implementation_score.p2_position = p2_position
                implementation_score.p2_entries = p2_entries
                implementation_score.p3_entries = p3_entries
                implementation_score.p4_entries = p4_entries
                break

    def compute_score(self):
        """
        Compute score
        """

        self.load_competitors()
        self.load_implementation_info()

        self.load_scenario1_statistics()
        self.load_scenario2_statistics()

        for implementation_score in self.implementations_scores:
            implementation_score.compute_score(self.n1, self.n2)

    def generate_players_mediawiki_table(self):
        """
        Generate MediaWiki Players table
        """

        players_score = []

        self.implementations_scores.sort(key=lambda i: i.total, reverse=True)

        for implementation_score in self.implementations_scores:
            found = False

            for player_score in players_score:
                if player_score.implementers == implementation_score.implementers:
                    player_score.score += implementation_score.total
                    found = True
                    break

            if not found:
                player_score = PlayerScore(implementation_score.implementers, implementation_score.total)
                players_score.append(player_score)

        players_score.sort(key=lambda p: p.score, reverse=True)

        f = open(Constants.TRIATHLON_RESULT_PLAYERS_MEDIAWIKI_FILE_PATH, Constants.TRIATHLON_RESULT_FILE_ACCESS_MODE)

        f.write('{| class="wikitable sortable" style="margin: auto;" \n')
        f.write('|+ Triathlon Results - Players \n')
        f.write('|- \n')
        f.write('! scope="col" | Player(s) \n')
        f.write('! scope="col" | Score \n')

        for player_score in players_score:
            f.write(Constants.TRIATHLON_PLAYERS_MEDIAWIKI_ROW_FORMAT.format(player_score.implementers,
                                                                            player_score.score))

        f.write('|}\n')
        f.close()

    def generate_implementations_mediawiki_table(self):
        """
        Generate MediaWiki Implementations table
        """

        self.implementations_scores.sort(key=lambda i: i.total, reverse=True)

        f = open(Constants.TRIATHLON_RESULT_IMPLEMENTATIONS_MEDIAWIKI_FILE_PATH,
                 Constants.TRIATHLON_RESULT_FILE_ACCESS_MODE)

        f.write('{| class="wikitable sortable" style="margin: auto;" \n')
        f.write('|+ Triathlon Results - Implementations \n')
        f.write('|- \n')
        f.write('! scope="col" | Implementation \n')
        f.write('! scope="col" | Implementer(s) \n')
        f.write('! scope="col" data-sort-type="isoDate" | Submission Date \n')
        f.write('! scope="col" | Score \n')

        for implementation_score in self.implementations_scores:
            f.write(Constants.TRIATHLON_IMPLEMENTATIONS_MEDIAWIKI_ROW_FORMAT.format(
                implementation_score.full_name, implementation_score.implementers,
                implementation_score.submission_date, implementation_score.total))

        f.write('|}\n')
        f.close()
