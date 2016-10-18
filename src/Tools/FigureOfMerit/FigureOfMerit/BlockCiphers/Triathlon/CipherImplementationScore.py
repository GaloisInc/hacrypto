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


from Triathlon import Constants


__author__ = 'daniel.dinu'


class CipherImplementationScore:
    def __init__(self, full_name, submission_date, b1_count, b2_count, b3_count, b4_count, b5_count):
        """
        Initialize cipher implementation score
        :param full_name: Implementation full name
        :param submission_date: Submission date
        :param b1_count: Rule B1 count
        :param b2_count: Rule B2 count
        :param b3_count: Rule B3 count
        :param b4_count: Rule B4 count
        :param b5_count: Rule B5 count
        """

        self.full_name = full_name
        self.implementers = ''
        self.submission_date = submission_date

        self.b1_count = b1_count
        self.b2_count = b2_count
        self.b3_count = b3_count
        self.b4_count = b4_count
        self.b5_count = b5_count

        self.p1_position = 0
        self.p1_entries = 0

        self.p2_position = 0
        self.p2_entries = 0

        self.p3_entries = 0
        self.p4_entries = 0

        self.p1_score = 0
        self.p2_score = 0
        self.p3_score = 0
        self.p4_score = 0

        self.b1_score = 0
        self.b2_score = 0
        self.b3_score = 0
        self.b4_score = 0
        self.b5_score = 0

        self.total = 0

    def compute_score(self, n1, n2):
        """
        Compute implementation score
        :param n1: The number of entries in table for Scenario 1 ordered by FOM
        :param n2: The number of entries in table for Scenario 2 ordered by FOM
        """

        self.p1_score = Constants.P1_WEIGHT * (n1 + 1 - self.p1_position) * self.p1_entries
        self.p2_score = Constants.P2_WEIGHT * (n2 + 1 - self.p2_position) * self.p2_entries
        self.p3_score = Constants.P3_WEIGHT * self.p3_entries
        self.p4_score = Constants.P4_WEIGHT * self.p4_entries

        self.b1_score = Constants.B1_WEIGHT * self.b1_count
        self.b2_score = Constants.B2_WEIGHT * self.b2_count
        self.b3_score = Constants.B3_WEIGHT * self.b3_count
        self.b4_score = Constants.B4_WEIGHT * self.b4_count
        self.b5_score = Constants.B5_WEIGHT * self.b5_count

        self.total = self.p1_score + self.p2_score + self.p3_score + self.p4_score + \
                     self.b1_score + self.b2_score + self.b3_score + self.b4_score + self.b5_score
