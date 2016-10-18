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


from Utils import Utils


__author__ = 'daniel.dinu'


'''
    Scenario 1
'''
Utils.compute_scenario1_fom()
print('\n')


'''
    Scenario 2
'''
Utils.compute_scenario2_fom()
print('\n')


'''
    Generate MediaWiki file
'''
Utils.generate_mediawiki_page()
print('\n')


'''
    Generate Triathlon Results MediaWiki file
'''
Utils.generate_triathlon_mediawiki_page()
print('\n')
