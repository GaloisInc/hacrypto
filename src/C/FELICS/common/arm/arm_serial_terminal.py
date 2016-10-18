#!/usr/bin/python

#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu> and 
# Daniel Dinu <dumitru-daniel.dinu@uni.lu>
#
# This file is part of FELICS.
#
# FELICS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# FELICS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

from __future__ import print_function
import sys
import serial

class ArmBoard(object):
	def __init__(self, device = '/dev/ttyACM0', baudrate = 115200):
		self.device = device
		self.baudrate = baudrate
		self.port = None
	
	def open(self):
		self.port = serial.Serial(
			port = self.device,
			baudrate = self.baudrate,
			bytesize = 8,
			parity = 'N',
			stopbits = 1,
			xonxoff = 0,
			rtscts = 0,
			dsrdtr = 0,
			timeout = 1
		)
	
	def close(self):
		self.port.close()

	def drain(self):
		if None == self.port:
			self.open()
			wasOpen = False
		else:
			self.close()
			self.open()
			wasOpen = True
		while True:
			c = self.port.read(1024)
			if 1024 != len(c):
				break
		self.close()
		if wasOpen:
			self.open()

	def readAll(self):
		msg = ''
		while True:
			c = self.port.read(1024)
			msg += c
			if len(c) < 1024:
				break
		return msg

if '__main__' == __name__:
	if 2 == len(sys.argv):
		board = ArmBoard(device = sys.argv[1])
	else:
		board = ArmBoard()
	board.open()
	board.drain()
	print(board.readAll())
	board.close()
