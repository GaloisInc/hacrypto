#! /usr/bin/python3

#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FigureOfMerit (FOM)
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu>
#
# This file is part of FigureOfMerit.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

import sys
import subprocess
import getpass
import hashlib
import requests
from xml.dom import minidom


class ApiException(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)


class CryptoluxWiki:

	def __init__(self):
		self.apiEndPoint = "https://www.cryptolux.org/api.php"
		self.session = requests.Session()

	def login(self, user, passwd):
		loginQuery = {
			'action'		: 'login',
			'format'		: 'xml',
			'lgdomain'		: 'uni.lu'
		}
		loginQuery['lgname'] = user
		response = self.session.post(self.apiEndPoint, params = loginQuery)
		xml = minidom.parseString(response.text)
		loginNode = xml.getElementsByTagName('login')[0]
		token = loginNode.getAttribute('token')
		loginQuery['lgtoken'] = token
		loginQuery['lgpassword'] = passwd
		response = self.session.post(self.apiEndPoint, params = loginQuery)
		xml = minidom.parseString(response.text)
		loginNode = xml.getElementsByTagName('login')
		result = loginNode[0].getAttribute('result')
		if result != "Success":
			raise ApiException("login failed")

		editTokenQuery = {
			'action'	: 'query',
			'format'	: 'xml',
			'prop'		: 'info',
			'intoken'	: 'edit'
		}
		editTokenQuery['titles'] = 'myEditToken'
		response = self.session.post(self.apiEndPoint, editTokenQuery)
		xml = minidom.parseString(response.text)
		pageNode = xml.getElementsByTagName('page')[0]
		self.editToken = pageNode.getAttribute('edittoken')

	def logout(self):
		logoutQuery = {
			'action'	: 'logout',
			'format'	: 'xml'
		}
		response = self.session.post(self.apiEndPoint, logoutQuery)

	def editPage(self, pageTitle, pageContent):
		editPageQuery = {
			'action'	: 'edit',
			'format'	: 'xml'
		}
		editPageQuery['title'] = pageTitle
		editPageQuery['text'] = pageContent.encode('utf-8')
		md5 = hashlib.md5()
		md5.update(pageContent.encode('utf-8'))
		editPageQuery['md5'] = md5.hexdigest()
		editPageQuery['token'] = self.editToken.encode('utf-8')
		response = self.session.post(self.apiEndPoint, editPageQuery)
		xml = minidom.parseString(response.text)
		editNode = xml.getElementsByTagName('edit')[0]
		resultAttribute = editNode.getAttribute('result')
		if resultAttribute != 'Success':
			raise ApiException('editPage failed')

	def uploadFile(self, fileName):
		uploadQuery = {
			'action' : 'upload',
			'ignorewarnings' : 'true',
			'filename' : fileName,
			'token': self.editToken,
		}
		uploadFiles = {
			'file': open(fileName, 'rb'),
		}
		response = self.session.post(self.apiEndPoint, uploadQuery, files = uploadFiles)

# Quick tests
if __name__ == '__main__':

	user = "yann.lecorre"
	passwd = getpass.getpass()
	cryptoluxWiki = CryptoluxWiki()
	try:
		cryptoluxWiki.login(user, passwd)
		cryptoluxWiki.editPage("Ylc_test", "final test??!")
		cryptoluxWiki.uploadFile("test_upload.txt")
		cryptoluxWiki.logout()
	except ApiException:
		print("ERROR: caught ApiException. Exiting ...")
