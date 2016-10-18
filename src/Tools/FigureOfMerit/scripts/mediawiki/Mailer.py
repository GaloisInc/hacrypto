#! /usr/bin/python3

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

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import sys
import smtplib

MAILER_START_CONNECTING = 'Start connecting to email server ...'
MAILER_START_SENDING_EMAILS = 'Start sending emails ...'
MAILER_CLOSED_CONNECTION = 'Mailer closed connection to server ...'
MAILER_TRY_SEND_EMAIL_FORMAT = 'Try send email From: "{0}" To: "{1}" with CC: "{2}" and BCC: "{3}". Subject is "{4}".'
MAILER_SEND_EMAIL_EXCEPTION_FORMAT = 'Send email From: "{0}" To: "{1}" with CC: "{2}" and BCC: "{3}". ' \
                                     'Subject is "{4}". Error: "{5}".'
MAILER_SENT_EMAIL_FORMAT = 'Sent email From: "{0}" To: "{1}" with CC: "{2}" and BCC: "{3}". Subject is "{4}".'
MAILER_TRY_CONNECT_FORMAT = 'Try connect email server "{0}":"{1}" using username "{2}".'
MAILER_CONNECT_EXCEPTION_FORMAT = 'Connect to email server "{0}":"{1}" using username "{2}". Error: "{3}".'
MAILER_CONNECTED_FORMAT = 'Connected to email server "{0}":"{1}" using username "{2}".'

MIME_MULTIPART_ALTERNATIVE_SUBTYPE = 'alternative'
MIME_SUBCONTENT_PLAIN_TYPE = 'plain'
MIME_SUBCONTENT_HTML_TYPE = 'html'

EMAIL_SUBJECT = 'Subject'
EMAIL_FROM = 'From'
EMAIL_TO = 'To'
EMAIL_CC = 'CC'
EMAIL_BCC = 'BCC'

COMMA_SEPARATOR = ','


class Mailer:
	"""Sends emails"""

	smtpClient = None
	serverName = ''
	serverPort = ''
	userName = ''
	userPassword = ''


	def __init__(self, serverName, serverPort, userName, userPassword):
		self.serverName = serverName
		self.serverPort = serverPort
		self.userName = userName
		self.userPassword = userPassword

	def connectToEmailServer(self):
		logging.info(MAILER_START_CONNECTING)

		try:
			logging.debug(MAILER_TRY_CONNECT_FORMAT.format(self.serverName, self.serverPort, self.userName))

			self.smtpClient = smtplib.SMTP(self.serverName, self.serverPort)
			self.smtpClient.starttls()
			self.smtpClient.login(self.userName, self.userPassword)

			logging.debug(MAILER_CONNECTED_FORMAT.format(self.serverName, self.serverPort, self.userName))
		except Exception as e:
			logging.error(MAILER_CONNECT_EXCEPTION_FORMAT.format(self.serverName, self.serverPort, self.userName, str(e)))
			sys.exit(MAILER_CONNECT_EXCEPTION_FORMAT.format(self.serverName, self.serverPort, self.userName, str(e)))


	def disconnectFromEmailServer(self):
		self.smtpClient.quit()
		logging.debug(MAILER_CLOSED_CONNECTION)


	def sendEmail(self, sender, toList, ccList, bccList, subject, textMessage, htmlMessage):
		self.connectToEmailServer()

		mimeMultipart = MIMEMultipart(MIME_MULTIPART_ALTERNATIVE_SUBTYPE)

		mimeMultipart[EMAIL_SUBJECT] = subject
		mimeMultipart[EMAIL_FROM] = sender
		mimeMultipart[EMAIL_TO] = toList

		if ccList:
			mimeMultipart[EMAIL_CC] = ccList

		# The MIME parts: text/plain and text/html
		textPart = MIMEText(textMessage, MIME_SUBCONTENT_PLAIN_TYPE)
		htmlPart = MIMEText(htmlMessage, MIME_SUBCONTENT_HTML_TYPE)

		# Attach parts into message container. According to RFC 2046, the last part of a multipart message, in this case
		# the HTML message, is best and preferred.
		mimeMultipart.attach(textPart)
		if len(htmlMessage) > 0:
			mimeMultipart.attach(htmlPart)

		recipients = toList.split(COMMA_SEPARATOR) + ccList.split(COMMA_SEPARATOR) + bccList.split(COMMA_SEPARATOR)

		self.smtpClient.sendmail(sender, recipients, mimeMultipart.as_string())

		self.disconnectFromEmailServer()
