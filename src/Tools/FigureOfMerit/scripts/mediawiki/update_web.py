#! /usr/bin/python3
# -*- coding: utf-8 -*-

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
import os
import subprocess
import getpass
import shutil
import Mailer
import cryptolux_wiki as cryptolux
import logging
import time
import datetime

################################################################################
# Log functions
################################################################################
logging.basicConfig(filename = 'update_web.log', filemode = 'w', level = logging.INFO)
COLOR_PREFIX = {
	'NOTE': '',
	'OK': '\033[92m',
	'ERROR': '\033[91m',
	'WARNING': '\033[93m',
	'HEADER': '\033[95m',
	'QUOTE': '\033[94m',
}
COLOR_SUFFIX = '\033[0m'

def printColor(msg, level = 'NOTE'):
    print(COLOR_PREFIX[level] + msg + COLOR_SUFFIX)
    if level == 'ERROR':
        mailError(msg)
        logging.error(msg)
    elif level == 'WARNING':
        logging.warning(msg)
    else:
        logging.info(msg)

def mailError(msg):
    mailer.sendEmail(
        sender = user + '@' + SERVER_DOMAIN,
        toList = user + '@' + SERVER_DOMAIN,
        ccList = '',
        bccList = '',
        subject = '[update_web.py] PID = {0}'.format(os.getpid()),
        textMessage = 'Script path: {}\nERROR: {}'.format(os.getcwd(), msg),
        htmlMessage = ''
    )

################################################################################
# Definitions
################################################################################
ACRYPT_SRC = "./../../../acrypt"
FOM_SRC = "./../.."
DEFAULT_WIKI_USER = "yann.lecorre"

SERVER_NAME = 'smtp-3.uni.lu'
SERVER_PORT = 587
SERVER_DOMAIN = 'uni.lu'

# 1 field is the source, 2nd field is the destination. Source is rooted in acrypt while
# destination is rooted in fom.
ACRYPT_TO_FOM = (
	("block_ciphers/results/BlockCiphers/Info/FELICS_info.csv",          "FigureOfMerit/BlockCiphers/Input/Info/FELICS_info.csv"),
	("block_ciphers/results/BlockCiphers/ARM/FELICS_ARM_scenario1.csv",  "FigureOfMerit/BlockCiphers/Input/ARM/FELICS_ARM_scenario1.csv"),
	("block_ciphers/results/BlockCiphers/ARM/FELICS_ARM_scenario2.csv",  "FigureOfMerit/BlockCiphers/Input/ARM/FELICS_ARM_scenario2.csv"),
	("block_ciphers/results/BlockCiphers/AVR/FELICS_AVR_scenario1.csv",  "FigureOfMerit/BlockCiphers/Input/AVR/FELICS_AVR_scenario1.csv"),
	("block_ciphers/results/BlockCiphers/AVR/FELICS_AVR_scenario2.csv",  "FigureOfMerit/BlockCiphers/Input/AVR/FELICS_AVR_scenario2.csv"),
	("block_ciphers/results/BlockCiphers/MSP/FELICS_MSP_scenario1.csv",  "FigureOfMerit/BlockCiphers/Input/MSP/FELICS_MSP_scenario1.csv"),
	("block_ciphers/results/BlockCiphers/MSP/FELICS_MSP_scenario2.csv",  "FigureOfMerit/BlockCiphers/Input/MSP/FELICS_MSP_scenario2.csv"),
	("stream_ciphers/results/StreamCiphers/ARM/FELICS_ARM_scenario1.csv", "FigureOfMerit/StreamCiphers/Input/ARM/FELICS_ARM_scenario1.csv"),
	("stream_ciphers/results/StreamCiphers/AVR/FELICS_AVR_scenario1.csv", "FigureOfMerit/StreamCiphers/Input/AVR/FELICS_AVR_scenario1.csv"),
	("stream_ciphers/results/StreamCiphers/MSP/FELICS_MSP_scenario1.csv", "FigureOfMerit/StreamCiphers/Input/MSP/FELICS_MSP_scenario1.csv"),
)

# 1st field is the location of the file, 2nd field is the name of the corresponding wiki page
WIKI_SRC_PAGE = (
	(os.path.join(ACRYPT_SRC, "block_ciphers/results/BlockCiphers.mwk"), "FELICS_Block_Ciphers_Detailed_Results"),
	(os.path.join(ACRYPT_SRC, "stream_ciphers/results/StreamCiphers.mwk"), "FELICS_Stream_Ciphers_Detailed_Results"),
	(os.path.join(FOM_SRC, "FigureOfMerit/BlockCiphers/Output/BlockCiphers.mkw"), "FELICS_Block_Ciphers_Brief_Results"),
	(os.path.join(FOM_SRC, "FigureOfMerit/StreamCiphers/Output/StreamCiphers.mkw"), "FELICS_Stream_Ciphers_Brief_Results"),
	(os.path.join(FOM_SRC, "FigureOfMerit/BlockCiphers/Output/TriathlonResults.mkw"), "FELICS_Triathlon_Results"),
)

# 1st field is source in FOM tree, 2nd field is destination on cryptolux web server
WIKI_UPLOADS = (
	os.path.join(ACRYPT_SRC, "block_ciphers/results/FELICS_BlockCiphers.zip"),
	os.path.join(ACRYPT_SRC, "stream_ciphers/results/FELICS_StreamCiphers.zip"),
	os.path.join(ACRYPT_SRC, "FELICS.zip"),
	os.path.join(FOM_SRC, "FigureOfMerit.zip"),
)

################################################################################
# Main
################################################################################
#### 0. Login on cryptolux wiki
# Actually log in and then immediatly log out to check that the credentials
# are OK. We'll log in only when we will update the wiki after the long (!)
# metrics collection
printColor("-- 0. Login on cryptolux wiki: ", 'NOTE')
user = input("Cryptolux wiki user [default = '{0}']:".format(DEFAULT_WIKI_USER))
if len(user) == 0:
	user = DEFAULT_WIKI_USER
printColor("User: {0}".format(user))
wiki = cryptolux.CryptoluxWiki()
passwd = getpass.getpass()
wiki.login(user, passwd)
wiki.logout()

# Configure email
startTime = time.time()
mailer = Mailer.Mailer(SERVER_NAME, SERVER_PORT, user, passwd)

try:
    #### 1. Measure all ciphers using the .get_results.sh script
    scriptPath = os.path.join(ACRYPT_SRC, "common/scripts/get_results.sh");
    printColor("-- 1. Update ciphers metrics", 'HEADER')

    try:
        output = subprocess.check_output([scriptPath], stderr = subprocess.STDOUT)
    except subprocess.CalledProcessError:
        printColor("Error trying to execute {0}. Exiting...".format(scriptPath), 'ERROR')
        sys.exit(-1)

    for line in output.splitlines():
        printColor(line.decode('utf-8'), 'QUOTE')


    #### 2. Copy files from acrypt tree to fom tree
    printColor("-- 2. Copy files from ACRYPT to FOM", 'HEADER')
    for (src, dst) in ACRYPT_TO_FOM:
        srcFileName = os.path.join(ACRYPT_SRC, src)
        dstFileName = os.path.join(FOM_SRC, dst)
        if not os.path.exists(srcFileName):
            printColor("File {0} does not exist. Exiting...".format(srcFileName), "ERROR")
            sys.exit(-1)
        printColor("copying {0} -> {1}".format(srcFileName, dstFileName))
        shutil.copyfile(srcFileName, dstFileName)


    #### 3. Generate block ciphers FOM and Triathlon results
    printColor("-- 3. Calculate block ciphers FOM and Triathlon scoring", 'HEADER')

    try:
        output = subprocess.check_output(
            ['/usr/bin/python3', 'FigureOfMerit.py'],
            cwd = os.path.join(FOM_SRC, 'FigureOfMerit/BlockCiphers'),
            stderr = subprocess.STDOUT
        )
    except subprocess.CalledProcessError:
        printColor("Error executing block ciphers FigureOfMerit.py. Exiting...", 'ERROR')
        sys.exit(-1)

    for line in output.splitlines():
        printColor(line.decode('utf-8'), 'QUOTE')

    #### 4. Generate stream ciphers FOM
    printColor("-- 4. Calculate stream ciphers FOM", 'HEADER')

    try:
        output = subprocess.check_output(
            ['/usr/bin/python3', 'FigureOfMerit.py'],
            cwd = os.path.join(FOM_SRC, 'FigureOfMerit/StreamCiphers'),
            stderr = subprocess.STDOUT
        )
    except subprocess.CalledProcessError:
        printColor("Error executing stream ciphers FigureOfMerit.py. Exiting...", 'ERROR')
        sys.exit(-1)

    for line in output.splitlines():
        printColor(line.decode('utf-8'), 'QUOTE')

    #### 5. Generate archive for ACRYPT repository
    printColor("-- 5. Generate archive for ACRYPT repository", 'HEADER')
    scriptPath = os.path.join(ACRYPT_SRC, 'common/scripts/export_repository.sh')
    try:
        output = subprocess.check_output(
            [scriptPath],
            stderr = subprocess.STDOUT
        )
    except subprocess.CalledProcessError:
        printColor("Error trying to execute {0}. Exiting...".format(scriptPath), 'ERROR')
        sys.exit(-1)

    for line in output.splitlines():
        printColor(line.decode('utf-8'), 'QUOTE')

    #### 6. Generate archive for FOM repository
    printColor("-- 6. Generate archive for FOM repository", 'HEADER')
    scriptPath = os.path.join(FOM_SRC, 'scripts/export_repository.sh')
    try:
        output = subprocess.check_output(
            [scriptPath],
            stderr = subprocess.STDOUT
        )
    except subprocess.CalledProcessError:
        printColor("Error trying to execute {0}. Exiting...".format(scriptPath), 'ERROR')
        sys.exit(-1)

    for line in output.splitlines():
        printColor(line.decode('utf-8'), 'QUOTE')

    #### Login on cryptolux wiki
    wiki = cryptolux.CryptoluxWiki()
    wiki.login(user, passwd)

    #### 8. Upload files to cryptolux wiki
    printColor("-- 8. Upload files to cryptolux wiki", 'HEADER')
    for fileName in WIKI_UPLOADS:
        if not os.path.exists(fileName):
            printColor("File {0} does not exist. Exiting...".format(fileName), "ERROR")
            sys.exit(-1)
        printColor("Uploading {0} to cryptolux".format(fileName))
        try:
            wiki.uploadFile(fileName)
        except cryptolux.ApiException:
            printColor('Uploading of file {0} failed. Exiting...'.format(fileName), 'ERROR')
            sys.exit(-1)

    #### 9. Upload pages to cryptolux wiki
    printColor("-- 9. Upload pages to cryptolux wiki", 'HEADER')

    for (srcFileName, wikiPageName) in WIKI_SRC_PAGE:
        if not os.path.exists(srcFileName):
            printColor("File {0} does not exist. Exiting...".format(srcFileName), "ERROR")
            sys.exit(-1)
        with open(srcFileName, 'r') as fh:
            pageContent = fh.read()
        fh.close()
        printColor("Uploading {0} to cryptolux wiki page '{1}'".format(srcFileName, wikiPageName))
        try:
            wiki.editPage(wikiPageName, pageContent)
        except cryptolux.ApiException:
            printColor('Uploading of page {0} failed. Exiting...'.format(wikiPageName), 'ERROR')
            sys.exit(-1)

    #### Cleanup
    wiki.logout()

except Exception as e:
    printColor('Unexpected error: {}'.format(e), 'ERROR')
    sys.exit(-1)

### Send completion email
pid = os.getpid()
stopTime = time.time()
elapsedTime = stopTime - startTime
textMessage = \
    'Job done!\n' \
    'Start: @{0}\n' \
    'End:   @{1}\n' \
    'Elapsed time: {2} seconds\n' \
    'Elapsed time: {3}\n'.format(time.asctime(time.localtime(startTime)), time.asctime(time.localtime(stopTime)), round(elapsedTime, 2), str(datetime.timedelta(seconds=elapsedTime)))
textMessage += '\n' \
               'Script path: {}' \
               '\n'.format(os.getcwd())
textMessage += \
    '\n' \
    'Uploaded files:\n' \
    '1. FELICS.zip https://www.cryptolux.org/images/c/cf/FELICS.zip\n' \
    '2. FigureOfMerit.zip https://www.cryptolux.org/images/f/fd/FigureOfMerit.zip\n' \
    '3. FELICS_BlockCiphers.zip https://www.cryptolux.org/images/b/b9/FELICS_BlockCiphers.zip\n' \
    '4. FELICS_StreamCiphers.zip https://www.cryptolux.org/images/5/51/FELICS_StreamCiphers.zip\n' \
    '\n' \
    'Updated pages:\n' \
    '1. FELICS_Triathlon_Results https://www.cryptolux.org/index.php/FELICS_Triathlon_Results\n' \
    '2. FELICS_Block_Ciphers_Brief_Results https://www.cryptolux.org/index.php/FELICS_Block_Ciphers_Brief_Results\n' \
    '3. FELICS_Stream_Ciphers_Brief_Results https://www.cryptolux.org/index.php/FELICS_Stream_Ciphers_Brief_Results\n' \
    '4. FELICS_Block_Ciphers_Detailed_Results https://www.cryptolux.org/index.php/FELICS_Block_Ciphers_Detailed_Results\n' \
    '5. FELICS_Stream_Ciphers_Detailed_Results https://www.cryptolux.org/index.php/FELICS_Stream_Ciphers_Detailed_Results\n'
htmlMessage = \
    '<b>Job done!</b><br />' \
    'Start: @{0}<br />' \
    'End: &nbsp; @{1}<br />' \
    'Elapsed time: {2} seconds<br />' \
    'Elapsed time: {3}<br />'.format(time.asctime(time.localtime(startTime)), time.asctime(time.localtime(stopTime)), round(elapsedTime, 2), str(datetime.timedelta(seconds=elapsedTime)))
htmlMessage += '<br />' \
               'Script path: {}' \
               '<br />'.format(os.getcwd())
htmlMessage += \
    '<br />' \
    '<b>Uploaded files:</b><br />' \
    '1. <a href="https://www.cryptolux.org/images/c/cf/FELICS.zip">FELICS.zip</a> <br />' \
    '2. <a href="https://www.cryptolux.org/images/f/fd/FigureOfMerit.zip">FigureOfMerit.zip</a> <br />' \
    '3. <a href="https://www.cryptolux.org/images/b/b9/FELICS_BlockCiphers.zip">FELICS_BlockCiphers.zip</a> <br />' \
    '4. <a href="https://www.cryptolux.org/images/5/51/FELICS_StreamCiphers.zip">FELICS_StreamCiphers.zip</a> <br />' \
    '<br />' \
    '<b>Updated pages:</b><br />' \
    '1. <a href="https://www.cryptolux.org/index.php/FELICS_Triathlon_Results">FELICS_Triathlon_Results</a><br />' \
    '2. <a href="https://www.cryptolux.org/index.php/FELICS_Block_Ciphers_Brief_Results">FELICS_Block_Ciphers_Brief_Results</a><br />' \
    '3. <a href="https://www.cryptolux.org/index.php/FELICS_Stream_Ciphers_Brief_Results">FELICS_Stream_Ciphers_Brief_Results</a><br />' \
    '4. <a href="https://www.cryptolux.org/index.php/FELICS_Block_Ciphers_Detailed_Results">FELICS_Block_Ciphers_Detailed_Results</a><br />' \
    '5. <a href="https://www.cryptolux.org/index.php/FELICS_Stream_Ciphers_Detailed_Results">FELICS_Stream_Ciphers_Detailed_Results</a><br />'

print(textMessage)
mailer.sendEmail(
    sender = user + '@' + SERVER_DOMAIN,
    toList = user + '@' + SERVER_DOMAIN,
    ccList = '',
    bccList = '',
    subject = '[update_web.py] PID = {0}'.format(pid),
    textMessage = textMessage,
    htmlMessage = htmlMessage
)
