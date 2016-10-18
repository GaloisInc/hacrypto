#!/bin/bash

#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#
# Functions to generate XML data table
#


# Add XML table header
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the architecture
function add_xml_table_header()
{	
	local output_file=$1
	local scenario=$2
	local architecture=$3


	# Clear output
	echo -n "" > $output_file


	printf "<?xml version=\"1.0\"?>" >> $output_file
	printf "\n" >> $output_file
	printf "<?mso-application progid=\"Excel.Sheet\"?>" >> $output_file
	printf "\n" >> $output_file

	printf "<Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\"" >> $output_file
	printf "\n" >> $output_file
	printf " xmlns:o=\"urn:schemas-microsoft-com:office:office\"" >> $output_file
	printf "\n" >> $output_file
	printf " xmlns:x=\"urn:schemas-microsoft-com:office:excel\"" >> $output_file
	printf "\n" >> $output_file
	printf " xmlns:ss=\"urn:schemas-microsoft-com:office:spreadsheet\"" >> $output_file
	printf "\n" >> $output_file
	printf " xmlns:html=\"http://www.w3.org/TR/REC-html40\">" >> $output_file
	printf "\n" >> $output_file

	printf " <DocumentProperties xmlns=\"urn:schemas-microsoft-com:office:office\">" >> $output_file
	printf "\n" >> $output_file
	printf "  <Author>FELICS</Author>" >> $output_file
	printf "\n" >> $output_file
	printf "  <LastAuthor>FELICS</LastAuthor>" >> $output_file
	printf "\n" >> $output_file
	printf "  <Created>"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"</Created>" >> $output_file
	printf "\n" >> $output_file
	printf "  <LastSaved>"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"</LastSaved>" >> $output_file
	printf "\n" >> $output_file
	printf "  <Company>Unversity of Luxembourg</Company>" >> $output_file
	printf "\n" >> $output_file
	printf "  <Version>15.00</Version>" >> $output_file
	printf "\n" >> $output_file
	printf " </DocumentProperties>" >> $output_file
	printf "\n" >> $output_file

	printf " <OfficeDocumentSettings xmlns=\"urn:schemas-microsoft-com:office:office\">" >> $output_file
	printf "\n" >> $output_file
	printf "  <AllowPNG/>" >> $output_file
	printf "\n" >> $output_file
	printf " </OfficeDocumentSettings>" >> $output_file
	printf "\n" >> $output_file

	printf " <ExcelWorkbook xmlns=\"urn:schemas-microsoft-com:office:excel\">" >> $output_file
	printf "\n" >> $output_file
	printf "  <WindowHeight>12375</WindowHeight>" >> $output_file
	printf "\n" >> $output_file
	printf "  <WindowWidth>19965</WindowWidth>" >> $output_file
	printf "\n" >> $output_file
	printf "  <WindowTopX>0</WindowTopX>" >> $output_file
	printf "\n" >> $output_file
	printf "  <WindowTopY>0</WindowTopY>" >> $output_file
	printf "\n" >> $output_file
	printf "  <ProtectStructure>False</ProtectStructure>" >> $output_file
	printf "\n" >> $output_file
	printf "  <ProtectWindows>False</ProtectWindows>" >> $output_file
	printf "\n" >> $output_file
	printf " </ExcelWorkbook>" >> $output_file
	printf "\n" >> $output_file

	printf " <Styles>" >> $output_file
	printf "\n" >> $output_file
	printf "  <Style ss:ID=\"Default\" ss:Name=\"Normal\">" >> $output_file
	printf "\n" >> $output_file
	printf "   <Alignment ss:Vertical=\"Bottom\"/>" >> $output_file
	printf "\n" >> $output_file
	printf "   <Borders/>" >> $output_file
	printf "\n" >> $output_file
	printf "   <Font ss:FontName=\"Calibri\" x:Family=\"Swiss\" ss:Size=\"11\" ss:Color=\"#000000\"/>" >> $output_file
	printf "\n" >> $output_file
	printf "   <Interior/>" >> $output_file
	printf "\n" >> $output_file
	printf "   <NumberFormat/>" >> $output_file
	printf "\n" >> $output_file
	printf "   <Protection/>" >> $output_file
	printf "\n" >> $output_file
	printf "  </Style>" >> $output_file
	printf "\n" >> $output_file
	printf "  <Style ss:ID=\"s1\">" >> $output_file
	printf "\n" >> $output_file
	printf "   <Alignment ss:Horizontal=\"Center\" ss:Vertical=\"Center\"/>" >> $output_file
	printf "\n" >> $output_file
	printf "   <Font ss:FontName=\"Calibri\" x:Family=\"Swiss\" ss:Size=\"11\" ss:Color=\"#000000\"" >> $output_file
	printf "\n" >> $output_file
	printf "    ss:Bold=\"1\"/>" >> $output_file
	printf "\n" >> $output_file
	printf "  </Style>" >> $output_file
	printf "\n" >> $output_file
	printf "  <Style ss:ID=\"s2\">" >> $output_file
	printf "\n" >> $output_file
	printf "   <Alignment ss:Vertical=\"Center\"/>" >> $output_file
	printf "\n" >> $output_file
	printf "   <Font ss:FontName=\"Calibri\" x:Family=\"Swiss\" ss:Size=\"11\" ss:Color=\"#000000\"" >> $output_file
	printf "\n" >> $output_file
	printf "    ss:Bold=\"1\"/>" >> $output_file
	printf "\n" >> $output_file
	printf "  </Style>" >> $output_file
	printf "\n" >> $output_file
	printf " </Styles>" >> $output_file
	printf "\n" >> $output_file

	printf " <Worksheet ss:Name=\"Results\">" >> $output_file
	printf "\n" >> $output_file

	
	case $scenario in
		$SCRIPT_SCENARIO_0)
			printf "  <Names>" >> $output_file
			printf "\n" >> $output_file
			printf "   <NamedRange ss:Name=\"_FilterDatabase\" ss:RefersTo=\"=Results!R3C1:R3C18\"" >> $output_file
			printf "\n" >> $output_file
			printf "    ss:Hidden=\"1\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "  </Names>" >> $output_file
			printf "\n" >> $output_file

			printf "  <Table ss:ExpandedColumnCount=\"19\" x:FullColumns=\"1\"" >> $output_file
			printf "\n" >> $output_file
			printf "   x:FullRows=\"1\" ss:DefaultRowHeight=\"15\">" >> $output_file
			printf "\n" >> $output_file

			printf "   <Column ss:Width=\"125\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"90\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"83.25\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"53.25\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"60.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"60.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"72.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"95.25\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"75.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"60\"/>" >> $output_file
			printf "\n" >> $output_file

			printf "   <Row>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"3\" ss:MergeDown=\"1\" ss:StyleID=\"s1\"><Data" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Type=\"String\">Cipher Info</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"2\" ss:MergeDown=\"1\" ss:StyleID=\"s1\"><Data" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Type=\"String\">Implementation Info</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"2\" ss:MergeDown=\"1\" ss:StyleID=\"s1\"><Data" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Type=\"String\">Code Size</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"5\" ss:StyleID=\"s1\"><Data ss:Type=\"String\">RAM</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"1\" ss:MergeDown=\"1\" ss:StyleID=\"s1\"><Data" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Type=\"String\">Execution Time</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "   </Row>" >> $output_file
			printf "\n" >> $output_file

			printf "   <Row>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:Index=\"11\" ss:MergeAcross=\"1\" ss:StyleID=\"s1\"><Data ss:Type=\"String\">Stack</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"3\" ss:StyleID=\"s1\"><Data ss:Type=\"String\">Data</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "   </Row>" >> $output_file
			printf "\n" >> $output_file

			printf "   <Row>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Cipher</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">State Size (bits)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Key Size (bits)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">IV Size (bits)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Version</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Language</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Options</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">S (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">E (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">S + E (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">S (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">E (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">S (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">E (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Common (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Total (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">S (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">E (cycles)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "   </Row>" >> $output_file
			printf "\n" >> $output_file

			;;

		$SCRIPT_SCENARIO_1)
			printf "  <Names>" >> $output_file
			printf "\n" >> $output_file
			printf "   <NamedRange ss:Name=\"_FilterDatabase\" ss:RefersTo=\"=Results!R3C1:R3C18\"" >> $output_file
			printf "\n" >> $output_file
			printf "    ss:Hidden=\"1\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "  </Names>" >> $output_file
			printf "\n" >> $output_file

			printf "  <Table ss:ExpandedColumnCount=\"19\" x:FullColumns=\"1\"" >> $output_file
			printf "\n" >> $output_file
			printf "   x:FullRows=\"1\" ss:DefaultRowHeight=\"15\">" >> $output_file
			printf "\n" >> $output_file

			printf "   <Column ss:Width=\"125\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"90\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"83.25\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"53.25\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"60.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"60.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"72.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"95.25\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"75.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"57.75\"/>" >> $output_file
			printf "\n" >> $output_file
			printf "   <Column ss:Width=\"60\"/>" >> $output_file
			printf "\n" >> $output_file

			printf "   <Row>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"3\" ss:MergeDown=\"1\" ss:StyleID=\"s1\"><Data" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Type=\"String\">Cipher Info</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"2\" ss:MergeDown=\"1\" ss:StyleID=\"s1\"><Data" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Type=\"String\">Implementation Info</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"2\" ss:MergeDown=\"1\" ss:StyleID=\"s1\"><Data" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Type=\"String\">Code Size</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"5\" ss:StyleID=\"s1\"><Data ss:Type=\"String\">RAM</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"1\" ss:MergeDown=\"1\" ss:StyleID=\"s1\"><Data" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Type=\"String\">Execution Time</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "   </Row>" >> $output_file
			printf "\n" >> $output_file

			printf "   <Row>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:Index=\"11\" ss:MergeAcross=\"1\" ss:StyleID=\"s1\"><Data ss:Type=\"String\">Stack</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:MergeAcross=\"3\" ss:StyleID=\"s1\"><Data ss:Type=\"String\">Data</Data></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "   </Row>" >> $output_file
			printf "\n" >> $output_file

			printf "   <Row>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Cipher</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">State Size (bits)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Key Size (bits)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">IV Size (bits)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Version</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Language</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Options</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">S (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">E (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">S + E (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">S (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">E (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">S (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">E (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Common (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">Total (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">S (bytes)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">E (cycles)</Data><NamedCell" >> $output_file
			printf "\n" >> $output_file
			printf "      ss:Name=\"_FilterDatabase\"/></Cell>" >> $output_file
			printf "\n" >> $output_file
			printf "   </Row>" >> $output_file
			printf "\n" >> $output_file
			
			;;
	esac
}


# Add XML table row
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the cipher name
#	$4 - the cipher state size
#	$5 - the cipher key size
#	$6 - the cipher IV size
#	$7 - the cipher implementation version
#	$8 - the cipher implementation language
#	$9 - the cipher implementation compiler options
#	$10 ... - cipher metrics values
function add_xml_table_row()
{
	local output_file=$1
	local scenario=$2
	local cipher_name=$3
	local cipher_state_size=$4
	local cipher_key_size=$5
	local cipher_iv_size=$6
	local cipher_implementation_version=$7
	local cipher_implementation_language=$8
	local cipher_implementation_compiler_options=$9
	local cipher_metrics_values=( ${@:10} )


	printf "   <Row>" >> $output_file
	printf "\n" >> $output_file

	printf "    <Cell ss:StyleID=\"s2\"><Data ss:Type=\"String\">$cipher_name</Data></Cell>" >> $output_file
	printf "\n" >> $output_file
	printf "    <Cell><Data ss:Type=\"Number\">$cipher_state_size</Data></Cell>" >> $output_file
	printf "\n" >> $output_file
	printf "    <Cell><Data ss:Type=\"Number\">$cipher_key_size</Data></Cell>" >> $output_file
	printf "\n" >> $output_file
	printf "    <Cell><Data ss:Type=\"Number\">$cipher_iv_size</Data></Cell>" >> $output_file
	printf "\n" >> $output_file
	printf "    <Cell><Data ss:Type=\"Number\">$cipher_implementation_version</Data></Cell>" >> $output_file
	printf "\n" >> $output_file
	printf "    <Cell><Data ss:Type=\"String\">$cipher_implementation_language</Data></Cell>" >> $output_file
	printf "\n" >> $output_file
	printf "    <Cell><Data ss:Type=\"String\">$cipher_implementation_compiler_options</Data></Cell>" >> $output_file
	printf "\n" >> $output_file


	for value in ${cipher_metrics_values[@]}
	do
		printf "    <Cell><Data ss:Type=\"Number\">$value</Data></Cell>" >> $output_file
		printf "\n" >> $output_file
	done
	

	printf "   </Row>" >> $output_file
	printf "\n" >> $output_file
}


# Add XML table footer
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
function add_xml_table_footer()
{
	local output_file=$1
	local scenario=$2

	
	printf "  </Table>" >> $output_file
	printf "\n" >> $output_file

	printf "  <WorksheetOptions xmlns=\"urn:schemas-microsoft-com:office:excel\">" >> $output_file
	printf "\n" >> $output_file

	printf "   <PageSetup>" >> $output_file
	printf "\n" >> $output_file
	printf "    <Header x:Margin=\"0.3\"/>" >> $output_file
	printf "\n" >> $output_file
	printf "    <Footer x:Margin=\"0.3\"/>" >> $output_file
	printf "\n" >> $output_file
	printf "    <PageMargins x:Bottom=\"0.75\" x:Left=\"0.7\" x:Right=\"0.7\" x:Top=\"0.75\"/>" >> $output_file
	printf "\n" >> $output_file
	printf "   </PageSetup>" >> $output_file
	printf "\n" >> $output_file

	printf "   <Print>" >> $output_file
	printf "\n" >> $output_file
	printf "    <ValidPrinterInfo/>" >> $output_file
	printf "\n" >> $output_file
	printf "    <PaperSizeIndex>9</PaperSizeIndex>" >> $output_file
	printf "\n" >> $output_file
	printf "    <HorizontalResolution>600</HorizontalResolution>" >> $output_file
	printf "\n" >> $output_file
	printf "    <VerticalResolution>597</VerticalResolution>" >> $output_file
	printf "\n" >> $output_file
	printf "   </Print>" >> $output_file
	printf "\n" >> $output_file

	printf "   <Selected/>" >> $output_file
	printf "\n" >> $output_file

	printf "   <FreezePanes/>" >> $output_file
	printf "\n" >> $output_file
	printf "   <FrozenNoSplit/>" >> $output_file
	printf "\n" >> $output_file
	printf "   <SplitHorizontal>3</SplitHorizontal>" >> $output_file
	printf "\n" >> $output_file
	printf "   <TopRowBottomPane>3</TopRowBottomPane>" >> $output_file
	printf "\n" >> $output_file
	printf "   <SplitVertical>4</SplitVertical>" >> $output_file
	printf "\n" >> $output_file
	printf "   <LeftColumnRightPane>4</LeftColumnRightPane>" >> $output_file
	printf "\n" >> $output_file
	printf "   <ActivePane>0</ActivePane>" >> $output_file
	printf "\n" >> $output_file

	
	printf "   <Panes>" >> $output_file
	printf "\n" >> $output_file

	printf "    <Pane>" >> $output_file
	printf "\n" >> $output_file
	printf "     <Number>3</Number>" >> $output_file
	printf "\n" >> $output_file
	printf "    </Pane>" >> $output_file
	printf "\n" >> $output_file
	printf "    <Pane>" >> $output_file
	printf "\n" >> $output_file
	printf "     <Number>1</Number>" >> $output_file
	printf "\n" >> $output_file
	printf "    </Pane>" >> $output_file
	printf "\n" >> $output_file
	printf "    <Pane>" >> $output_file
	printf "\n" >> $output_file
	printf "     <Number>2</Number>" >> $output_file
	printf "\n" >> $output_file
	printf "    </Pane>" >> $output_file
	printf "\n" >> $output_file

	case $scenario in
		$SCRIPT_SCENARIO_0)
			printf "    <Pane>" >> $output_file
			printf "\n" >> $output_file
			printf "     <Number>0</Number>" >> $output_file
			printf "\n" >> $output_file
			printf "     <ActiveRow>0</ActiveRow>" >> $output_file
			printf "\n" >> $output_file
			printf "     <ActiveCol>0</ActiveCol>" >> $output_file
			printf "\n" >> $output_file
			printf "     <RangeSelection>R1C1:R2C4</RangeSelection>" >> $output_file
			printf "\n" >> $output_file
			printf "    </Pane>" >> $output_file
			printf "\n" >> $output_file
			printf "   </Panes>" >> $output_file
			printf "\n" >> $output_file

			printf "   <ProtectObjects>False</ProtectObjects>" >> $output_file
			printf "\n" >> $output_file

			printf "   <ProtectScenarios>False</ProtectScenarios>" >> $output_file
			printf "\n" >> $output_file

			printf "  </WorksheetOptions>" >> $output_file
			printf "\n" >> $output_file

			printf "  <AutoFilter x:Range=\"R3C1:R3C18\"" >> $output_file
			printf "\n" >> $output_file
			printf "   xmlns=\"urn:schemas-microsoft-com:office:excel\">" >> $output_file
			printf "\n" >> $output_file
			printf "  </AutoFilter>" >> $output_file
			printf "\n" >> $output_file

			;;

		$SCRIPT_SCENARIO_1)
			printf "    <Pane>" >> $output_file
			printf "\n" >> $output_file
			printf "     <Number>0</Number>" >> $output_file
			printf "\n" >> $output_file
			printf "     <ActiveRow>0</ActiveRow>" >> $output_file
			printf "\n" >> $output_file
			printf "     <ActiveCol>0</ActiveCol>" >> $output_file
			printf "\n" >> $output_file
			printf "     <RangeSelection>R1C1:R2C4</RangeSelection>" >> $output_file
			printf "\n" >> $output_file
			printf "    </Pane>" >> $output_file
			printf "\n" >> $output_file
			printf "   </Panes>" >> $output_file
			printf "\n" >> $output_file

			printf "   <ProtectObjects>False</ProtectObjects>" >> $output_file
			printf "\n" >> $output_file

			printf "   <ProtectScenarios>False</ProtectScenarios>" >> $output_file
			printf "\n" >> $output_file

			printf "  </WorksheetOptions>" >> $output_file
			printf "\n" >> $output_file

			printf "  <AutoFilter x:Range=\"R3C1:R3C18\"" >> $output_file
			printf "\n" >> $output_file
			printf "   xmlns=\"urn:schemas-microsoft-com:office:excel\">" >> $output_file
			printf "\n" >> $output_file
			printf "  </AutoFilter>" >> $output_file
			printf "\n" >> $output_file
			
			;;
	esac


	printf " </Worksheet>" >> $output_file
	printf "\n" >> $output_file
	
	printf "</Workbook>" >> $output_file
}
